#!/usr/bin/env python3

# NOTE The memory reclaimer should not run during collection (leads to faulty page-hit detection)!
# Regarding Linux:
# NOTE For speeding up processing drop the page cache beforehand (echo 1 | sudo tee /proc/sys/vm/drop_caches)!
import argparse
import mmap
import time
import tqdm
import matplotlib.pyplot as plt
import numpy as np
import os
import json
import signal
import random
import re
import importlib
import sys
import platform
import itertools
import psutil
if platform.system() == "Linux":
    import vmtools.linux
    from vmtools.linux import PageUsageTracker
elif platform.system() == "Windows":
    import vmtools.nt
    from vmtools.nt import PageUsageTracker
from fctools import fc_hit_classify

# fitness threshold for training, found mappings must be above (higher is better, max = 1)
FITNESS_THRESHOLD_TRAIN = 0.8
# if the difference between two page-hit ratios is below they are considered to be equal
# (currently only used for checking if a page-hit ratio is similar to zero)
PH_RATIOS_SIMILAR_THRESHOLD = 0.15

# How should speculative readahead/readaround be handled?
# On Windows only none is used always as there actually the working set state is observed
# which does not track speculatively read pages.
# "none":         assume none exists
# "suppressed":   assume the attacker suppresssed readahead/readaround (by keeping surrounding pages active)
#                 to aid with the classification of events linked with pages whose readaround windows overlap
#                 the corner pages of these windows are added to the results if their page-hit ratio is nearly zero
#                 these corner pages can be used in the general case (not at the beginning and limited at
#                 the end of the file) to still classify the events correctly (requires that affected events
#                 do not occur in parallel, overlapping event groups also could cause problems!)
#                 the rational behind this is that in the general case the readaround window of any two events
#                 does not overlap completely and therefore observing the cache state of the readaround corner
#                 pages allows to determine to which faulted page the detected readaround window belongs to
#                 if the implementation detects that this approach is ambiguous or wrong for pages, a warning is issued
#                 the user can then manually resolve these issues by blacklisting some of the involved pages
# "noise":        trigger readahead/readaround as noise: substract the sum of page-hit ratios of pages that might
#                 trigger caching of the current candidate page from its page-hit ratio
HANDLE_RA = "suppressed" if platform.system() == "Linux" else "none"
# Linux: max. readahead/readaround pages (/sys/class/block/nvme0n1/queue/read_ahead_kb)
MAX_RA_WINDOW_PAGES = 32

# filter pages before sampling
EXPERIMENTAL_FILTER_PFNS_BEFORE_SAMPLING = True

# the following should be overwritten by the event triggering module which is
# dynamically loaded
# see ../experiments/keystrokes/fc_profiler_conf_{linux,windows}.py as an example
FILE_BLACKLIST_REGEX = []
FILE_WHITELIST_REGEX = []
FILE_PAGE_BLACKLIST = {}


def loadModule(module_path):
    folder = os.path.dirname(module_path)
    module = os.path.basename(module_path)[:-3]
    sys.path.append(folder)
    return importlib.import_module(module)


def createPageCacheHitHeatmap(event_cache_hits, page_range, mapping_page_offset, title,
                              pages_per_row=16, show=True, save=False):
    # offset
    offset = page_range[0]
    length = page_range[1]
    # reorganize data
    data = [event_cache_hits[i: i + pages_per_row]
            for i in range(offset, offset + length, pages_per_row)]
    if len(data) > 1 and len(data[-1]) < pages_per_row:
        data[-1] = np.pad(data[-1], (0, pages_per_row - len(data[-1])))
    # generate x labels
    x_labels = ["{:x}".format(o) for o in range(
        0, len(data[0]) if len(data) == 1 else pages_per_row)]
    y_labels = ["0x{:x}".format(o) for o in range(
        mapping_page_offset + offset, mapping_page_offset + offset + len(data) * pages_per_row, pages_per_row)]

    # new plot
    fig, ax = plt.subplots()  # figsize=())
    # use imshow
    im = ax.imshow(np.array(data), cmap=plt.cm.Greys, vmin=0, vmax=1)

    # create colorbar
    cbar = ax.figure.colorbar(im, ax=ax, ticks=range(0, 1))
    cbar.ax.set_ylabel("Hits", rotation=-90, va="bottom")

    # major ticks
    ax.set_xticks(range(len(x_labels)))
    ax.set_yticks(range(len(y_labels)))
    # label major ticks
    ax.set_xticklabels(x_labels)
    ax.set_yticklabels(y_labels)

    # minor ticks
    ax.set_xticks(np.arange(-0.5, len(x_labels), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(y_labels), 1), minor=True)
    # grid
    ax.grid(which="minor", color="black", linestyle="-", linewidth=1)

    # title is file path
    ax.set_title(title)
    fig.tight_layout()

    if save:
        plt.savefig(title + ".pdf", dpi=300)
    if show:
        plt.show()
    plt.close()

# linux related


def targetGetPcMappingsLinux(pids, includes=None):
    maps = []
    # add targets from the target processes memory mappings
    for pid in pids:
        # freeze process (for parsing maps)
        process_control = vmtools.linux.ProcessControl(pid)
        process_control.freeze()
        # get read-only, file-backed mappings
        #   -> e.g. shared libraries, read-only data files
        #   -> everything that likely stays shared through the page cache
        maps_reader = vmtools.linux.MapsReader(pid)
        maps += maps_reader.getMapsByPermissions(
            read=True, only_file=True)
        process_control.resume()
    # add additional target files if wanted
    if includes is not None:
        for include in includes:
            for dirpath, subdirs, files in os.walk(include):
                if len(files) == 0:
                    continue
                for file in files:
                    path = os.path.join(dirpath, file)
                    if os.path.islink(path):
                        continue
                    maps.append({
                        "path": path
                    })

    # NOTE many applications consists of multiple (forked) subprocesses and map
    # files multiple times so it would be necessary to check the page table entries
    # of all processes to determine which pages are used
    # to circumvent these problems we only use the name of the mapped files as suggestion
    # which files to track
    # we then map these files ourselves and check which pages are resident in RAM
    # and therefore should be tracked (emptying the page cache before running the
    # profiling script therefore might increase its performance)
    processed_files = set()
    processed_maps = []
    resident_target_pages = 0
    # initialise page mapping reader
    page_map_reader = vmtools.linux.PageMapReader(os.getpid())
    for map in maps:
        if (map["path"] in processed_files):
            continue
        # try to map whole file
        try:
            # map whole file
            mm = vmtools.linux.mapFileSharedRo(map["path"])
            # ensure we do not trigger any readahead
            vmtools.linux.madvise(mm.address, mm.length, mmap.MADV_RANDOM)
        except (FileNotFoundError, ValueError):
            # remember that we processed this file (no duplicates)
            processed_files.add(map["path"])
            mm = None
            continue
        # get cache state + track resident pages
        pc_state = vmtools.linux.mincore(mm.address, mm.length)
        # no resident page at all -> skip
        if all(state == 0 for state in pc_state):
            # remember that we processed this file
            processed_files.add(map["path"])
            mm = None
            continue
        # track resident pages
        pfns = [-1] * len(pc_state)
        for p, state in enumerate(pc_state):
            if state == 1:
                # access so that page table entry is created
                # mlock was considered to ensure the pfn number stays stable, but
                # apparently that migh lead to problems with the idle page tracking feature
                # see https://www.kernel.org/doc/html/latest/admin-guide/mm/idle_page_tracking.html
                vmtools.linux.mread(mm.address + p * mmap.PAGESIZE)
                #vmtools.linux.mlock(address + p * mmap.PAGESIZE, mmap.PAGESIZE)

                # get PFN
                mapping = page_map_reader.getMapping(
                    int(mm.address / mmap.PAGESIZE) + p)
                if mapping[0].present:
                    pfns[p] = mapping[0].pfn_swap
                else:
                    raise RuntimeError(
                        "Page not present, this should not happen! Low memory?")

                resident_target_pages += 1

        # remember that we processed this file
        processed_files.add(map["path"])
        # add file map region
        processed_maps.append({
            "path": map["path"],
            "size": mm.length,
            "size_pages": len(pfns),
            "page_ids": pfns,
            # not used for Linux
            "image": None,
            "mm": mm
        })

    print("Number of possible target pages to check: {}".format(
        resident_target_pages))
    return processed_maps


def targetGetPcMappingsWindows(pids, includes):
    target_maps = []
    processed_maps = []
    processed_files = set()
    sum_active_target_pages = 0
    page_usage_tracker = vmtools.nt.PageUsageTracker()

    # add files from target process mappings
    # first pid should be main target process
    for pid in pids:
        # fetch all maps
        map_reader = vmtools.nt.MapsReader(pid)
        maps = map_reader.getMaps()
        for m in maps:
            # only add relevant maps
            # private mappings can not be observed
            if m.range_type == vmtools.nt.MEM_PRIVATE:
                continue
            # only file-backed mappings can be observed
            if m.range_type == vmtools.nt.MEM_MAPPED and (len(m.backing_file) == 0 or m.range_file_offset == -1):
                continue
            # only new files
            if m.backing_file in processed_files:
                continue

            # save map
            target_maps.append({
                "path": m.backing_file,
                "image": True if m.range_type == vmtools.nt.MEM_IMAGE else False,
                "unsafe_image": False,
                "load_address_target": m.vaddr_range[0]
            })
            # remember that we processed this file
            processed_files.add(m.backing_file)

    # add additional target files if wanted
    if includes is not None:
        for include in includes:
            for dirpath, subdirs, files in os.walk(include):
                if len(files) == 0:
                    continue
                for file in files:
                    path = os.path.join(dirpath, file)
                    if os.path.islink(path):
                        continue
                    # only new files
                    if path in processed_files:
                        continue
                    ext = os.path.splitext(file)[1]
                    # image
                    if ext == ".dll" or ext == ".exe":
                        target_maps.append({
                            "path": path,
                            "image": True,
                            "unsafe_image": True
                        })
                    # other
                    else:
                        target_maps.append({
                            "path": path,
                            "image": False
                        })
                    # remember that we processed this file
                    processed_files.add(path)

    # map possible targets
    for m in target_maps:
        # if mapping fails just skip
        try:
            if m["image"]:
                # if we map DLLs resulting from iterating the given include directories,
                # then do not trigger the execution of DllMain() as this has lead to crashes in multiple situations
                # for example when loading AppVTerminator.dll ;) (https://gist.github.com/EvanMcBroom/ac2b9084bf3c84939efcb9c894fadd07)
                # TODO in future this might be improved by spwaning a new process and trying if the DLL can be mapped
                mo = vmtools.nt.mapImage(
                    m["path"], vmtools.nt.DONT_RESOLVE_DLL_REFERENCES if m["unsafe_image"] else 0)
                # additional check for images
                if "load_address_target" in m and mo.address != m["load_address_target"]:
                    print("WARNING: Image addresses do not match!")
            else:
                mo = vmtools.nt.mapFileSharedRo(m["path"])
        except Exception as e:
            print("WARNING: Mapping of target {} failed!".format(m["path"]))
            print(e)
            mo = None
            continue

        # add all active pages to observed pages
        active_vas = []
        active_target_pages = 0
        vas = [int(va / mmap.PAGESIZE)
               for va in range(mo.address, mo.address + mo.length, mmap.PAGESIZE)]
        state = page_usage_tracker.getState(vas)
        for i in range(len(vas)):
            if state[i]:
                active_vas.append(vas[i])
                active_target_pages += 1
            else:
                active_vas.append(-1)
        sum_active_target_pages += active_target_pages

        # if no active vas, then skip file
        if active_target_pages == 0:
            mo = None
            continue

        # add file map region
        processed_maps.append({
            "path": m["path"],
            "size": mo.length,
            "size_pages": len(vas),
            "page_ids": active_vas,
            "image": m["image"],
            "mm": mo
        })

    print("Number of possible target pages to check: {}".format(
        sum_active_target_pages))
    return processed_maps


def renewPageIDsLinux(results):
    file_to_mapping = {}
    page_map_reader = vmtools.linux.PageMapReader(os.getpid())
    for event_mapping in results["event_file_offset_mappings"]:
        # do not map multiple times, use cached mappings
        if event_mapping["file"] in file_to_mapping:
            mm = file_to_mapping[event_mapping["file"]]
        else:
            # map whole file
            mm = vmtools.linux.mapFileSharedRo(event_mapping["file"])
            file_to_mapping[event_mapping["file"]] = mm
        event_mapping["link_to_mapping"]["mm"] = mm
        # ensure we do not trigger any readahead
        vmtools.linux.madvise(mm.address, mm.length, mmap.MADV_RANDOM)
        vmtools.linux.mread(int(mm.address + event_mapping["offset"]))
        # get PFN
        mapping = page_map_reader.getMapping(
            int((mm.address + event_mapping["offset"]) / mmap.PAGESIZE))
        if not mapping[0].present:
            raise RuntimeError(
                "Page not present, this should not happen! Low memory?")
        event_mapping["current_page_id"] = mapping[0].pfn_swap


def renewPageIDsWindows(results):
    file_to_mapping = {}
    for event_mapping in results["event_file_offset_mappings"]:
        # do not map multiple times, use cached mappings
        if event_mapping["file"] in file_to_mapping:
            mo = file_to_mapping[event_mapping["file"]]
        elif "image" in event_mapping and event_mapping["image"]:
            # map whole image
            mo = vmtools.nt.mapImage(event_mapping["file"])
            file_to_mapping[event_mapping["file"]] = mo
        else:
            # map whole file
            mo = vmtools.nt.mapFileSharedRo(event_mapping["file"])
            file_to_mapping[event_mapping["file"]] = mo
        event_mapping["link_to_mapping"]["mm"] = mo
        event_mapping["current_page_id"] = int(
            (mo.address + event_mapping["offset"]) / mmap.PAGESIZE)


if platform.system() == "Linux":
    targetGetPcMappings = targetGetPcMappingsLinux
    renewPageIDs = renewPageIDsLinux
elif platform.system() == "Windows":
    targetGetPcMappings = targetGetPcMappingsWindows
    renewPageIDs = renewPageIDsWindows


class ClassificationTrainer:
    def __init__(self, fitness_threshold_train, f_collect_event_generator=None):
        self.fitness_threshold_train_ = fitness_threshold_train
        self.events_ = None
        self.samples_ = None
        self.pc_mappings_ = None
        self.f_collect_event_generator_ = f_collect_event_generator if f_collect_event_generator is not None else self.sampleGenerator

    def loadRawData(self, events, samples, pc_mappings):
        self.events_ = events
        self.samples_ = samples
        self.pc_mappings_ = pc_mappings

    # generator (because of yield, first call does not execute function)
    def eventSeqGenerator(self, events, len, samples):
        # shuffle event order for each sample, avoids dependence on the sequence of events
        for _ in range(samples):
            for event in random.sample(events, len):
                yield event

    def collect(self, events, samples, pids, includes):
        self.events_ = events
        self.samples_ = samples

        # warm-up page cache (cache all pages needed for the events except idle event)
        print("Executing events for warm-up...")
        for event in self.events_[:-1]:
            event[1]()
        # give a bit of time
        time.sleep(2)
        # get library mappings and the PFN of their present pages which should be tracked
        pc_mappings = targetGetPcMappings(pids, includes)

        # prepare mapping objects for storing results
        self.collectPrepare_(pc_mappings)
        # prepare page usage tracker
        page_usage_tracker = PageUsageTracker()

        # EXPERIMENTAL optimization, throw away not-accessed pages to reduce overhead of sampling
        if EXPERIMENTAL_FILTER_PFNS_BEFORE_SAMPLING:
            filtered = 0
            # reset
            if platform.system() == "Linux":
                for mapping in pc_mappings:
                    page_usage_tracker.reset(mapping["page_ids"])
            elif platform.system() == "Windows":
                page_usage_tracker.reset()

            # execute all events 3 times (except idle event)
            for _ in range(3):
                for event in self.events_[:-1]:
                    event[1]()

            # sample
            for mapping in pc_mappings:
                state = page_usage_tracker.getState(mapping["page_ids"])
                for i in range(len(mapping["page_ids"])):
                    if state[i] == False and mapping["page_ids"][i] != -1:
                        mapping["page_ids"][i] = -1
                        filtered += 1

            print("Filtered {} pages due to inactivity during events!".format(filtered))

        # init event sequence generator
        collect_event_generator = self.f_collect_event_generator_(
            list(enumerate(self.events_)), len(self.events_), self.samples_)
        # sample all events
        print("Sampling events:")
        for event_i, event in tqdm.tqdm(collect_event_generator, total=len(events)*samples):
            # reset
            if platform.system() == "Linux":
                for mapping in pc_mappings:
                    page_usage_tracker.reset(mapping["page_ids"])
            elif platform.system() == "Windows":
                page_usage_tracker.reset()

            # run event function
            event[1]()

            # sample
            for mapping in pc_mappings:
                state = page_usage_tracker.getState(mapping["page_ids"])
                self.collectMappingAdd_(mapping, state, event_i)

        self.pc_mappings_ = pc_mappings

    def collectPrepare_(self, pc_mappings):
        raise NotImplementedError("Needs to be overwritten!")

    def collectMappingAdd_(self, mapping, pfn_state, event):
        raise NotImplementedError("Needs to be overwritten!")

    def train(self):
        raise NotImplementedError("Needs to be overwritten!")

    def printResults(self):
        raise NotImplementedError("Needs to be overwritten!")


# NOTE: Preconditions:
#   - Requires last event to be the "idle" event!
#   - Events do not happen in parallel!
# NOTE: Limitations:
#   - Linux: If pages which might trigger the readahead of the current candidate page and
#            the current candidate page have overlapping event groups, then the classification
#            results can be wrong. Further, if not enough suitable readahead suppress pages
#            are available results can also be wrong / ambiguous. However, this is shown
#            at the end.
class SinglePageHitClassificationTrainer(ClassificationTrainer):
    def __init__(self, fitness_threshold_train, ph_ratios_similar_threshold, handle_ra=None, ra_window=None,
                 file_blacklist_re=None, file_whitelist_re=None, file_page_blacklist=None, f_collect_event_generator=None,
                 debug_heatmaps=False):
        super().__init__(fitness_threshold_train, f_collect_event_generator)
        self.event_file_offset_mappings_ = None
        self.ph_ratios_similar_threshold_ = ph_ratios_similar_threshold
        if platform.system() == "Linux":
            self.handle_ra_ = handle_ra
            self.fault_ra_window_ = ra_window
            self.calcRaPagesLinux()
        elif platform.system() == "Windows":
            self.handle_ra_ = None
            self.fault_ra_window_ = None
        self.file_blacklist_re_ = file_blacklist_re
        self.file_whitelist_re_ = file_whitelist_re
        self.file_page_blacklist_ = file_page_blacklist
        self.debug_heatmaps_ = debug_heatmaps

        # only use white-listed files if both filters are set
        if len(self.file_blacklist_re_) != 0  and len(self.file_whitelist_re_) != 0:
            self.file_blacklist_re_ = []

    def calcRaPagesLinux(self):
        # in case of major pagefaults (page cache misses)
        self.mj_pf_back_ra_window_ = int(self.fault_ra_window_ / 2)
        self.mj_pf_front_ra_window_ = int(self.fault_ra_window_ / 2) - 1

        # a minor pagefault could trigger the sequential readahead algorithm
        # in the w.c. then a page 63 pages before the triggering one might
        # be faulted in
        # only applies if no suppression is used (otherwise no minor pagefaults should be possible)
        self.back_trigger_ra_window_ = 2 * self.fault_ra_window_ - 1
        # from major pagefaults readaround as sequential readahead algorithm only reads pages in front
        self.front_trigger_ra_window_ = self.mj_pf_back_ra_window_

    def collectPrepare_(self, pc_mappings):
        # prepare mapping objects for storing results
        for mapping in pc_mappings:
            # create event-access matrix
            mapping["events_page_accesses"] = np.zeros(
                (len(self.events_), len(mapping["page_ids"])))

    def collectMappingAdd_(self, mapping, pfn_state, event):
        mapping["events_page_accesses"][event] += pfn_state

    def filter(self):
        for i in range(len(self.pc_mappings_) - 1, -1, -1):
            if any([re.match(r, self.pc_mappings_[i]["path"]) for r in self.file_blacklist_re_]):
                del self.pc_mappings_[i]
            if not any([re.match(r, self.pc_mappings_[i]["path"]) for r in self.file_whitelist_re_]):
                del self.pc_mappings_[i]

    def computePageHitRatios(self):
        for mapping in self.pc_mappings_:
            mapping["events_ph_ratios_raw"] = mapping["events_page_accesses"] / self.samples_

    def getEventGroupLabel(self, event_group):
        # human readable event labels
        return ", ".join([self.events_[x][0] for x in event_group])

    def presortPageHitMatricesExcludeIdleEvent(self):
        for mapping in self.pc_mappings_:
            # - sort descending, exclude idle event!
            mapping["non_idle_events_ph_ratios_argsort"] = np.argsort(
                -mapping["events_ph_ratios_raw"][:-1], axis=0)

    def tryLinkEventWithPageHitUnderGivenGroupSize(self, event, detectable_events, group_size):
        best_candidate = None

        for mapping in self.pc_mappings_:
            # calculate fitness matrix
            # base are the collected page-hit ratios of the event
            # events other than the target event are treated as noise
            # (w.c. estimation: as if each noise page-hit would cause an ambiguous or wrong classification)
            event_fitness = mapping["events_ph_ratios_raw"][event]
            # merge with other events if specified + calculate noise
            if group_size > 1:
                # merge events per page according to current group size
                # we use a pre-done sorting of the page-hit matrices to speed up the process
                # remove searched-for-event (event can't be merged with itsself)
                events_to_merge_sorted = np.reshape(mapping["non_idle_events_ph_ratios_argsort"].T[mapping["non_idle_events_ph_ratios_argsort"].T != event],
                                                    (mapping["non_idle_events_ph_ratios_argsort"].shape[0] - 1, mapping["non_idle_events_ph_ratios_argsort"].shape[1]), order="F")
                # get min ph ratio of the next (n = group size) events with the highest ph ratio
                events_to_merge_min_ph_ratios = np.min(mapping["events_ph_ratios_raw"][events_to_merge_sorted[: group_size - 1],
                                                                                       range(events_to_merge_sorted.shape[1])], axis=0)
                # merged ph ratio is the minimun (w.c. estimation)
                event_fitness = np.minimum(
                    event_fitness, events_to_merge_min_ph_ratios)
                # noise is the ph-ratio sum of the not-merged events and the idle event
                noise = np.sum(mapping["events_ph_ratios_raw"][events_to_merge_sorted[group_size - 1:],
                                                               range(events_to_merge_sorted.shape[1])], axis=0)
                noise += mapping["events_ph_ratios_raw"][-1]
            else:
                # noise is the ph-ratio sum of the not-merged events and the idle event
                noise = np.sum(mapping["events_ph_ratios_raw"],
                               axis=0) - mapping["events_ph_ratios_raw"][event]
            event_fitness = event_fitness - noise

            # (optionally, only linux) readahead-trigger window is treated as noise
            if self.handle_ra_ == "noise":
                event_fitness_ra = event_fitness.copy()
                # each page in the readahead-trigger window could cause the target page to be read independend of the event
                rh_ch_sum = np.sum(mapping["events_ph_ratios_raw"], axis=0)
                for p in range(event_fitness.shape[0]):
                    # readaround behaves different if the full back readaround can not be made
                    # (always MAX_RA_WINDOW_PAGES pages are loaded)
                    if p < self.back_trigger_ra_window_:
                        event_fitness_ra[p] = event_fitness[p] - (
                            np.sum(rh_ch_sum[0: p]) +
                            np.sum(rh_ch_sum[p + 1: p + 1 + self.front_trigger_ra_window_]))
                    else:
                        event_fitness_ra[p] = event_fitness[p] - (
                            np.sum(rh_ch_sum[p - self.back_trigger_ra_window_: p]) +
                            np.sum(rh_ch_sum[p + 1: p + 1 + self.front_trigger_ra_window_]))
                event_fitness = event_fitness_ra

            # get best-performing candidate page which is not blacklisted
            while True:
                candidate_page = np.argmax(event_fitness)
                if (mapping["path"] in self.file_page_blacklist_ and
                        candidate_page in self.file_page_blacklist_[mapping["path"]]):
                    # event_fitness is only a temporarily used copy it is safe to zero here
                    event_fitness[candidate_page] = 0
                else:
                    break

            candidate_page_fitness = event_fitness[candidate_page]
            # we already might have classified some events, so these can be filtered out of the new group
            event_merge_order = [] if group_size == 1 else events_to_merge_sorted[:group_size -
                                                                                  1, candidate_page].tolist()
            candidate_group = set([event] + event_merge_order)
            candidate_group_filtered = candidate_group - detectable_events
            candidate_group_filtered_size = len(candidate_group_filtered)
            # save candidate if it matches our minimum requirements and/or is better than previous ones
            # we prefer a smaller group size over larger ones if our minimum requirements are fulfilled
            # if the group size are equal, we prefer the candidate with the higher fitness score
            if ((best_candidate is None and candidate_page_fitness >= FITNESS_THRESHOLD_TRAIN) or
                (best_candidate is not None and
                 ((candidate_group_filtered_size < len(best_candidate["event_group_filtered"]) and
                   candidate_page_fitness >= FITNESS_THRESHOLD_TRAIN) or
                  (candidate_group_filtered_size == len(best_candidate["event_group_filtered"]) and
                   candidate_page_fitness > best_candidate["fitness"])))):
                best_candidate = {
                    "fitness": candidate_page_fitness,
                    "ph_ratio": mapping["events_ph_ratios_raw"][event][candidate_page],
                    "event_group": candidate_group,
                    "event_group_filtered": candidate_group_filtered,
                    "offset": candidate_page * mmap.PAGESIZE,
                    "file": mapping["path"],
                    "image": mapping["image"],
                    "current_page_id": mapping["page_ids"][candidate_page],
                    "link_to_mapping": mapping
                }

        # if we found a candidate, perform final processing steps
        if best_candidate is not None:
            # get labels
            best_candidate["event_group_labels"] = self.getEventGroupLabel(
                best_candidate["event_group"])
            # not needed anymore
            del best_candidate["event_group_filtered"]

        return best_candidate

    def linkEventsWithPageHits(self):
        found_mappings = []
        # last event is always "idle" event
        #   -> no need to classify
        events_to_process = set(range(len(self.events_) - 1))
        detectable_events = set()

        # try to find the best single page hits that describe our events
        # start out with minimal event group size
        #   -> if no canidate is found increase it and retry
        #      ("idle" event should not be part of any group, therefore no + 1)
        for group_size in range(1, len(self.events_)):
            next_events_to_process = set()
            while len(events_to_process) > 0:
                target_event = events_to_process.pop()
                best_candidate = self.tryLinkEventWithPageHitUnderGivenGroupSize(target_event,
                                                                                 detectable_events, group_size)
                # either a candidate is found for this event and group size
                # or we have to try again with a larger group size
                if best_candidate is None:
                    # add again -> no candidate was found
                    next_events_to_process.add(target_event)
                else:
                    # yay we have found a suitable mapping
                    detectable_events = detectable_events.union(
                        best_candidate["event_group"])
                    events_to_process -= best_candidate["event_group"]
                    found_mappings.append(best_candidate)
            if len(next_events_to_process) == 0:
                break
            events_to_process = next_events_to_process

        # also return events_to_process, which contains possible events for
        # which no mapping was found
        return found_mappings, list(events_to_process)

    def toFileOffsetEventMappings(self, event_file_offset_mappings):
        # convert results from an array to a file-offset-to-event structure
        # needed for further processing and finally classification
        file_to_events = {}
        for event_mapping in event_file_offset_mappings:
            if not (event_mapping["file"] in file_to_events):
                file_to_events[event_mapping["file"]] = {}
            file_to_events[event_mapping["file"]][int(
                event_mapping["offset"] / mmap.PAGESIZE)] = event_mapping
        return file_to_events

    def simulateEventPageHits(self, event_id, event_file_offset_mappings_access_order, file_observed_pages, ignore_readahead=False):
        event_mappings_to_add = []
        simulated_trace = {}
        # NOTE there might be multiple mappings that contain an event!
        for event_mapping in event_file_offset_mappings_access_order:
            if event_id in event_mapping["event_group"]:
                event_mappings_to_add.append(event_mapping)

        # add all pages that the event triggering fetches to the simulated trace
        for event_mapping in event_mappings_to_add:
            # add target page
            was_already_present = False
            target_page = int(event_mapping["offset"] / mmap.PAGESIZE)
            if event_mapping["file"] not in simulated_trace:
                simulated_trace[event_mapping["file"]] = set()
            if target_page not in simulated_trace[event_mapping["file"]]:
                simulated_trace[event_mapping["file"]].add(target_page)
            else:
                was_already_present = True

            # if a target page was already read-around by another target page it triggers no read-around anymore
            # this behaviour leads to problem with read-around suppression (violates preconditions)
            if ignore_readahead or was_already_present or platform.system() == "Windows":
                continue

            # add any other observed page that lies in the read-around window of the target page
            for other_page in range(event_mapping["ra_corner_pages"][0],
                                    event_mapping["ra_corner_pages"][1] + 1):
                # we do not care about the page itsself
                if other_page == target_page:
                    continue
                # nope we do not track this page
                if other_page not in file_observed_pages[event_mapping["file"]]:
                    continue
                # ok we do track this page, add it
                simulated_trace[event_mapping["file"]].add(other_page)

        return simulated_trace

    def simulateIdealEventClassification(self, training_results):
        classification_results = {}
        training_results = training_results.copy()
        # for ideal conditions no readahead exists
        training_results["handle_ra"] = None
        classifier = fc_hit_classify.Classifier(
            training_results=training_results)
        # exclude idle event
        for event_id in range(len(self.events_) - 1):
            # for ideal conditions no readahead exists
            simulated_trace = self.simulateEventPageHits(
                event_id, training_results["event_file_offset_mappings"], training_results["file_offset_event_mappings"], True)
            result = classifier.classifySample(simulated_trace)
            classification_results[event_id] = {
                "event_group": result,
                "event_group_labels": self.getEventGroupLabel(result)
            }
        return classification_results

    # linux related
    def raSuppressionGetReadaheadWindow(self, file, page):
        # get linked file mapping
        file_mapping = list(self.file_offset_event_mappings_[
                            file].values())[0]["link_to_mapping"]
        file_pages = len(file_mapping["page_ids"])

        # get readahead window corner pages
        if page < self.mj_pf_back_ra_window_:
            back_ra_corner_page = 0 if page != 0 else -1
            front_ra_corner_page = min(self.mj_pf_front_ra_window_ + self.mj_pf_back_ra_window_,
                                       file_pages - 1)
        else:
            back_ra_corner_page = page - self.mj_pf_back_ra_window_
            front_ra_corner_page = min(
                page + self.mj_pf_front_ra_window_, file_pages - 1)

        return (back_ra_corner_page, front_ra_corner_page)

    def raSuppressionGetPagesWhichTriggerReadahead(self, file, page):
        back = []
        front = []

        # get linked file mapping
        file_mapping = list(self.file_offset_event_mappings_[
                            file].values())[0]["link_to_mapping"]
        file_pages = len(file_mapping["page_ids"])

        # outmost corner pages which could possible trigger readahead or page itself
        back_trigger_ra_corner = 0 if page < self.fault_ra_window_ else page - \
            self.mj_pf_front_ra_window_
        front_trigger_ra_corner = min(
            page + self.mj_pf_back_ra_window_, file_pages - 1)

        # check which pages fall into these categories
        # back
        for p in range(back_trigger_ra_corner, page):
            if p in self.file_offset_event_mappings_[file].keys():
                back.append(p)
        # front
        for p in range(page + 1, front_trigger_ra_corner + 1):
            if p in self.file_offset_event_mappings_[file].keys():
                front.append(p)

        return (back, front)

    def raSuppressionFindSuitableRaSuppressPageForward(self, assist_ra_ph_ratios, starti, ende):
        for p in range(starti, ende):
            if assist_ra_ph_ratios[p] <= self.ph_ratios_similar_threshold_:
                return (p, assist_ra_ph_ratios[p])
        return None

    def raSuppressionFindSuitableRaSuppressPageBackward(self, assist_ra_ph_ratios, starti, ende):
        for p in range(starti, ende, -1):
            if assist_ra_ph_ratios[p] <= self.ph_ratios_similar_threshold_:
                return (p, assist_ra_ph_ratios[p])
        return None

    def raSuppressionLinux(self, training_results):
        # first pass: find useable ra suppression pages
        for file in self.file_offset_event_mappings_:
            # get linked file mapping
            file_mapping = list(self.file_offset_event_mappings_[
                                file].values())[0]["link_to_mapping"]
            file_pages = len(file_mapping["page_ids"])

            # ra suppress pages should not be used by any other event
            # otherwise, they might trigger unexpected read-around
            # we sum-up all page-hit ratios and cap them with 1
            assist_ra_ph_ratios = np.sum(
                file_mapping["events_ph_ratios_raw"], axis=0)
            assist_ra_ph_ratios[assist_ra_ph_ratios > 1] = 1

            # go through all tracked pages and see for which we need ra helper pages
            for page in self.file_offset_event_mappings_[file].keys():
                event_mapping = self.file_offset_event_mappings_[file][page]
                ra_suppress_back = None
                ra_suppress_front = None

                # save the pages readaround window for later processing
                event_mapping["ra_corner_pages"] = self.raSuppressionGetReadaheadWindow(
                    file, page)

                # get helper pages to suppress ra
                back_trigger_ra, front_trigger_ra = self.raSuppressionGetPagesWhichTriggerReadahead(
                    file, page)
                # back helper page only needed if readahead from front
                if len(front_trigger_ra) != 0:
                    ra_suppress_back = self.raSuppressionFindSuitableRaSuppressPageForward(assist_ra_ph_ratios, max(
                        page - self.mj_pf_back_ra_window_, 0), max(front_trigger_ra[0] - self.mj_pf_back_ra_window_, 0))
                # front helper page only needed if readahead from back
                if len(back_trigger_ra) != 0:
                    ra_suppress_front = self.raSuppressionFindSuitableRaSuppressPageBackward(assist_ra_ph_ratios, min(
                        page + self.mj_pf_front_ra_window_, file_pages - 1), min(back_trigger_ra[-1] + self.mj_pf_front_ra_window_, file_pages - 1))

                # both suppress pages are useable
                if ra_suppress_back is not None and ra_suppress_front is not None:
                    event_mapping["ra_suppress_pages_ph_ratios"] = (
                        ra_suppress_back, ra_suppress_front)
                    event_mapping["ra_suppress_mode"] = 2
                # only one suppress page is useable
                elif ra_suppress_back is not None:
                    event_mapping["ra_suppress_pages_ph_ratios"] = (
                        ra_suppress_back, None)
                    event_mapping["ra_suppress_mode"] = 0
                elif ra_suppress_front is not None:
                    event_mapping["ra_suppress_pages_ph_ratios"] = (
                        None, ra_suppress_front)
                    event_mapping["ra_suppress_mode"] = 1

        # second pass: check if some of the found mappings lead to ambiguous or wrong results
        # determine the complete set of pages we observe per file
        file_observed_pages = {}
        for file in self.file_offset_event_mappings_:
            for poffset in self.file_offset_event_mappings_[file]:
                event_mapping = self.file_offset_event_mappings_[file][poffset]
                if file not in file_observed_pages:
                    file_observed_pages[file] = set()
                file_observed_pages[file].add(poffset)
                if ("ra_suppress_mode" in event_mapping and
                        (event_mapping["ra_suppress_mode"] == 0 or event_mapping["ra_suppress_mode"] == 2)):
                    file_observed_pages[file].add(
                        event_mapping["ra_suppress_pages_ph_ratios"][0][0])
                if ("ra_suppress_mode" in event_mapping and
                        (event_mapping["ra_suppress_mode"] == 1 or event_mapping["ra_suppress_mode"] == 2)):
                    file_observed_pages[file].add(
                        event_mapping["ra_suppress_pages_ph_ratios"][1][0])

        # simulate event page-hit traces and apply the classifier to check results
        classifier = fc_hit_classify.Classifier(
            training_results=training_results)
        is_ambiguous_wrong = False
        # exclude idle event
        for event_id in range(len(self.events_) - 1):
            # simulate page hit trace (we have to consider all possible access patterns)
            # performance optimization, only consider affected mappings
            affected_mappings = []
            for mapping in training_results["event_file_offset_mappings"]:
                if event_id in mapping["event_group"]:
                    affected_mappings.append(mapping)
            for affected_mappings_access_permutation in itertools.permutations(affected_mappings):
                simulated_trace = self.simulateEventPageHits(
                    event_id, affected_mappings_access_permutation, file_observed_pages)
                # classify
                result = classifier.classifySample(simulated_trace)
                # check if event detection is correct
                if result != self.classification_results_[event_id]["event_group"]:
                    if "ambiguous_wrong_classification_events" not in self.classification_results_[event_id]:
                        self.classification_results_[
                            event_id]["ambiguous_wrong_classification_events"] = []
                        self.classification_results_[
                            event_id]["ambiguous_wrong_classification_events_labels"] = []
                    # only add if no equal result was already added
                    if all([result != x for x in self.classification_results_[event_id]["ambiguous_wrong_classification_events"]]):
                        self.classification_results_[
                            event_id]["ambiguous_wrong_classification_events"].append(result)
                        self.classification_results_[event_id]["ambiguous_wrong_classification_events_labels"].append(
                            self.getEventGroupLabel(list(result)))
                    is_ambiguous_wrong = True

        return not is_ambiguous_wrong

    def train(self):
        results = {
            "samples": self.samples_,
            "event_strings": [e[0] for e in self.events_],
            "raw_data": self.pc_mappings_,
            "handle_ra": HANDLE_RA
        }

        # 1. Filter unwanted files
        self.filter()
        # 2. Compute raw page-hit ratios
        self.computePageHitRatios()
        # 3. Presort page-hit matrices, exclude idle event (not needed)
        self.presortPageHitMatricesExcludeIdleEvent()
        # 4. Search set of event to file-offset-hit mappings to describe events
        #       -> fails if not all events are classifiable using single page hits
        self.event_file_offset_mappings_, events_no_mapping = self.linkEventsWithPageHits()
        if len(self.event_file_offset_mappings_) == 0:
            print("ERROR - no classification is possible!")
            results["event_file_offset_mappings"] = []
            results["file_offset_event_mappings"] = []
            return results
        if len(events_no_mapping) != 0:
            print("WARNING - not for every event a suitable page was found:")
            print(self.getEventGroupLabel(events_no_mapping))

        # convert to file-offset-to-event mapping
        self.file_offset_event_mappings_ = self.toFileOffsetEventMappings(
            self.event_file_offset_mappings_)
        # preliminary results without classification simulation and readahead suppression
        results["event_file_offset_mappings"] = self.event_file_offset_mappings_
        results["file_offset_event_mappings"] = self.file_offset_event_mappings_

        # 5. Simulate event classification
        self.classification_results_ = self.simulateIdealEventClassification(
            results)
        results["classification_results"] = self.classification_results_
        # (optional, only linux) 6. Perform and validate ra suppression
        if self.handle_ra_ == "suppressed":
            if(self.raSuppressionLinux(results) == False):
                print(
                    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                print(
                    "WARNING - not every event can be classified uniquely or correctly using readaround suppression!")
                print(
                    "Check the results and resolve conflicts manually by blacklisting some of the involved pages!")
                print(
                    "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n")

        return results

    def printResults(self):
        # No results at all
        if self.event_file_offset_mappings_ is None or len(self.event_file_offset_mappings_) == 0:
            print("No results available!")
            return

        print("--------------------------------------------------------------------------------")
        print("Mappings between file offsets and events")
        print("--------------------------------------------------------------------------------")
        # file-offset-to-event mappings
        for mapping in self.event_file_offset_mappings_:
            print("Event Group: {}".format(
                mapping["event_group_labels"]))
            print("Fitness: {}".format(mapping["fitness"]))
            print("File Path: {} Offset: 0x{:x} Current Page ID: 0x{:x}".format(
                mapping["file"], mapping["offset"], mapping["current_page_id"]))
            if "ra_suppress_pages_ph_ratios" in mapping:
                ra_suppress_str = ""
                if mapping["ra_suppress_pages_ph_ratios"][0] is not None:
                    ra_suppress_str += "0x{:x}->{} ".format(
                        mapping["ra_suppress_pages_ph_ratios"][0][0], mapping["ra_suppress_pages_ph_ratios"][0][1])
                if mapping["ra_suppress_pages_ph_ratios"][1] is not None:
                    ra_suppress_str += "0x{:x}->{} ".format(
                        mapping["ra_suppress_pages_ph_ratios"][1][0], mapping["ra_suppress_pages_ph_ratios"][1][1])
                print("RA suppress page-hit ratios: " + ra_suppress_str)
            print("")
        print("")

        print("--------------------------------------------------------------------------------")
        print("Simulated classification results")
        print("--------------------------------------------------------------------------------")
        detectable_event_groups = set()
        # classification results
        for event_id in self.classification_results_:
            event_result = self.classification_results_[event_id]
            print("Simulated event: {} -> Ideal Classification: {}".format(
                self.events_[event_id][0], event_result["event_group_labels"]))
            if "ambiguous_wrong_classification_events" in event_result:
                print(
                    "WARNING - Can not be classified uniquely or correctly using readaround suppression!")
                print("Possible classification outcomes: {}".format(" | ".join(
                    event_result["ambiguous_wrong_classification_events_labels"])))
            print("")
            detectable_event_groups.add(tuple(event_result["event_group"]))

        # calculate possible entropy reduction (assuming events are distributed uniformly)
        # except idle
        original_entropy = np.log2(len(self.events_) - 1)
        # attack entropy
        attack_entropy = 0
        for group in detectable_event_groups:
            attack_entropy -= len(group) / len(self.events_) * np.log2(len(group) / len(self.events_))
        print("Original entropy: {} reduced by {} to {} bit (ideally; assumes uniform event distribution).".format(
            original_entropy, attack_entropy, original_entropy - attack_entropy))

        # (optional, only for debugging) Print raw cache-ratio heatmaps for all events in vicinity of the
        # selected page
        # allow visual inspection to ensure algorithm works right
        if self.debug_heatmaps_:
            for result in self.event_file_offset_mappings_:
                print("Event Group: {}".format(result["event_group_labels"]))
                print("File Path: {} Offset: 0x{:x}".format(
                    result["file"], result["offset"]))
                candidate_page = int(result["offset"] / mmap.PAGESIZE)
                show_page_range_start = candidate_page - 128
                show_page_range_start = 0 if show_page_range_start < 0 else show_page_range_start
                show_page_range_len = int(
                    result["link_to_mapping"]["size"] / mmap.PAGESIZE) - show_page_range_start
                show_page_range_len = 256 if show_page_range_len > 256 else show_page_range_len
                for event in result["event_group"]:
                    createPageCacheHitHeatmap(result["link_to_mapping"]["events_ph_ratios_raw"][event],
                                              (show_page_range_start,
                                               show_page_range_len), 0,
                                              self.events_[event][0] + "\n" + result["file"])
                input("Press key for next event group...\n")


parser = argparse.ArgumentParser(
    description="Profiles which page offsets of shared files are accessed in case of an event.")
parser.add_argument("event_conf", type=str, metavar=("EVENT_CONF_PATH"),
                    help="path to the python file which contains the event triggering code")
group_ex = parser.add_mutually_exclusive_group(required="yes")
group_ex.add_argument("--collect", type=int,
                      metavar="SAMPLES", help="collect x samples")
group_ex.add_argument("--load", type=str, metavar=("PATH"),
                      help="load raw results from a json file and process them")
parser.add_argument("--target_pids", type=int, nargs="+",
                    metavar=("PID"), help="pids of the target processes")
parser.add_argument("--target_names", type=str, nargs="+",
                    metavar=("NAME"), help="names of the target processes")
parser.add_argument("--target_paths", type=str, nargs="+", metavar=("PATH"),
                    help="additional paths with target files to consider")
parser.add_argument("--tracer", action="store_true",
                    help="starts an interactive tracer afterwards (only Linux)")
parser.add_argument("--save", type=str, help="saves results into a json file")
args = parser.parse_args()

# additional command line syntax checking
if args.collect and not (args.target_pids or args.target_names or args.target_paths):
    print(
        "For --collect one of the arguments --target_{pids,names,paths} is needed!")
    parser.print_usage()
    exit(-1)

signal.signal(signal.SIGINT, signal.default_int_handler)

events_conf = loadModule(args.event_conf)

classifier = SinglePageHitClassificationTrainer(FITNESS_THRESHOLD_TRAIN, PH_RATIOS_SIMILAR_THRESHOLD,
                                                HANDLE_RA, MAX_RA_WINDOW_PAGES, events_conf.FILE_BLACKLIST_REGEX, events_conf.FILE_WHITELIST_REGEX, 
                                                events_conf.FILE_PAGE_BLACKLIST, events_conf.CUSTOM_COLLECT_EVENT_GENERATOR)

events = None
pid = None
samples = None
if args.load:
    results_json = None
    with open(args.load, "r") as file:
        results_json = json.loads(file.read())
    samples = results_json["samples"]
    events = [(e, None) for e in results_json["event_strings"]]
    pc_mappings = results_json["raw_data"]
    for mapping in pc_mappings:
        mapping["events_page_accesses"] = np.array(
            mapping["events_page_accesses"])

    # load saved raw data
    classifier.loadRawData(events, samples, pc_mappings)
    # process data
    # requires last event to be the "idle" event!
    results = classifier.train()
    # renew page IDs
    renewPageIDs(results)
    # print results
    classifier.printResults()
elif args.collect:
    samples = args.collect
    pids = args.target_pids if args.target_pids else []
    pnames = args.target_names if args.target_names else []
    includes = args.target_paths

    # get pids from process names
    for proc in psutil.process_iter():
        if proc.name() in pnames:
            pids.append(proc.pid)

    print("Target PIDs: {}".format(pids))
    print("Target paths: {}".format(includes))

    # prepare events
    events = events_conf.prepareEvents()

    # give user time to change focus, ...
    print("Starting in 5s...")
    time.sleep(5)

    # collect page access data from process
    classifier.collect(events, samples, pids, includes)
    # process data
    # requires last event to be the "idle" event!
    results = classifier.train()
    # print results
    classifier.printResults()

# optional: save data
# transform numpy to python structures
mapped_files = []
if args.save:
    for mapping in results["raw_data"]:
        mapping["events_page_accesses"] = [x.tolist()
                                           for x in mapping["events_page_accesses"]]
        # remove not needed data
        del mapping["events_ph_ratios_raw"]
        del mapping["non_idle_events_ph_ratios_argsort"]
        if "mm" in mapping:
            # keep reference to mapped files so that they keep being mapped
            mapped_files.append(mapping["mm"])
            del mapping["mm"]
    # in the "file_offset_event_mappings" same objects are stored
    for mapping in results["event_file_offset_mappings"]:
        mapping["offset"] = int(mapping["offset"])
        mapping["event_group"] = list(mapping["event_group"])
        # remove not needed data
        del mapping["link_to_mapping"]
        del mapping["current_page_id"]
    for event_result in results["classification_results"].values():
        event_result["event_group"] = list(event_result["event_group"])
        if "ambiguous_wrong_classification_events" in event_result:
            event_result["ambiguous_wrong_classification_events"] = [
                list(x) for x in event_result["ambiguous_wrong_classification_events"]]
    with open(args.save, "w") as file:
        file.write(json.dumps(results, indent=4))

# optional: interactive page-hit tracker
if args.tracer:
    # page usage tracker
    page_usage_tracker = PageUsageTracker()
    while True:
        pfn = int(input("Page ID to track (hex)> "), 16)
        page_usage_tracker.reset([pfn])
        #counter = 0
        try:
            while True:
                current_time = time.time_ns()
                state = page_usage_tracker.getState([pfn])
                if state[0] == True:
                    # NOTE: printing might trigger events in certain cases
                    #counter += 1
                    print("[{}s {}ns] Access detected!".format(
                        int(current_time / 1000000000), current_time % 1000000000))
                    page_usage_tracker.reset([pfn])
        except KeyboardInterrupt:
            # print(str(counter))
            pass
