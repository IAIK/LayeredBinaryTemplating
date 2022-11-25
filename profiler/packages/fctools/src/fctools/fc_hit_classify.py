#!/usr/bin/env python3

import numpy as np
import sys
import json

class Classifier:
    def __init__(self, training_result_file_path = None, training_results = None):
        if training_result_file_path is not None:
            training_results = self.loadTrainingResults(training_result_file_path)
        elif training_results is None:
            raise RuntimeError("You must specify some training results source!")

        # unpack results
        self.file_offset_event_mappings_ = training_results["file_offset_event_mappings"]
        self.handle_ra_ = training_results["handle_ra"]
        self.event_count_ = len(training_results["event_strings"])

        # get a set of all tracked pages
        self.tracked_file_offsets_ = set()
        for file in self.file_offset_event_mappings_:
            for page in self.file_offset_event_mappings_[file]:
                self.tracked_file_offsets_.add((file, page))

    def loadTrainingResults(self, training_result_file_path):
        with open(training_result_file_path, "r") as file:
            results_json = json.loads(file.read())
        self.file_offset_event_mappings_ = results_json["file_offset_event_mappings"]
        # convert keys to int
        for file in self.file_offset_event_mappings_:
            self.file_offset_event_mappings_[file] = {int(k): v for k,v in self.file_offset_event_mappings_[file].items()}
            for page in self.file_offset_event_mappings_[file]:
                self.file_offset_event_mappings_[file][page]["event_group"] = set(self.file_offset_event_mappings_[file][page]["event_group"])

        return results_json
    
    def createAttackConfig(self, attack_conf_path):
        with open(attack_conf_path, "w") as attack_conf_file:
            for file in self.file_offset_event_mappings_.keys():
                # check if should be mapped as data or image file
                event_mapping = next(iter(self.file_offset_event_mappings_[file].values()))
                if "image" in event_mapping and event_mapping["image"]:
                    image = 1
                else:
                    image = 0
                attack_conf_file.write("{} {}\n".format(image, file))
                for poffset in sorted(self.file_offset_event_mappings_[file].keys()):
                    event_mapping = self.file_offset_event_mappings_[file][poffset]
                    attack_conf_file.write("{:x} {}\n".format(poffset, 0))
                    if "ra_suppress_mode" in event_mapping:
                        if (event_mapping["ra_suppress_mode" ] == 0 and not
                            event_mapping["ra_suppress_pages_ph_ratios"][0][0] in self.file_offset_event_mappings_[file]):
                            attack_conf_file.write("{:x} {}\n".format(event_mapping["ra_suppress_pages_ph_ratios"][0][0], 1))
                        elif (event_mapping["ra_suppress_mode" ] == 1 and not
                            event_mapping["ra_suppress_pages_ph_ratios"][1][0] in self.file_offset_event_mappings_[file]):
                            attack_conf_file.write("{:x} {}\n".format(event_mapping["ra_suppress_pages_ph_ratios"][1][0], 1))
                        elif (event_mapping["ra_suppress_mode" ] == 2):
                            if event_mapping["ra_suppress_pages_ph_ratios"][0][0] not in self.file_offset_event_mappings_[file]:
                                attack_conf_file.write("{:x} {}\n".format(event_mapping["ra_suppress_pages_ph_ratios"][0][0], 1))
                            if event_mapping["ra_suppress_pages_ph_ratios"][1][0] not in self.file_offset_event_mappings_[file]:
                                attack_conf_file.write("{:x} {}\n".format(event_mapping["ra_suppress_pages_ph_ratios"][1][0], 1))
                attack_conf_file.write("\n")

    # NOTE we do not check if ra suppression is applicable
    # this should already have been visible after the training phase!
    def raSuppressionSpeculativePage(self, file, page, sample):
        event_mapping = self.file_offset_event_mappings_[file][page]

	    # if we do not need or should not check the corner pages, we skip it
        if "ra_suppress_mode" not in event_mapping:
            return False

        # check if readaround corner pages are present if they are available
        if (event_mapping["ra_suppress_mode"] == 0 and not
            event_mapping["ra_suppress_pages_ph_ratios"][0][0] in sample[file]):
            # not present in sample, skip this page
            return True
        elif (event_mapping["ra_suppress_mode"] == 1 and not 
            event_mapping["ra_suppress_pages_ph_ratios"][1][0] in sample[file]):
            # not present in sample, skip this page
            return True
        elif (event_mapping["ra_suppress_mode"] == 2 and not
            (event_mapping["ra_suppress_pages_ph_ratios"][0][0] in sample[file] and 
            event_mapping["ra_suppress_pages_ph_ratios"][1][0] in sample[file])):
            # not present in sample, skip this page
            return True

        # possible ambiguous page (less than two readaround corner pages)
        # check if we find another observed target page which likely speculatively fetched this one
        #   -> if so skip it
        #   -> if not keep it
        if event_mapping["ra_suppress_mode"] < 2:
            # go through pages which might readaround this page (in a sorted manner)
            # skip current page, if we find a better candidate
            for other_page in range(event_mapping["ra_corner_pages"][0] + 1, 
                event_mapping["ra_corner_pages"][1] + 2):
                # we do not care about the page itsself
                if other_page == page:
                    continue
                # ok, found a different target that could have readaround our current observed target page
                if (other_page in self.file_offset_event_mappings_[file] and other_page in sample[file]):
                    # a page which triggers the readaround of the current observed page is present, 
                    # and the current observed page does not trigger its readahead
                    #   -> better candidate, skip current observed page
                    if (self.file_offset_event_mappings_[file][page]["ra_corner_pages"][1] < other_page and 
                        self.file_offset_event_mappings_[file][other_page]["ra_corner_pages"][0] <= page):
                        return True

                    # other page has no useable suppress page -> skip further checks
                    if "ra_suppress_mode" not in self.file_offset_event_mappings_[file][other_page]:
                        continue

                    # a page which triggers the readaround of the currently observed page was identified uniquely
                    # (both ra corner pages present)
                    #   -> better candidate, skip current observed page
                    if (self.file_offset_event_mappings_[file][other_page]["ra_suppress_mode"] == 2 and 
                        self.file_offset_event_mappings_[file][other_page]["ra_suppress_pages_ph_ratios"][0][0] in sample[file] and 
                        self.file_offset_event_mappings_[file][other_page]["ra_suppress_pages_ph_ratios"][1][0] in sample[file]):
                        return True

                    # a page below our current observed page has its left ra corner page present 
                    #   -> better candidate, skip current observed page
                    if (other_page < page and self.file_offset_event_mappings_[file][other_page]["ra_suppress_mode"] == 0 and
                        self.file_offset_event_mappings_[file][other_page]["ra_suppress_pages_ph_ratios"][0][0] in sample[file]): 
                        return True
                    # a page above our current observed page has its right ra corner page present 
                    #   -> better candidate, skip current observed page
                    if (other_page > page and self.file_offset_event_mappings_[file][other_page]["ra_suppress_mode"] == 1 and
                        self.file_offset_event_mappings_[file][other_page]["ra_suppress_pages_ph_ratios"][1][0] in sample[file]): 
                        return True
        return False

    def voteForFinalEvents(self, hit_file_offsets, not_hit_file_offsets):
        score = [0] * self.event_count_

        # for all events in hit page-to-events mappings the score is increased
        for hit in hit_file_offsets:
            mapping = self.file_offset_event_mappings_[hit[0]][hit[1]]
            for event in mapping["event_group"]:
                score[event] += 1

        # for all events in missed page-to-events mappings the score is decreased
        for miss in not_hit_file_offsets:
            mapping = self.file_offset_event_mappings_[miss[0]][miss[1]]
            for event in mapping["event_group"]:
                score[event] -= 1

        # events with the maximum score are returned, except it is <= 0 (no event)
        max_score = np.max(score)
        if max_score <= 0:
            return set()
        return set(np.where(score == max_score)[0].tolist())

    def classifySample(self, sample):
        hit_file_offsets = set()
        
        # best effort classification
        # 1) Get all hit page-to-events mappings
        #    Further, remove ambigous hits using readahead suppression if possible
        for file in sample.keys():
            for page in sample[file]:
                # sampled page not part of tracked target pages at all
                # (could be a readaround corner page though)
                if page not in self.file_offset_event_mappings_[file]:
                    continue 
 
                # if necessary and possible perform ra suppression
                # skip current page if suppression result indicates that this is speculatively
                # prefetched page
                if self.handle_ra_ == "suppressed":
                    # NOTE we do not check the non-parallel-events assumption here as it is a predicondition
                    # ra suppression tells us to skip this page 
                    if self.raSuppressionSpeculativePage(file, page, sample):
                        continue

                # accept for now
                hit_file_offsets.add((file, page))

        # 2) Perform final event detection using a voting algorithm
        not_hit_file_offsets = self.tracked_file_offsets_ - hit_file_offsets
        return self.voteForFinalEvents(hit_file_offsets, not_hit_file_offsets)

    def classifyNextStdin(self):
        sample = {}
        sample_times = []
        # read new sample from stdin
        line = None
        while True:
            line = sys.stdin.readline()
            if line == "\n" or line == "":
                break
            line = line.rstrip("\n")
            tokens = line.split(";")
            sample_times.append(int(tokens[0]))
            if tokens[1] not in sample:
                sample[tokens[1]] = set()
            sample[tokens[1]].add(int(tokens[2], 16))
        # EOF
        if line == "":
            return None
        # classify
        return (np.mean(sample_times) , self.classifySample(sample))
