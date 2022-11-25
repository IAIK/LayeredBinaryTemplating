#!/usr/bin/env python3

from ctypes import *
import ctypes
import os
import signal
import mmap
import pdb


# ctype extension
class StructureExt(Structure):
    def pack(self):
        return bytes(self)

    def unpack(self, bytes):
        fit = min(len(bytes), sizeof(self))
        memmove(addressof(self), bytes, fit)


# fs/proc/task_mmu.c
class PageMapEntry(StructureExt):
    _fields_ = [("pfn_swap", c_uint64, 55),
                ("soft_dirty", c_uint64, 1),
                ("exclusive", c_uint64, 1),
                ("zero", c_uint64, 4),
                ("file_shared", c_uint64, 1),
                ("swapped", c_uint64, 1),
                ("present", c_uint64, 1)]


# container for memory-mapped objects (auto close)
class MmapObject:
    def __init__(self, address, length):
        self.address = address 
        self.length = length

    def __del__(self):
        if self.address != -1:
            if LIBC.munmap(c_void_p(self.address), c_size_t(self.length)) != 0:
                raise("munmap() failed: " + str(get_errno()))


PROCESS_STAT_PATH_TEMPLATE = "/proc/{}/stat"
PROCESS_MAPS_PATH_TEMPLATE = "/proc/{}/maps"
PROCESS_PAGEMAP_PATH_TEMPLATE = "/proc/{}/pagemap"
PROCESS_MEM_PATH_TEMPLATE = "/proc/{}/mem"
KPAGEFLAGS_PATH = "/proc/kpageflags"
PAGE_IDLE_BITMAP_PATH = "/sys/kernel/mm/page_idle/bitmap"

LIBC = CDLL("libc.so.6")
LIBC.mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_size_t]
LIBC.mmap.restype = c_void_p
LIBC.mlock.argtypes = [c_void_p, c_size_t]
LIBC.mlock.restype = c_int
LIBC.mincore.argtypes = [c_void_p, c_size_t, c_char_p]
LIBC.mincore.restype = c_int
LIBC.madvise.argtypes = [c_void_p, c_size_t, c_int]
LIBC.madvise.restype = c_int


def mapFileSharedRo(file):
    # map whole file
    with open(file, "rb") as file:
        # get file size 
        file.seek(0, os.SEEK_END)
        length = file.tell()
        file.seek(0, os.SEEK_SET)

        # check file size 
        if length == 0:
            raise ValueError

        # get file descriptor
        fd = file.fileno()
        address = LIBC.mmap(0, length, mmap.PROT_READ, mmap.MAP_SHARED, fd, 0)
        if address == c_void_p(-1).value:
            raise RuntimeError("mmap() failed: " + str(get_errno()))

    mm = MmapObject(address, length)
    return mm

def mlock(address, length):
    # mlock
    if LIBC.mlock(address, length) != 0:
        raise RuntimeError("mlock() failed: " + str(get_errno()))

def mincore(address, length):
    state = create_string_buffer(int((length + mmap.PAGESIZE - 1) / mmap.PAGESIZE))
    if LIBC.mincore(address, length, state) != 0:
        raise RuntimeError("mincore() failed: " + str(get_errno()))
    return state.raw

def madvise(address, length, advice):
    if LIBC.madvise(address, length, advice) != 0:
        raise RuntimeError("madvise() failed: " + str(get_errno()))    

def mread(address, length = 1):
    return string_at(address, length)    


class ProcessControl:
    def __init__(self, pid=None):
        self.pid_ = pid

    def connect(self, pid):
        self.pid_ = pid

    def freeze(self):
        # signal SIGSTOP (freeze process)
        os.kill(self.pid_, signal.SIGSTOP)
        # wait for stop of process
        with open(PROCESS_STAT_PATH_TEMPLATE.format(self.pid_), "r") as file:
            while True:
                file.seek(0)
                status_str = file.read()
                if status_str.split(" ")[2] == "T":
                    break
                os.sched_yield()

    def resume(self):
        os.kill(self.pid_, signal.SIGCONT)


class MapsReader:
    def __init__(self, pid=None):
        self.maps_ = None
        if pid is not None:
            self.parse(pid)

    def parse(self, pid):
        maps = []
        with open(PROCESS_MAPS_PATH_TEMPLATE.format(pid), "r") as file:
            maps_content = file.read()
        maps_lines = maps_content.split("\n")
        for line in maps_lines:
            # skip empty lines
            if line == "":
                continue
            # process memory regions
            tokens = line.split()
            addresses = [int(token, 16) for token in tokens[0].split("-")]
            maps.append({"addresses": addresses, "size": addresses[1] - addresses[0],
                         "perms": tokens[1], "file_offset": int(tokens[2], 16),
                         "inode": int(tokens[4]), "path": "" if len(tokens) < 6 else tokens[5]})
        self.maps_ = maps

    def getMapsBySize(self, size, only_file=False, only_anon=False):
        found = []
        for map in self.maps_:
            if(map["size"] == size and
               (not only_anon or map["inode"] == 0) and
               (not only_file or map["inode"] != 0)):
                found.append(map)
        return found

    def getMapsByAddr(self, addr, only_file=False, only_anon=False):
        found = []
        for map in self.maps_:
            if(addr >= map["addresses"][0] and addr <= map["addresses"][1]
               and (not only_anon or map["inode"] == 0)
               and (not only_file or map["inode"] != 0)):
                found.append(map)
        return found

    def getMapsByPermissions(self, read=None, write=None, executable=None, only_file=False, only_anon=False):
        found = []
        for map in self.maps_:
            if((read == True and map["perms"][0] != 'r') or
               (read == False and map["perms"][0] != '-')):
                continue
            if((write == True and map["perms"][1] != 'w') or
               (write == False and map["perms"][1] != '-')):
                continue
            if((executable == True and map["perms"][2] != 'x') or
               (executable == False and map["perms"][2] != '-')):
                continue

            if only_anon and map["inode"] != 0:
                continue
            if only_file and map["inode"] == 0:
                continue

            found.append(map)
        return found

    def getMaps(self, only_file=False, only_anon=False):
        if not only_anon and not only_file:
            return self.maps_

        found = []
        for map in self.maps_:
            if((not only_anon or map["inode"] == 0) and
               (not only_file or map["inode"] != 0)):
                found.append(map)

        return found


# https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/mm/pagemap.rst
class PageMapReader:
    def __init__(self, pid=None):
        self.pagemap_fd_ = -1
        self.kpageflags_fd_ = os.open(KPAGEFLAGS_PATH, os.O_RDONLY)
        if pid is not None:
            self.connect(pid)

    def connect(self, pid):
        if self.pagemap_fd_ != -1:
            os.close(self.pagemap_fd_)
        self.pagemap_fd_ = os.open(
            PROCESS_PAGEMAP_PATH_TEMPLATE.format(pid), os.O_RDONLY)

    def getMapping(self, vpn):
        # read
        data = os.pread(self.pagemap_fd_, sizeof(PageMapEntry), vpn * sizeof(PageMapEntry))
        # parse
        pagemap_entry = PageMapEntry()
        pagemap_entry.unpack(data)
        # get kpageflags - if present
        kpageflags = 0
        if pagemap_entry.present:
            raw = os.pread(self.kpageflags_fd_, 8, pagemap_entry.pfn_swap * 8)
            kpageflags = int.from_bytes(raw, "little")
        return (pagemap_entry, kpageflags)

    def __del__(self):
        if self.pagemap_fd_ != -1:
            os.close(self.pagemap_fd_)


class MemReader:
    def __init__(self, pid=None):
        self.mem_fd_ = None
        if pid is not None:
            self.connect(pid)

    def connect(self, pid):
        if self.mem_fd_ is not None:
            self.mem_fd_.close()
        self.mem_fd_ = os.open(PROCESS_MEM_PATH_TEMPLATE.format(pid), os.O_RDONLY)

    def getMem(self, vaddr, size):
        data = os.pread(self.mem_fd_, size, vaddr)
        return data

    def __del__(self):
        if self.mem_fd_ != -1:
            os.close(self.mem_fd_)


class HexDumpPrinter:
    def __init__(self, bytes_per_line, show_addr):
        self.bytes_per_line_ = bytes_per_line
        self.show_addr_ = show_addr

    def getPrintableAscii(self, byte):
        # printable range
        if byte >= 33 and byte <= 126:
            return chr(byte)
        # placeholder
        else:
            return '.'

    def print(self, data):
        offset = 0
        ascii_str = ""
        for byte in data:
            # new line
            if offset % self.bytes_per_line_ == 0:
                # print as hex string
                print(" " + ascii_str)
                if self.show_addr_:
                    print("0x{:08x}: ".format(offset), end="")
                ascii_str = ""

            # print byte
            print("{:02x} ".format(byte), end="")
            # add to string
            ascii_str += self.getPrintableAscii(byte)
            offset += 1
        # print left hexstring
        print(" " + ascii_str)


class PageUsageTracker:
    def __init__(self):
        self.page_idle_bitmap_fd_ = os.open(PAGE_IDLE_BITMAP_PATH, os.O_RDWR)

    def reset(self, pfns):
        for pfn in pfns:
            if pfn == -1:
                continue
            # reset page (mark idle)
            offset = int(pfn / 64) * 8
            bit = pfn % 64
            value = bytearray(8)
            value[int(bit / 8)] = 1 << (bit % 8)
            # alternative value: (1 << (pfn % 64)).to_bytes(8, "little")
            os.pwrite(self.page_idle_bitmap_fd_, value, offset) 

    def getState(self, pfns):
        states = [False] * len(pfns)
        for i, pfn in enumerate(pfns):
            if pfn == -1:
                continue
            # read state
            offset = int(pfn / 64) * 8 
            raw = os.pread(self.page_idle_bitmap_fd_, 8, offset)
            number = int.from_bytes(raw, "little")
            # check if page was accessed (not idle anymore)
            states[i] = not ((number >> (pfn % 64)) & 1)
        return states

    def __del__(self):
        if self.page_idle_bitmap_fd_ != -1:
            os.close(self.page_idle_bitmap_fd_)
