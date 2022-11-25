#!/usr/bin/env python3

from ctypes import *
import ctypes.wintypes as wintypes
import os
from sortedcontainers import SortedList
import mmap
import msvcrt
import pdb


# ctype extension
class StructureExt(Structure):
    def pack(self):
        return bytes(self)

    def unpack(self, bytes):
        fit = min(len(bytes), sizeof(self))
        memmove(addressof(self), bytes, fit)

# filemap protection constants
FILE_MAP_READ = 0x0004
FILE_MAP_WRITE = 0x0002
FILE_MAP_EXECUTE = 0x0020

# process access rights
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_CREATE_THREAD = 0x0002
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_INFORMATION = 0x0200
PROCESS_SET_QUOTA = 0x0100
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE = 0x0001
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION |
    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | 
    PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE)

# vm protection constants 
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_TARGETS_INVALID = 0x40000000
PAGE_TARGETS_NO_UPDATE = 0x40000000
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# vm region states
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000

# vm region types 
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# load library flags
DONT_RESOLVE_DLL_REFERENCES = 0x1

# max path
MAX_PATH = 260

# errors
ERROR_NOACCESS = 998

# end of user virtual address on x64 (canoncial form)
VADDR_USER_END = 0x7FFFFFF0000


# MEMORY_BASIC_INFORMATION 
class MEMORY_BASIC_INFORMATION(StructureExt):
    _fields_ = [("BaseAddress", c_void_p),
                ("AllocationBase", c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("RegionSize", c_uint64),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]

# MODULEINFO 
class MODULEINFO(StructureExt):
    _fields_ = [("lpBaseOfDll", c_void_p),
                ("SizeOfImage",  wintypes.DWORD),
                ("EntryPoint", c_void_p)]

# PSAPI_WORKING_SET_EX_BLOCK
class PSAPI_WORKING_SET_EX_BLOCK(StructureExt):
    _fields_ = [("Valid", c_uint64, 1),
                ("ShareCount", c_uint64, 3),
                ("Win32Protection", c_uint64, 11),
                ("Shared", c_uint64, 1),                
                ("Node", c_uint64, 6),
                ("Locked", c_uint64, 1),
                ("LargePage", c_uint64, 1),
                ("Reserved", c_uint64, 7),                                                                
                ("Bad", c_uint64, 1),
                ("ReservedUlong", c_uint64, 32)]

# PSAPI_WORKING_SET_EX_INFORMATION
class PSAPI_WORKING_SET_EX_INFORMATION(StructureExt):
    _fields_ = [("VirtualAddress", c_void_p),
                ("VirtualAttributes",  PSAPI_WORKING_SET_EX_BLOCK)]

# PSAPI_WS_WATCH_INFORMATION 
class PSAPI_WS_WATCH_INFORMATION(StructureExt):
    _fields_ = [("FaultingPc", c_void_p),
                ("FaultingVa",  c_void_p)]


# specifying functions and argument types
KERNEL32 = windll.kernel32
PSAPI = windll.psapi

#    HANDLE OpenProcess(
#    DWORD dwDesiredAccess,
#    BOOL  bInheritHandle,
#    DWORD dwProcessId
#    );
KERNEL32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
KERNEL32.OpenProcess.restype = wintypes.HANDLE

#    SIZE_T VirtualQueryEx(
#    HANDLE                    hProcess,
#    LPCVOID                   lpAddress,
#    PMEMORY_BASIC_INFORMATION lpBuffer,
#    SIZE_T                    dwLength
#    );
KERNEL32.VirtualQueryEx.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, c_uint64]
KERNEL32.VirtualQueryEx.restype = c_uint64

#    BOOL EnumProcessModules(
#    HANDLE  hProcess,
#    HMODULE *lphModule,
#    DWORD   cb,
#    LPDWORD lpcbNeeded
#    );
PSAPI.EnumProcessModules.argtypes = [wintypes.HANDLE, c_void_p, wintypes.DWORD, c_void_p]
PSAPI.EnumProcessModules.restype = wintypes.BOOL

#    DWORD GetModuleFileNameExA(
#    HANDLE  hProcess,
#    HMODULE hModule,
#    LPSTR   lpFilename,
#    DWORD   nSize
#    );
PSAPI.GetModuleFileNameExA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, c_void_p, wintypes.DWORD]
PSAPI.GetModuleFileNameExA.restype = wintypes.DWORD

#    BOOL GetModuleInformation(
#    HANDLE       hProcess,
#    HMODULE      hModule,
#    LPMODULEINFO lpmodinfo,
#    DWORD        cb
#    );
PSAPI.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, c_void_p, wintypes.DWORD]
PSAPI.GetModuleInformation.restype = wintypes.BOOL

#    DWORD GetMappedFileNameA(
#    HANDLE hProcess,
#    LPVOID lpv,
#    LPSTR  lpFilename,
#    DWORD  nSize
#    );
PSAPI.GetMappedFileNameA.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, wintypes.DWORD]
PSAPI.GetMappedFileNameA.restype = wintypes.DWORD

#    BOOL QueryWorkingSetEx(
#    HANDLE hProcess,
#    PVOID  pv,
#    DWORD  cb
#    );
PSAPI.QueryWorkingSetEx.argtypes = [wintypes.HANDLE, c_void_p, wintypes.DWORD]
PSAPI.QueryWorkingSetEx.restype = wintypes.BOOL

#    BOOL EmptyWorkingSet(
#    HANDLE hProcess
#    );
PSAPI.EmptyWorkingSet.argtypes = [wintypes.HANDLE]
PSAPI.EmptyWorkingSet.restype = wintypes.BOOL

#    BOOL InitializeProcessForWsWatch(
#    HANDLE hProcess
#    );
PSAPI.InitializeProcessForWsWatch.argtypes = [wintypes.HANDLE]
PSAPI.InitializeProcessForWsWatch.restype = wintypes.BOOL

#    BOOL GetWsChanges(
#    HANDLE                      hProcess,
#    PPSAPI_WS_WATCH_INFORMATION lpWatchInfo,
#    DWORD                       cb
#    );
PSAPI.GetWsChanges.argtypes = [wintypes.HANDLE, c_void_p, wintypes.DWORD]
PSAPI.GetWsChanges.restype = wintypes.BOOL

#    BOOL CloseHandle(
#    HANDLE hObject
#    );
KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
KERNEL32.CloseHandle.restype = wintypes.BOOL

#    DWORD QueryDosDeviceA(
#    LPCSTR lpDeviceName,
#    LPSTR  lpTargetPath,
#    DWORD  ucchMax
#    );
KERNEL32.QueryDosDeviceA.argtypes = [c_void_p, c_void_p, wintypes.DWORD]
KERNEL32.QueryDosDeviceA.restype = wintypes.DWORD

#    DWORD GetLogicalDriveStringsA(
#    DWORD nBufferLength,
#    LPSTR lpBuffer
#    );
KERNEL32.GetLogicalDriveStringsA.argtypes = [wintypes.DWORD, c_void_p]
KERNEL32.GetLogicalDriveStringsA.restype = wintypes.DWORD

#    BOOL DebugActiveProcess(
#    DWORD dwProcessId
#    );
KERNEL32.DebugActiveProcess.argtypes = [wintypes.DWORD]
KERNEL32.DebugActiveProcess.restype = wintypes.BOOL

#    BOOL DebugActiveProcessStop(
#    DWORD dwProcessId
#    );
KERNEL32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
KERNEL32.DebugActiveProcessStop.restype = wintypes.BOOL

#    BOOL ReadProcessMemory(
#    HANDLE  hProcess,
#    LPCVOID lpBaseAddress,
#    LPVOID  lpBuffer,
#    SIZE_T  nSize,
#    SIZE_T  *lpNumberOfBytesRead
#    );
KERNEL32.ReadProcessMemory.argtypes = [wintypes.HANDLE, c_void_p, c_void_p, c_uint64, c_void_p]
KERNEL32.ReadProcessMemory.restype = wintypes.BOOL

#    BOOL EnumProcesses(
#    DWORD   *lpidProcess,
#    DWORD   cb,
#    LPDWORD lpcbNeeded
#    );
PSAPI.EnumProcesses.argtypes = [c_void_p, wintypes.DWORD, c_void_p]
PSAPI.EnumProcesses.restype = wintypes.BOOL

#    HANDLE GetCurrentProcess();
KERNEL32.GetCurrentProcess.argtypes = []
KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE

#    BOOL VirtualLock(
#    LPVOID lpAddress,
#    SIZE_T dwSize
#    );
KERNEL32.VirtualLock.argtypes = [c_void_p, c_uint64]
KERNEL32.VirtualLock.restype = wintypes.BOOL

#    BOOL VirtualUnlock(
#    LPVOID lpAddress,
#    SIZE_T dwSize
#    );
KERNEL32.VirtualUnlock.argtypes = [c_void_p, c_uint64]
KERNEL32.VirtualUnlock.restype = wintypes.BOOL

#    HMODULE LoadLibraryA(
#    LPCSTR lpLibFileName
#    );
KERNEL32.LoadLibraryA.argtypes = [c_void_p]
KERNEL32.LoadLibraryA.restype = wintypes.HMODULE

#    HMODULE LoadLibraryExA(
#    LPCSTR lpLibFileName,
#    HANDLE hFile,
#    DWORD  dwFlags
#    );
KERNEL32.LoadLibraryExA.argtypes = [c_void_p, wintypes.HANDLE, wintypes.DWORD]
KERNEL32.LoadLibraryExA.restype = wintypes.HMODULE


#    BOOL FreeLibrary(
#    HMODULE hLibModule
#    );
KERNEL32.FreeLibrary.argtypes = [wintypes.HMODULE]
KERNEL32.FreeLibrary.restype = wintypes.BOOL

#    HANDLE CreateFileMappingA(
#    HANDLE                hFile,
#    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
#    DWORD                 flProtect,
#    DWORD                 dwMaximumSizeHigh,
#    DWORD                 dwMaximumSizeLow,
#    LPCSTR                lpName
#    );
KERNEL32.CreateFileMappingA.argtypes = [wintypes.HANDLE, c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, c_void_p]
KERNEL32.CreateFileMappingA.restype = wintypes.HANDLE

#    LPVOID MapViewOfFile(
#    HANDLE hFileMappingObject,
#    DWORD  dwDesiredAccess,
#    DWORD  dwFileOffsetHigh,
#    DWORD  dwFileOffsetLow,
#    SIZE_T dwNumberOfBytesToMap
#    );
KERNEL32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, c_uint64]
KERNEL32.MapViewOfFile.restype = c_void_p

#    BOOL UnmapViewOfFile(
#    LPCVOID lpBaseAddress
#    );
KERNEL32.UnmapViewOfFile.argtypes = [c_void_p]
KERNEL32.UnmapViewOfFile.restype = wintypes.BOOL

#    BOOL SetProcessWorkingSetSize(
#    HANDLE hProcess,
#    SIZE_T dwMinimumWorkingSetSize,
#    SIZE_T dwMaximumWorkingSetSize
#    );
KERNEL32.SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, c_uint64, c_uint64]
KERNEL32.SetProcessWorkingSetSize.restype = wintypes.BOOL


PIDS_PREALLOC_COUNT = 1000000
def getAllProcessPIDs():
    # get pids of all processes
    pids = (wintypes.DWORD * PIDS_PREALLOC_COUNT)()
    fetch_max = wintypes.DWORD(PIDS_PREALLOC_COUNT)
    fetch_needed = wintypes.DWORD(0)
    while True:
        res = PSAPI.EnumProcesses(pointer(pids), sizeof(pids), pointer(fetch_needed))
        if not res:
            raise WinError()
        
        fetch_needed.value = int(fetch_needed.value / sizeof(wintypes.DWORD))
        if fetch_needed.value < fetch_max.value:
            break
        else: 
            fetch_max.value = fetch_needed.value + 1
    # do not add idle process
    return pids[:fetch_needed.value]

MODULE_HANDLES_PREALLOC_COUNT = 1000000
def getModuleHandles(process_handle):
    module_handles = (wintypes.HMODULE * MODULE_HANDLES_PREALLOC_COUNT)()
    fetch_max = wintypes.DWORD(MODULE_HANDLES_PREALLOC_COUNT)
    fetch_needed = wintypes.DWORD(0)
    while True:
        res = PSAPI.EnumProcessModules(process_handle, pointer(module_handles), sizeof(module_handles), 
            pointer(fetch_needed))
        if not res:
            raise WinError()

        fetch_needed.value = int(fetch_needed.value / sizeof(wintypes.HMODULE))
        if fetch_needed.value < fetch_max.value:
            break
        else: 
            fetch_max.value = fetch_needed.value + 1
    return module_handles[:fetch_needed.value]

DRIVE_PATH_TO_DRIVE_LETTER = None
# path should be string
def convertToPathWithDriveLetter(path):
    global DRIVE_PATH_TO_DRIVE_LETTER
    path_drive = '\\'.join(path.split('\\')[:3])
    # not in cache
    if DRIVE_PATH_TO_DRIVE_LETTER is None or path_drive not in DRIVE_PATH_TO_DRIVE_LETTER:
        DRIVE_PATH_TO_DRIVE_LETTER = {}
        drive_letters_raw = create_string_buffer(4096)
        # get all possible drive letters
        fetched = KERNEL32.GetLogicalDriveStringsA(sizeof(drive_letters_raw), pointer(drive_letters_raw))
        if fetched == 0 or fetched > sizeof(drive_letters_raw):
            raise WinError()
        drive_letters = drive_letters_raw.raw.split(b"\x00")
        drive_letters = drive_letters[:drive_letters.index(b"")]
        drive_letters = [ drive_letter.rstrip(b"\\") for drive_letter in drive_letters]
        # fetch drive paths for drive letters
        drive_path = create_string_buffer(MAX_PATH)
        for drive_letter in drive_letters:
            fetched = KERNEL32.QueryDosDeviceA(drive_letter, pointer(drive_path), MAX_PATH)
            if fetched == 0:
                raise WinError()
            DRIVE_PATH_TO_DRIVE_LETTER[drive_path.value.decode("utf-8")] = drive_letter.decode("utf-8")
    # build path 
    remainder = path[len(path_drive):]
    return os.path.join(DRIVE_PATH_TO_DRIVE_LETTER[path_drive], remainder)


# container for file maps (auto close)
class MapObject:
    def __init__(self, address, length):
        self.address = address 
        self.length = length

    def __del__(self):
        if self.address is not None:
            KERNEL32.UnmapViewOfFile(self.address)                        

def mapFileSharedRo(path):
    # map whole file
    with open(path, "rb") as file:
        # get file size 
        file.seek(0, os.SEEK_END)
        length = file.tell()
        file.seek(0, os.SEEK_SET)

        # check file size 
        if length == 0:
            raise ValueError

        # map file
        # get file handle
        fh = msvcrt.get_osfhandle(file.fileno())
        # create mapping
        mapping_handle = KERNEL32.CreateFileMappingA(fh, None, PAGE_READONLY, 0, 0, None)
        if mapping_handle is None:
            raise WinError()
        # create view
        address = KERNEL32.MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0)
        if address == 0:
            ec = GetLastError()
            KERNEL32.CloseHandle(mapping_handle)
            raise WinError(ec)
    
    # success
    # close mapping handle
    KERNEL32.CloseHandle(mapping_handle)
    # return object
    mo = MapObject(address, length)
    return mo

# container for image maps (auto close)
class ImageObject:
    def __init__(self, address, length):
        self.address = address 
        self.length = length

    def __del__(self):
        if self.address is not None:
            KERNEL32.FreeLibrary(self.address)

def mapImage(image_path, flags = 0):
    address = KERNEL32.LoadLibraryExA(image_path.encode("utf8"), None, flags)
    if address is None:
        raise WinError()

    # get module info
    module_info = MODULEINFO()
    res = PSAPI.GetModuleInformation(KERNEL32.GetCurrentProcess(), address, pointer(module_info), sizeof(MODULEINFO))
    if not res:
        raise WinError()
    
    mm = ImageObject(address, module_info.SizeOfImage)
    return mm


# range for representing virtual objects
class VirtualRange:
    def __init__(self, vaddr_range, range_type, range_protection = 0, backing_file = "", range_file_offset = -1):
        self.vaddr_range = vaddr_range 
        self.range_type = range_type
        self.range_protection = range_protection
        self.backing_file = backing_file 
        self.range_file_offset = range_file_offset

    def __gt__(self, other):
        if not isinstance(other, VirtualRange):
            raise Exception("Can not compare with {0}!".format(type(other)))
        else:
            return self.vaddr_range[0] > other.vaddr_range[1]

    def __lt__(self, other):
        if not isinstance(other, VirtualRange):
            raise Exception("Can not compare with {0}!".format(type(other)))
        else:
            return self.vaddr_range[1] < other.vaddr_range[0]

    def __repr__(self):
        string = "Virtual Address Range: 0x{:x} - 0x{:x} Range Type: 0x{:x} Range Protection: 0x{:x} File: {} File Offset: 0x{:x}".format(
            self.vaddr_range[0], self.vaddr_range[1], self.range_type, self.range_protection, self.backing_file, self.range_file_offset)
        return string

# Helps to get a process's current virtual memory mappings
# NOTE This is only a snapshot and might be subject to changes!
class MapsReader:
    def __init__(self, pid):
        self.maps_ = None
        self.pid_ = pid
        self.process_handle_ = KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
        if self.process_handle_ is None:
            raise WinError()

    def _addImageMaps(self):
        # get handles
        module_handles = getModuleHandles(self.process_handle_)
        # get additional information (file names)
        for i in range(len(module_handles)):
            image_handle = module_handles[i]
            # get file name
            file_path = create_string_buffer(MAX_PATH) 
            fetched_str_length = PSAPI.GetModuleFileNameExA(self.process_handle_, image_handle, 
                pointer(file_path), MAX_PATH)
            if fetched_str_length == 0:
                raise WinError()

            # get module info
            module_info = MODULEINFO()
            res = PSAPI.GetModuleInformation(self.process_handle_, image_handle, pointer(module_info), sizeof(MODULEINFO))
            if not res:
                raise WinError()
            
            # add
            self.maps_.add(VirtualRange((image_handle, image_handle + module_info.SizeOfImage - mmap.PAGESIZE), 
                MEM_IMAGE, 0, file_path.value.decode("utf8"), 0))

    def _tryToRecoverRangeFileOffset(self, vaddr_begin, vaddr_end, file_path):
        distance = vaddr_end - vaddr_begin
        # only one page
        if distance == 0:
            # read page from process memory
            vpage = create_string_buffer(mmap.PAGESIZE)
            res = KERNEL32.ReadProcessMemory(self.process_handle_, vaddr_begin, pointer(vpage), mmap.PAGESIZE, None)
            if not res:
                return -1

            # compare with file pages
            try:
                # map file
                f = open(file_path, "r") 
                fm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                # iterate over file
                found_pos = 0
                found_count = 0
                pos = 0
                while pos < len(fm):
                    # might be below 4096!
                    fpage = memoryview(fm)[pos : pos + mmap.PAGESIZE]
                    if memoryview(vpage.raw)[:len(fpage)] == fpage:
                        found_pos = pos
                        found_count += 1
                    pos += mmap.PAGESIZE
                if found_count == 1:
                    return found_pos
                else:
                    return -1
            except:
                return -1

        # larger range
        else:
            # read begin and end page from process memory
            vpage_begin = create_string_buffer(mmap.PAGESIZE)
            vpage_end = create_string_buffer(mmap.PAGESIZE)
            res = KERNEL32.ReadProcessMemory(self.process_handle_, vaddr_begin, pointer(vpage_begin), mmap.PAGESIZE, None)
            if not res:
                return -1            
            res = KERNEL32.ReadProcessMemory(self.process_handle_, vaddr_end, pointer(vpage_end), mmap.PAGESIZE, None)
            if not res:
                return -1            

            # compare with file pages
            try:
                # map file
                f = open(file_path, "r") 
                fm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                # iterate over file
                found_pos = 0
                found_count = 0
                pos = 0
                while pos + distance < len(fm):
                    fpage_begin = memoryview(fm)[pos : pos + mmap.PAGESIZE]
                    # might be below 4096 !
                    fpage_end = memoryview(fm)[pos + distance : pos + distance + mmap.PAGESIZE]
                    if (vpage_begin.raw == fpage_begin  and 
                       memoryview(vpage_end.raw)[:len(fpage_end)] == fpage_end):
                        found_pos = pos
                        found_count += 1
                    pos += mmap.PAGESIZE
                if found_count == 1:
                    return found_pos
                else:
                    return -1
            except:
                return -1
        return -1

    def _addOtherMaps(self):
        address = 0
        while address <= VADDR_USER_END:
            #print("Evaluating: 0x{:x}".format(address))
            mem_info = MEMORY_BASIC_INFORMATION()
            fetched_bytes = KERNEL32.VirtualQueryEx(self.process_handle_, c_void_p(address), pointer(mem_info), 
                sizeof(MEMORY_BASIC_INFORMATION))
            if fetched_bytes == 0:
                raise WinError()

            # evaluate regions
            # state 
            if mem_info.State == MEM_FREE:
                address = address + mem_info.RegionSize
                continue
            # type
            # private region
            if mem_info.Type == MEM_PRIVATE:
                self.maps_.add(VirtualRange((mem_info.BaseAddress, mem_info.BaseAddress + mem_info.RegionSize - mmap.PAGESIZE), 
                    MEM_PRIVATE, mem_info.Protect))
            # mapped region
            elif mem_info.Type == MEM_MAPPED:
                # get file path
                file_path = create_string_buffer(MAX_PATH) 
                fetched_str_length = PSAPI.GetMappedFileNameA(self.process_handle_, mem_info.BaseAddress, 
                    pointer(file_path), MAX_PATH)
                # could not get file name out ot some reason, just use empty file name
                if fetched_str_length == 0:
                    file_path.value = b""
                elif fetched_str_length >= MAX_PATH:
                    raise WinError()
                # if we know the backing files path try to resolve the offset
                if len(file_path.value) > 0:
                    file_path_dos = convertToPathWithDriveLetter(file_path.value.decode("utf8"))
                    # try to recover file offset
                    # as we got an file name for the region it should still be shared
                    # attempt to read the first and last page of the region and search it in the file to find the offset
                    range_file_offset = self._tryToRecoverRangeFileOffset(mem_info.BaseAddress, mem_info.BaseAddress +
                        mem_info.RegionSize - mmap.PAGESIZE, file_path_dos)
                    self.maps_.add(VirtualRange((mem_info.BaseAddress, mem_info.BaseAddress + mem_info.RegionSize - mmap.PAGESIZE), 
                    MEM_MAPPED, mem_info.Protect, file_path_dos, range_file_offset))    
                else:
                    self.maps_.add(VirtualRange((mem_info.BaseAddress, mem_info.BaseAddress + mem_info.RegionSize - mmap.PAGESIZE), 
                    MEM_MAPPED, mem_info.Protect))
            # advance to next region (image regions are already processed)
            address = mem_info.BaseAddress + mem_info.RegionSize

    def getMaps(self):
        KERNEL32.DebugActiveProcess(self.pid_)
        try:
            self.maps_ = SortedList()
            # first get all image mappings
            self._addImageMaps()
            # get rest of the mappings
            self._addOtherMaps()
        except Exception as e:
            raise(e)
        finally:
            KERNEL32.DebugActiveProcessStop(self.pid_)
        return self.maps_
        
    def __del__(self):
        if self.process_handle_ != 0:
            KERNEL32.CloseHandle(self.process_handle_)

class PageUsageTracker:
    def __init__(self):
        self.pid_ = os.getpid()
        self.own_process_handle_ = KERNEL32.GetCurrentProcess() 
        if self.own_process_handle_ is None:
            raise WinError()

    def reset(self, unused = None):
        # get pids of all processes
        pids = getAllProcessPIDs()

        # empty all working sets which allow it
        # NOTE This does not work on protected processes even if the user has the SeDebugPrivilege
        # To disable the protection changing the EPROCESS.Protection member to 0 using a custom kernel driver 
        # or the kernel debugger.
        # Otherwise, it might not be possible to empty the working set completly.
        for i in range(len(pids)):
            pid = pids[i]
            # not our own process
            # also skip idle process (0)
            if pid == self.pid_ or pid == 0:
                continue

            handle = KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, 0, pid)
            if handle is None:
                print("WARNING: Can not open process {}".format(pid))
                # skip invalid handles
                continue
            res = PSAPI.EmptyWorkingSet(handle) #KERNEL32.SetProcessWorkingSetSize(handle, -1, -1)
            if not res:
                print("WARNING: Error at EmptyWorkingSet: {}".format(GetLastError()))
            KERNEL32.CloseHandle(handle)
  
    def getState(self, vpages):
        states = [False] * len(vpages)
        wsi = PSAPI_WORKING_SET_EX_INFORMATION()
        for i, vpage in enumerate(vpages):
            # not usable
            if vpage == -1:
                continue
            # prepare address
            wsi.VirtualAddress = vpage * mmap.PAGESIZE
            # try to lock pages 
            res = KERNEL32.VirtualLock(wsi.VirtualAddress, mmap.PAGESIZE)
            if not res:
                # not accessible, skip
                if GetLastError() == ERROR_NOACCESS:
                    continue
                raise WinError()
            # get share state
            res = PSAPI.QueryWorkingSetEx(self.own_process_handle_, pointer(wsi), sizeof(wsi))
            if not res:
                KERNEL32.VirtualUnlock(wsi.VirtualAddress, mmap.PAGESIZE)
                KERNEL32.VirtualUnlock(wsi.VirtualAddress, mmap.PAGESIZE)
                continue
            if (wsi.VirtualAttributes.Valid and wsi.VirtualAttributes.Shared and 
                wsi.VirtualAttributes.ShareCount > 1):
                states[i] = True
            KERNEL32.VirtualUnlock(wsi.VirtualAddress, mmap.PAGESIZE)
            KERNEL32.VirtualUnlock(wsi.VirtualAddress, mmap.PAGESIZE)
        return states

    def __del__(self):
        if self.own_process_handle_ != 0:
            KERNEL32.CloseHandle(self.own_process_handle_)
