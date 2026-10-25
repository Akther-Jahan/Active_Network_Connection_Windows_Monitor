# ==========================================
# process_resolver.py
# ==========================================

import ctypes

from ctypes import wintypes


# ------------------------------------------
# Windows DLL
# ------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002

MAX_PATH = 260

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ------------------------------------------
# PROCESSENTRY32 Structure
# ------------------------------------------

class PROCESSENTRY32(ctypes.Structure):

    _fields_ = [

        ("dwSize", wintypes.DWORD),

        ("cntUsage", wintypes.DWORD),

        ("th32ProcessID", wintypes.DWORD),

        ("th32DefaultHeapID", ctypes.c_void_p),

        ("th32ModuleID", wintypes.DWORD),

        ("cntThreads", wintypes.DWORD),

        ("th32ParentProcessID", wintypes.DWORD),

        ("pcPriClassBase", ctypes.c_long),

        ("dwFlags", wintypes.DWORD),

        ("szExeFile", ctypes.c_char * MAX_PATH)

    ]


# ------------------------------------------
# API Declaration
# ------------------------------------------

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot

Process32First = kernel32.Process32First

Process32Next = kernel32.Process32Next

CloseHandle = kernel32.CloseHandle


# ------------------------------------------
# Build PID -> Process Name Map
# ------------------------------------------

def build_process_map():

    process_map = {}

    snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0
    )

    if snapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    success = Process32First(
        snapshot,
        ctypes.byref(entry)
    )

    while success:

        pid = entry.th32ProcessID

        try:
            name = entry.szExeFile.decode()
        except:
            name = "Unknown"

        process_map[pid] = name

        success = Process32Next(
            snapshot,
            ctypes.byref(entry)
        )

    CloseHandle(snapshot)

    return process_map