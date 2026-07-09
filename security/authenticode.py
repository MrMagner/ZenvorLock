import ctypes
import os
from ctypes import wintypes
from pathlib import Path

# Constants for WinVerifyTrust
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0
WTD_UICONTEXT_EXECUTE = 0

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8)
    ]

# WINTRUST_ACTION_GENERIC_VERIFY_V2
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11d0,
    (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID))
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID)
    ]

def is_executable_signed(filepath: str | Path) -> bool:
    """
    Verifies if a given Windows executable is digitally signed using Authenticode.
    Returns True if the signature is valid, False otherwise.
    """
    filepath = str(filepath)
    if not os.path.exists(filepath):
        return False

    wintrust = ctypes.windll.wintrust

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = filepath
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.pPolicyCallbackData = None
    data.pSIPClientData = None
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = WTD_STATEACTION_IGNORE
    data.hWVTStateData = None
    data.pwszURLReference = None
    data.dwProvFlags = 0
    data.dwUIContext = WTD_UICONTEXT_EXECUTE
    data.pSignatureSettings = None

    status = wintrust.WinVerifyTrust(
        0, 
        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), 
        ctypes.byref(data)
    )

    # 0 (ERROR_SUCCESS) means the trust provider verified the signature.
    return status == 0
