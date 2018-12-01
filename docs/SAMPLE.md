### pescan

#### Header

- **Target Machine:** `0x14c (IMAGE_FILE_MACHINE_I386)`
- **Compilation Timestamp:** `2006-11-30 09:20:34`
- **Entry Point:** `0x5a46`
- **Contained Sections:** `4`

#### Sections

| Name   | Virtual Address | Virtual Size | Raw Size | Entropy | MD5                              |
| ------ | --------------- | ------------ | -------- | ------- | -------------------------------- |
| .text  | 0x1000          | 0x4bfe       | 20480    | 5.99    | 9062ff3acdff9ac80cd9f97a0df42383 |
| .rdata | 0x6000          | 0xc44        | 4096     | 3.29    | 28c9e7872eb9d0a20a1d953382722735 |
| .data  | 0x7000          | 0x17b0       | 4096     | 4.04    | c38a0453ad319c9cd8b1760baf57a528 |
| .rsrc  | 0x9000          | 0x15d0       | 8192     | 4.50    | 0d4522a26417d45c33759d2a6375a55f |

#### Imports

##### `KERNEL32.DLL`

- GetStartupInfoA
- GetModuleHandleA
- CreatePipe
- PeekNamedPipe
- ReadFile
- CreateProcessA
- MultiByteToWideChar
- GlobalAlloc
- GlobalFree
- GetLocalTime
- RemoveDirectoryA
- FindNextFileA
- FindFirstFileA
- GetFileTime
- SetFileTime
- FindClose
- GetPriorityClass
- OpenProcess
- GetCurrentProcess
- DuplicateHandle
- GetLastError
- LocalFree
- CreateToolhelp32Snapshot
- Process32First
- Process32Next
- GetLogicalDriveStringsA
- GetDriveTypeA
- GetVolumeInformationA
- GetComputerNameA
- CreateFileA
- GetFileSize
- WriteFile
- LoadLibraryA
- GetProcAddress
- FreeLibrary
- GetVersionExA
- GetSystemDefaultLangID
- OpenMutexA
- CreateMutexA
- CloseHandle
- lstrcmpiA
- ExitProcess
- SetEvent
- WaitForSingleObject
- Sleep
- DeleteFileA
- CopyFileA
- GetWindowsDirectoryA
- GetModuleFileNameA
- CreateDirectoryA
- GetFileAttributesA
- SetFileAttributesA
- CreateEventA
- CreateThread

##### `ADVAPI32.dll`

- RegCloseKey
- RegSetValueExA
- RegQueryValueExA
- RegCreateKeyExA
- RegDeleteValueA
- RegOpenKeyExA
- SetSecurityInfo
- SetEntriesInAclA
- AdjustTokenPrivileges
- LookupPrivilegeValueA
- GetTokenInformation
- OpenProcessToken
- GetUserNameA
- LookupAccountSidA
- RegEnumKeyExA
- RegEnumValueA

##### `MPR.dll`

- WNetCloseEnum
- WNetOpenEnumA
- WNetEnumResourceA

##### `MSVCRT.dll`

- \_except_handler3
- \_\_set_app_type
- **p**fmode
- **p**commode
- \_adjust_fdiv
- \_\_setusermatherr
- \_initterm
- \_\_getmainargs
- \_acmdln
- exit
- \_XcptFilter
- \_exit
- swprintf
- fwrite
- fopen
- fseek
- fread
- fclose
- \_strnicmp
- strcmp
- sprintf
- memcpy
- strstr
- strchr
- atoi
- memset
- strlen
- strrchr
- time
- srand
- rand
- strcpy
- strcat
- malloc
- \_EH_prolog
- \_\_CxxFrameHandler
- rename
- \_controlfp
- free
- \_itoa

##### `SHLWAPI.dll`

- SHDeleteKeyA

##### `WS2_32.dll`

- gethostname
- gethostbyname
- WSAGetLastError
- inet_ntoa
- inet_addr
- socket
- htons
- connect
- select
- send
- closesocket
- recv
- WSAStartup
- WSACleanup
- ioctlsocket

#### Resources

| SHA-256                                                          | Size   | Entropy | File Type | Type          | Language                           |
| ---------------------------------------------------------------- | ------ | ------- | --------- | ------------- | ---------------------------------- |
| 52a955550acda3b566c9fa9eda164853df4135dfa5eb7b173b3c5453a12f85a3 | 0x10a8 | 6.52    | None      | RT_ICON       | Chinese-People's Republic of China |
| a14e70ed824f3f17d3a51136aa08839954d6d3ccadaa067415c7bfc08e6636b0 | 0x14   | 1.78    | None      | RT_GROUP_ICON | Chinese-People's Republic of China |
| 934b13844893dc0438a47aadc20d4873f806000c761249795c7f265ccca48bc9 | 0x41c  | 3.47    | None      | RT_VERSION    | Chinese-People's Republic of China |

#### File Version Information

- **Copyright:** `(C) Microsoft Corporation. All rights reserved.`
- **Product:** `Microsoft(R) Windows(R) Operating System`
- **Description:** `Internet Explorer`
- **Original Name:** `IEXPLORE.EXE`
- **Internal Name:** `iexplore`
- **File Version:** `6.00.2900.2180 (xpsp_sp2_rtm.040803-2158)`

#### Signature Info

##### Signature Verification

> No file signature data found

#### PEiD

- `Armadillo v1.71`
- `Microsoft Visual C++ v5.0/v6.0 (MFC)`
- `Microsoft Visual C++`
