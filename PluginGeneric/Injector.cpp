#include "Injector.h"
#include <Psapi.h>
#include "Scylla/Logger.h"
#include <Scylla/User32Loader.h>
#include <Scylla/OsInfo.h>
#include <Scylla/PebHider.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>

#include "..\InjectorCLI\\ApplyHooking.h"

extern scl::Settings g_settings;
extern scl::Logger g_log;

static LPVOID remoteImageBase = 0;

typedef void(__cdecl * t_SetDebuggerBreakpoint)(DWORD_PTR address);
t_SetDebuggerBreakpoint _SetDebuggerBreakpoint = 0;

//anti-attach vars
DWORD ExitThread_addr;
BYTE* DbgUiIssueRemoteBreakin_addr;
DWORD jmpback;
DWORD DbgUiRemoteBreakin_addr;
BYTE* RemoteBreakinPatch;
BYTE OllyRemoteBreakInReplacement[8];
HANDLE hDebuggee;

void ReadNtApiInformation(HOOK_DLL_DATA *hdd, DWORD targetPid)
{
    scl::User32Loader user32Loader;
    if (!user32Loader.FindSyscalls({
        "NtUserBlockInput",
        "NtUserBuildHwndList",
        "NtUserFindWindowEx",
        "NtUserQueryWindow",
        "NtUserGetForegroundWindow",
        "NtUserGetClassName",
        "NtUserInternalGetWindowText",
        "NtUserGetThreadState" }, targetPid))
    {
        g_log.LogError(L"Failed to find user32.dll/win32u.dll syscalls!");
        return;
    }

    hdd->NtUserBlockInputVA = user32Loader.GetUserSyscallVa("NtUserBlockInput");
    hdd->NtUserQueryWindowVA = user32Loader.GetUserSyscallVa("NtUserQueryWindow");
    hdd->NtUserGetForegroundWindowVA = user32Loader.GetUserSyscallVa("NtUserGetForegroundWindow");
    hdd->NtUserBuildHwndListVA = user32Loader.GetUserSyscallVa("NtUserBuildHwndList");
    hdd->NtUserFindWindowExVA = user32Loader.GetUserSyscallVa("NtUserFindWindowEx");
    hdd->NtUserGetClassNameVA = user32Loader.GetUserSyscallVa("NtUserGetClassName");
    hdd->NtUserInternalGetWindowTextVA = user32Loader.GetUserSyscallVa("NtUserInternalGetWindowText");
    hdd->NtUserGetThreadStateVA = user32Loader.GetUserSyscallVa("NtUserGetThreadState");

    g_log.LogInfo(L"Loaded VA for NtUserBlockInput = 0x%p", hdd->NtUserBlockInputVA);
    g_log.LogInfo(L"Loaded VA for NtUserQueryWindow = 0x%p", hdd->NtUserQueryWindowVA);
    g_log.LogInfo(L"Loaded VA for NtUserGetForegroundWindow = 0x%p", hdd->NtUserGetForegroundWindowVA);
    g_log.LogInfo(L"Loaded VA for NtUserBuildHwndList = 0x%p", hdd->NtUserBuildHwndListVA);
    g_log.LogInfo(L"Loaded VA for NtUserFindWindowEx = 0x%p", hdd->NtUserFindWindowExVA);
    g_log.LogInfo(L"Loaded VA for NtUserGetClassName = 0x%p", hdd->NtUserGetClassNameVA);
    g_log.LogInfo(L"Loaded VA for NtUserInternalGetWindowText = 0x%p", hdd->NtUserInternalGetWindowTextVA);
    g_log.LogInfo(L"Loaded VA for NtUserGetThreadState = 0x%p", hdd->NtUserGetThreadStateVA);
}

#ifndef _WIN64
void __declspec(naked) handleAntiAttach()
{
    _asm {
        push ebp //stolen bytes
        mov ebp, esp //stolen bytes
        pushad
        mov eax, dword ptr[ebp + 0x8]
        mov hDebuggee, eax
    }

    //write our RemoteBreakIn patch to target memory
    RemoteBreakinPatch = (BYTE*)VirtualAllocEx(hDebuggee, 0, sizeof(OllyRemoteBreakInReplacement), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hDebuggee, (LPVOID)RemoteBreakinPatch, OllyRemoteBreakInReplacement, sizeof(OllyRemoteBreakInReplacement), NULL);

    //find push ntdll.DbgUiRemoteBreakin and patch our patch function addr there
    while (*(DWORD*)DbgUiIssueRemoteBreakin_addr != DbgUiRemoteBreakin_addr) {
        DbgUiIssueRemoteBreakin_addr++;
    }
    WriteProcessMemory(GetCurrentProcess(), DbgUiIssueRemoteBreakin_addr, &RemoteBreakinPatch, 4, NULL);
    ULONG oldProtect;
    VirtualProtectEx(hDebuggee, RemoteBreakinPatch, sizeof(OllyRemoteBreakInReplacement), PAGE_EXECUTE_READ, &oldProtect);

    _asm {
        popad
        mov eax, jmpback
        jmp eax
    }
}
#endif

void InstallAntiAttachHook()
{
#ifndef _WIN64
    HANDLE hOlly = GetCurrentProcess();

    DbgUiIssueRemoteBreakin_addr = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiIssueRemoteBreakin");
    DbgUiRemoteBreakin_addr = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiRemoteBreakin");
    ExitThread_addr = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    jmpback = (DWORD)DbgUiIssueRemoteBreakin_addr;
    jmpback += 5;

    BYTE jmp[1] = { 0xE9 };
    WriteProcessMemory(hOlly, DbgUiIssueRemoteBreakin_addr, &jmp, sizeof(jmp), NULL);
    DWORD patch = (DWORD)handleAntiAttach;
    patch -= (DWORD)DbgUiIssueRemoteBreakin_addr;
    patch -= 5;
    WriteProcessMemory(hOlly, DbgUiIssueRemoteBreakin_addr + 1, &patch, 4, NULL);

    //init our remote breakin patch
    BYTE* p = &OllyRemoteBreakInReplacement[0];
    *p = 0xCC;  //int3
    p++;
    *p = 0x68;  //push
    p++;
    *(DWORD*)(p) = ExitThread_addr;
    p += 4;
    *p = 0xC3; //retn
#endif
}

bool StartFixBeingDebugged(DWORD targetPid, bool setToNull)
{
    scl::Handle hProcess(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid));
    if (!hProcess.get())
        return false;

    auto peb = scl::GetPeb(hProcess.get());
    if (!peb)
        return false;

    peb->BeingDebugged = setToNull ? FALSE : TRUE;
    if (!scl::SetPeb(hProcess.get(), peb.get()))
        return false;

    if (scl::IsWow64Process(hProcess.get()))
    {
        auto peb64 = scl::Wow64GetPeb64(hProcess.get());
        if (!peb64)
            return false;

        peb->BeingDebugged = setToNull ? FALSE : TRUE;
        if (!scl::Wow64SetPeb64(hProcess.get(), peb64.get()))
            return false;
    }

    return true;
}

static bool GetProcessInfo(HANDLE hProcess, PPROCESS_SUSPEND_INFO processInfo)
{
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), nullptr);
    if (!NT_SUCCESS(status))
        return false;
    ULONG size;
    status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return false;
    const PSYSTEM_PROCESS_INFORMATION systemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * size);
    if (systemProcessInfo == nullptr)
        return false;
    status = NtQuerySystemInformation(SystemProcessInformation, systemProcessInfo, 2 * size, nullptr);
    if (!NT_SUCCESS(status))
    {
        RtlFreeHeap(RtlProcessHeap(), 0, systemProcessInfo);
        return false;
    }

    // Count threads
    ULONG numThreads = 0;
    PSYSTEM_PROCESS_INFORMATION entry = systemProcessInfo;

    while (true)
    {
        if (entry->UniqueProcessId == basicInfo.UniqueProcessId)
        {
            numThreads = entry->NumberOfThreads;
            break;
        }
        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)entry + entry->NextEntryOffset);
    }

    if (numThreads == 0)
    {
        RtlFreeHeap(RtlProcessHeap(), 0, systemProcessInfo);
        return false;
    }

    // Fill process info
    processInfo->ProcessId = basicInfo.UniqueProcessId;
    processInfo->ProcessHandle = hProcess;
    processInfo->NumThreads = numThreads;

    // Fill thread IDs
    processInfo->ThreadSuspendInfo = (PTHREAD_SUSPEND_INFO)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, numThreads * sizeof(THREAD_SUSPEND_INFO));
    for (ULONG i = 0; i < numThreads; ++i)
    {
        processInfo->ThreadSuspendInfo[i].ThreadId = entry->Threads[i].ClientId.UniqueThread;
    }

    RtlFreeHeap(RtlProcessHeap(), 0, systemProcessInfo);
    return true;
}

// NtSuspendProcess does not return STATUS_SUSPEND_COUNT_EXCEEDED (or any other error) when one or more thread(s) in the process is/are at the suspend limit.
// This replacement suspends all threads in a process, storing the individual thread suspend statuses. True is returned iff all threads are suspended.
bool SafeSuspendProcess(HANDLE hProcess, PPROCESS_SUSPEND_INFO suspendInfo)
{
    // Get process info
    if (!GetProcessInfo(hProcess, suspendInfo))
        return false;

    for (ULONG i = 0; i < suspendInfo->NumThreads; ++i)
    {
        PTHREAD_SUSPEND_INFO threadSuspendInfo = &suspendInfo->ThreadSuspendInfo[i];
        OBJECT_ATTRIBUTES objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)nullptr, 0);
        CLIENT_ID clientId = { suspendInfo->ProcessId, suspendInfo->ThreadSuspendInfo[i].ThreadId };

        // Open the thread by thread ID
        NTSTATUS status = NtOpenThread(&threadSuspendInfo->ThreadHandle, THREAD_SUSPEND_RESUME, &objectAttributes, &clientId);
        if (!NT_SUCCESS(status))
        {
            RtlFreeHeap(RtlProcessHeap(), 0, suspendInfo->ThreadSuspendInfo);
            return false;
        }

        // Suspend the thread, ignoring (but saving) STATUS_SUSPEND_COUNT_EXCEEDED errors
        threadSuspendInfo->SuspendStatus = NtSuspendThread(threadSuspendInfo->ThreadHandle, nullptr);
        if (!NT_SUCCESS(threadSuspendInfo->SuspendStatus) && threadSuspendInfo->SuspendStatus != STATUS_SUSPEND_COUNT_EXCEEDED)
        {
            RtlFreeHeap(RtlProcessHeap(), 0, suspendInfo->ThreadSuspendInfo);
            return false;
        }
    }

    return true;
}

// Replacement for NtResumeProcess, to be used with info obtained from a prior call to SafeSuspendProcess
bool SafeResumeProcess(PPROCESS_SUSPEND_INFO suspendInfo)
{
    bool success = true;

    for (ULONG i = 0; i < suspendInfo->NumThreads; ++i)
    {
        if (NT_SUCCESS(suspendInfo->ThreadSuspendInfo[i].SuspendStatus) &&
            !NT_SUCCESS(NtResumeThread(suspendInfo->ThreadSuspendInfo[i].ThreadHandle, nullptr)))
            success = false;
        if (!NT_SUCCESS(NtClose(suspendInfo->ThreadSuspendInfo[i].ThreadHandle)))
            success = false;
    }

    RtlFreeHeap(RtlProcessHeap(), 0, suspendInfo->ThreadSuspendInfo);
    return success;
}

bool StartHooking(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hdd->dwProtectedProcessId = GetCurrentProcessId();
    hdd->EnableProtectProcessId = TRUE;

    DWORD peb_flags = 0;
    if (g_settings.opts().fixPebBeingDebugged)
        peb_flags |= PEB_PATCH_BeingDebugged;
    if (g_settings.opts().fixPebHeapFlags)
        peb_flags |= PEB_PATCH_HeapFlags;
    if (g_settings.opts().fixPebNtGlobalFlag)
        peb_flags |= PEB_PATCH_NtGlobalFlag;
    if (g_settings.opts().fixPebStartupInfo)
        peb_flags |= PEB_PATCH_ProcessParameters;
    if (g_settings.opts().fixPebOsBuildNumber)
        peb_flags |= PEB_PATCH_OsBuildNumber;

    ApplyPEBPatch(hProcess, peb_flags);
    if (g_settings.opts().fixPebOsBuildNumber)
        ApplyNtdllVersionPatch(hProcess);

    if (dllMemory == nullptr || imageBase == 0)
        return peb_flags != 0; // Not injecting hook DLL

    return ApplyHook(hdd, hProcess, dllMemory, imageBase);
}

void AddWineFunctionName(HANDLE hProcess)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    BYTE* remote_ntdll = (BYTE*)GetModuleBaseRemote(hProcess, L"ntdll.dll");
    // check input
    if (!remote_ntdll)
        return;

    SIZE_T readed = 0;
    // check module's header
    IMAGE_DOS_HEADER dos_header;
    ReadProcessMemory(hProcess, remote_ntdll, &dos_header, sizeof(IMAGE_DOS_HEADER), &readed);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        return;

    // check NT header
    IMAGE_NT_HEADERS pe_header;
    ReadProcessMemory(hProcess, (BYTE*)remote_ntdll + dos_header.e_lfanew, &pe_header, sizeof(IMAGE_NT_HEADERS), &readed);
    if (pe_header.Signature != IMAGE_NT_SIGNATURE)
        return;

    // get the export directory
    DWORD export_adress = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_adress)
        return;

    DWORD export_size = pe_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    BYTE* new_export_table = (BYTE*)VirtualAllocEx(hProcess, remote_ntdll + 0x1000000, export_size + 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    IMAGE_EXPORT_DIRECTORY export_directory;
    ReadProcessMemory(hProcess, remote_ntdll + export_adress, &export_directory, sizeof(IMAGE_EXPORT_DIRECTORY), &readed);

    BYTE* tmp_table = (BYTE*)malloc(export_size + 0x1000);
    if (tmp_table == nullptr) return;

    //copy functions table
    BYTE* new_functions_table = new_export_table;
    ReadProcessMemory(hProcess, remote_ntdll + export_directory.AddressOfFunctions, tmp_table, export_directory.NumberOfFunctions * sizeof(DWORD), &readed);
    WriteProcessMemory(hProcess, new_functions_table, tmp_table, export_directory.NumberOfFunctions * sizeof(DWORD), &readed);
    g_log.LogInfo(L"[VMPBypass] new_functions_table: %p", new_functions_table);

    //copy ordinal table
    BYTE* new_ordinal_table = new_functions_table + export_directory.NumberOfFunctions * sizeof(DWORD) + 0x100;
    ReadProcessMemory(hProcess, remote_ntdll + export_directory.AddressOfNameOrdinals, tmp_table, export_directory.NumberOfNames * sizeof(WORD), &readed);
    WriteProcessMemory(hProcess, new_ordinal_table, tmp_table, export_directory.NumberOfNames * sizeof(WORD), &readed);
    g_log.LogInfo(L"[VMPBypass] new_ordinal_table: %p", new_ordinal_table);

    //copy name table
    BYTE* new_name_table = new_ordinal_table + export_directory.NumberOfNames * sizeof(WORD) + 0x100;
    ReadProcessMemory(hProcess, remote_ntdll + export_directory.AddressOfNames, tmp_table, export_directory.NumberOfNames * sizeof(DWORD), &readed);
    WriteProcessMemory(hProcess, new_name_table, tmp_table, export_directory.NumberOfNames * sizeof(DWORD), &readed);
    g_log.LogInfo(L"[VMPBypass] new_name_table: %p", new_name_table);

    free(tmp_table);
    tmp_table = nullptr;

    //setup new name & name offset
    BYTE* wine_func_addr = new_name_table + export_directory.NumberOfNames * sizeof(DWORD) + 0x100;
    WriteProcessMemory(hProcess, wine_func_addr, "wine_get_version\x00", 17, &readed);
    DWORD wine_func_offset = (DWORD)(wine_func_addr - remote_ntdll);
    WriteProcessMemory(hProcess, new_name_table + export_directory.NumberOfNames * sizeof(DWORD), &wine_func_offset, 4, &readed);

    //set fake ordinal
    WORD last_ordinal = export_directory.NumberOfNames;
    WriteProcessMemory(hProcess, new_ordinal_table + export_directory.NumberOfNames * sizeof(WORD), &last_ordinal, 2, &readed);

    //set fake function offset
    BYTE* query_information_process = reinterpret_cast<BYTE*>(GetProcAddress(hNtdll, "NtCurrentProcess"));
    DWORD function_offset = (DWORD)(query_information_process - remote_ntdll);
    WriteProcessMemory(hProcess, new_functions_table + export_directory.NumberOfFunctions * sizeof(DWORD), &function_offset, 4, &readed);

    //setup new directory
    export_directory.NumberOfNames++;
    export_directory.NumberOfFunctions++;

    DWORD name_table_offset = (DWORD)(new_name_table - remote_ntdll);
    export_directory.AddressOfNames = name_table_offset;

    DWORD function_talble_offset = (DWORD)(new_functions_table - remote_ntdll);
    export_directory.AddressOfFunctions = function_talble_offset;

    DWORD ordinal_table_offset = (DWORD)(new_ordinal_table - remote_ntdll);
    export_directory.AddressOfNameOrdinals = ordinal_table_offset;

    //// change the offset of header data
    DWORD old_prot;
    VirtualProtectEx(hProcess, remote_ntdll + export_adress, sizeof(IMAGE_EXPORT_DIRECTORY), PAGE_EXECUTE_READWRITE, &old_prot);
    WriteProcessMemory(hProcess, remote_ntdll + export_adress, &export_directory, sizeof(IMAGE_EXPORT_DIRECTORY), &readed);
    VirtualProtectEx(hProcess, remote_ntdll + export_adress, sizeof(IMAGE_EXPORT_DIRECTORY), old_prot, &old_prot);

    g_log.LogInfo(L"[VMPBypass] wine_get_version fake export added to remote ntdll");
}

void startInjectionProcess(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, bool newProcess)
{
    PROCESS_SUSPEND_INFO suspendInfo;
    if (!SafeSuspendProcess(hProcess, &suspendInfo))
        return;

    const bool injectDll = g_settings.hook_dll_needed() || hdd->isNtdllHooked || hdd->isKernel32Hooked || hdd->isUserDllHooked;

    DWORD hookDllDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "HookDllData");

    if (!newProcess)
    {
        //g_log.Log(L"Apply hooks again");
        if (injectDll && StartHooking(hProcess, hdd, dllMemory, (DWORD_PTR)remoteImageBase))
        {
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), hdd, sizeof(HOOK_DLL_DATA), 0);
        }
        else if (!injectDll)
        {
            StartHooking(hProcess, hdd, nullptr, 0);
        }
    }
    else
    {
        if (g_settings.opts().removeDebugPrivileges)
        {
            RemoveDebugPrivileges(hProcess);
        }

        RestoreHooks(hdd, hProcess);

        AddWineFunctionName(hProcess);

        if (injectDll)
        {
            remoteImageBase = MapModuleToProcess(hProcess, dllMemory, true);
            if (remoteImageBase)
            {
                FillHookDllData(hProcess, hdd);

                if (StartHooking(hProcess, hdd, dllMemory, (DWORD_PTR)remoteImageBase) &&
                    WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), hdd, sizeof(HOOK_DLL_DATA), 0))
                {
                    g_log.LogInfo(L"Hook injection successful, image base %p", remoteImageBase);
                }
                else
                {
                    g_log.LogError(L"Failed to write hook dll data");
                }
            }
            else
            {
                g_log.LogError(L"Failed to map image!");
            }
        }
        else
        {
            if (StartHooking(hProcess, hdd, nullptr, 0))
                g_log.LogInfo(L"PEB patch successful, hook injection not needed\n");
        }
    }

    SafeResumeProcess(&suspendInfo);
}

void startInjection(DWORD targetPid, HOOK_DLL_DATA *hdd, const WCHAR * dllPath, bool newProcess)
{
    HANDLE hProcess = OpenProcess( PROCESS_SUSPEND_RESUME | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
        0, targetPid);
    if (hProcess)
    {
        BYTE * dllMemory = ReadFileToMemory(dllPath);
        if (dllMemory)
        {
            startInjectionProcess(hProcess, hdd, dllMemory, newProcess);
            free(dllMemory);
        }
        else
        {
            g_log.LogError(L"Cannot find %s", dllPath);
            MessageBoxW(nullptr, L"Failed to load ScyllaHide hook library DLL! Make sure it is installed correctly and has not been deleted by an anti-virus.", L"Error", MB_ICONERROR);
        }
        CloseHandle(hProcess);
    }
    else
    {
        g_log.LogError(L"Cannot open process handle %d", targetPid);
    }
}

NTSTATUS CreateAndWaitForThread(HANDLE hProcess, LPTHREAD_START_ROUTINE threadStart, PVOID parameter, PHANDLE threadHandle, BOOLEAN suppressDllMains)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    const t_NtCreateThreadEx fpNtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
    if (fpNtCreateThreadEx == nullptr)
    {
        // We are on XP/2003 - use CreateRemoteThread
        *threadHandle = CreateRemoteThread(hProcess, nullptr, 0, threadStart, parameter, CREATE_SUSPENDED, nullptr);
        if (*threadHandle != nullptr)
        {
            NtSetInformationThread(*threadHandle, ThreadHideFromDebugger, 0, 0);
            status = STATUS_SUCCESS;
        }
    }
    else
    {
        // Create sneaky thread
        status = fpNtCreateThreadEx(threadHandle,
                                    THREAD_ALL_ACCESS,
                                    nullptr,
                                    hProcess,
                                    (PUSER_THREAD_START_ROUTINE)threadStart,
                                    parameter,
                                    THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | (suppressDllMains ? THREAD_CREATE_FLAGS_SUPPRESS_DLLMAINS : 0),
                                    0,
                                    0,
                                    0,
                                    nullptr);
    }

    if (NT_SUCCESS(status))
    {
        // Wait for thread to exit
        SetThreadPriority(*threadHandle, THREAD_PRIORITY_TIME_CRITICAL);
        ResumeThread(*threadHandle);
        WaitForSingleObject(*threadHandle, INFINITE);
    }
    return status;
}

LPVOID NormalDllInjection(HANDLE hProcess, const WCHAR * dllPath)
{
    SIZE_T memorySize = (wcslen(dllPath) + 1) * sizeof(WCHAR);

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, memorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    LPVOID hModule = nullptr;

    if (!remoteMemory)
    {
        g_log.LogError(L"DLL INJECTION: VirtualAllocEx failed!");
        return 0;
    }

    if (WriteProcessMemory(hProcess, remoteMemory, dllPath, memorySize, 0))
    {
        HANDLE hThread;
        NTSTATUS status = CreateAndWaitForThread(hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryW, remoteMemory, &hThread, FALSE);
        if (NT_SUCCESS(status))
        {
            GetExitCodeThread(hThread, (LPDWORD)&hModule);

            if (!hModule)
            {
                g_log.LogError(L"DLL INJECTION: Failed load library!");
            }

            CloseHandle(hThread);
        }
        else
        {
            g_log.LogError(L"DLL INJECTION: Failed to start thread: 0x%08X!", status);
        }
    }
    else
    {
        g_log.LogError(L"DLL INJECTION: Failed WriteProcessMemory!");
    }

    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

    return hModule;
}

DWORD GetAddressOfEntryPoint(BYTE * dllMemory)
{
    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(dllMemory);
    return HEADER_FIELD(ntHeaders, AddressOfEntryPoint);
}

LPVOID StealthDllInjection(HANDLE hProcess, const WCHAR * dllPath, BYTE * dllMemory)
{
    LPVOID remoteImageBaseOfInjectedDll = 0;

    if (dllMemory)
    {
        remoteImageBaseOfInjectedDll = MapModuleToProcess(hProcess, dllMemory, false);
        if (remoteImageBaseOfInjectedDll)
        {

            DWORD_PTR entryPoint = (DWORD_PTR)GetAddressOfEntryPoint(dllMemory);

            if (entryPoint)
            {
                DWORD_PTR dllMain = entryPoint + (DWORD_PTR)remoteImageBaseOfInjectedDll;

                g_log.LogInfo(L"DLL INJECTION: Starting thread at RVA %p VA %p!", entryPoint, dllMain);

                HANDLE hThread;
                NTSTATUS status = CreateAndWaitForThread(hProcess, (LPTHREAD_START_ROUTINE)dllMain, remoteImageBaseOfInjectedDll, &hThread, TRUE);
                if (NT_SUCCESS(status))
                {
                    CloseHandle(hThread);
                }
                else
                {
                    g_log.LogError(L"DLL INJECTION: Failed to start thread: 0x%08X!", status);
                }
            }
        }
        else
        {
            g_log.LogError(L"DLL INJECTION: Failed to map image of %s!", dllPath);
        }
    }

    return remoteImageBaseOfInjectedDll;
}

void injectDll(DWORD targetPid, const WCHAR * dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    if (hProcess == nullptr)
    {
        g_log.LogError(L"DLL INJECTION: Cannot open process handle %d", targetPid);
        return;
    }

    BYTE* dllMemory = ReadFileToMemory(dllPath);
    if (dllMemory == nullptr)
    {
        g_log.LogError(L"DLL INJECTION: Failed to read file %s!", dllPath);
        CloseHandle(hProcess);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(dllMemory);
    if (ntHeaders == nullptr)
    {
        g_log.LogError(L"DLL INJECTION: Invalid PE file %s!", dllPath);
        free(dllMemory);
        CloseHandle(hProcess);
        return;
    }

    bool processIsWow64 = scl::IsWow64Process(hProcess);
    if ((scl::IsWindows64() &&
        ((processIsWow64 && ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) ||
        (!processIsWow64 && ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)))
        ||
        (!scl::IsWindows64() && ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386))
    {
        g_log.LogError(L"DLL INJECTION: DLL %s is of wrong bitness for process!", dllPath);
        free(dllMemory);
        CloseHandle(hProcess);
        return;
    }

    LPVOID remoteImage = nullptr;
    DWORD entryPoint = GetAddressOfEntryPoint(dllMemory);
    if (entryPoint != 0)
        g_log.LogInfo(L"DLL entry point (DllMain) RVA %X!", entryPoint);

    if (g_settings.opts().dllStealth)
    {
        g_log.LogInfo(L"Starting Stealth DLL Injection!");
        remoteImage = StealthDllInjection(hProcess, dllPath, dllMemory);
    }
    else if (g_settings.opts().dllNormal)
    {
        g_log.LogInfo(L"Starting Normal DLL Injection!");
        remoteImage = NormalDllInjection(hProcess, dllPath);
    }
    else
    {
        g_log.LogError(L"DLL INJECTION: No injection type selected!");
    }

    if (remoteImage != nullptr)
    {
        g_log.LogInfo(L"DLL INJECTION: Injection of %s successful, Imagebase %p", dllPath, remoteImage);

        if (g_settings.opts().dllUnload)
        {
            g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p", remoteImage);

            if (g_settings.opts().dllNormal)
            {
                HANDLE hThread;
                NTSTATUS status = CreateAndWaitForThread(hProcess, (LPTHREAD_START_ROUTINE)FreeLibrary, remoteImage, &hThread, FALSE);
                if (NT_SUCCESS(status))
                {
                    CloseHandle(hThread);
                    g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p successful", remoteImage);
                }
                else
                {
                    g_log.LogError(L"DLL INJECTION: Unloading Imagebase %p FAILED: 0x%08X", remoteImage, status);
                }
            }
            else if (g_settings.opts().dllStealth)
            {
                VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
                g_log.LogInfo(L"DLL INJECTION: Unloading Imagebase %p successful", remoteImage);
            }
        }
    }

    free(dllMemory);
    CloseHandle(hProcess);
}

BYTE * ReadFileToMemory(const WCHAR * targetFilePath)
{
    HANDLE hFile;
    DWORD dwBytesRead;
    DWORD FileSize;
    BYTE* FilePtr = 0;

    hFile = CreateFileW(targetFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        FileSize = GetFileSize(hFile, NULL);
        if (FileSize > 0)
        {
            FilePtr = (BYTE*)calloc(FileSize + 1, 1);
            if (FilePtr)
            {
                if (!ReadFile(hFile, (LPVOID)FilePtr, FileSize, &dwBytesRead, NULL))
                {
                    free(FilePtr);
                    FilePtr = 0;
                }

            }
        }
        CloseHandle(hFile);
    }

    return FilePtr;
}

void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA *hdd)
{
    hdd->EnablePebBeingDebugged = g_settings.opts().fixPebBeingDebugged;
    hdd->EnablePebHeapFlags = g_settings.opts().fixPebHeapFlags;
    hdd->EnablePebNtGlobalFlag = g_settings.opts().fixPebNtGlobalFlag;
    hdd->EnablePebStartupInfo = g_settings.opts().fixPebStartupInfo;
    hdd->EnablePebOsBuildNumber = g_settings.opts().fixPebOsBuildNumber;
    hdd->EnableOutputDebugStringHook = g_settings.opts().hookOutputDebugStringA;
    hdd->EnableNtSetInformationThreadHook = g_settings.opts().hookNtSetInformationThread;
    hdd->EnableNtQueryInformationProcessHook = g_settings.opts().hookNtQueryInformationProcess;
    hdd->EnableNtQuerySystemInformationHook = g_settings.opts().hookNtQuerySystemInformation;
    hdd->EnableNtQueryObjectHook = g_settings.opts().hookNtQueryObject;
    hdd->EnableNtYieldExecutionHook = g_settings.opts().hookNtYieldExecution;
    hdd->EnableNtCloseHook = g_settings.opts().hookNtClose;
    hdd->EnableNtCreateThreadExHook = g_settings.opts().hookNtCreateThreadEx;
    hdd->EnablePreventThreadCreation = g_settings.opts().preventThreadCreation;
    hdd->EnableNtUserBlockInputHook = g_settings.opts().hookNtUserBlockInput;
    hdd->EnableNtUserFindWindowExHook = g_settings.opts().hookNtUserFindWindowEx;
    hdd->EnableNtUserBuildHwndListHook = g_settings.opts().hookNtUserBuildHwndList;
    hdd->EnableNtUserQueryWindowHook = g_settings.opts().hookNtUserQueryWindow;
    hdd->EnableNtUserGetForegroundWindowHook = g_settings.opts().hookNtUserGetForegroundWindow;
    hdd->EnableNtSetDebugFilterStateHook = g_settings.opts().hookNtSetDebugFilterState;
    hdd->EnableGetTickCountHook = g_settings.opts().hookGetTickCount;
    hdd->EnableGetTickCount64Hook = g_settings.opts().hookGetTickCount64;
    hdd->EnableGetLocalTimeHook = g_settings.opts().hookGetLocalTime;
    hdd->EnableGetSystemTimeHook = g_settings.opts().hookGetSystemTime;
    hdd->EnableNtQuerySystemTimeHook = g_settings.opts().hookNtQuerySystemTime;
    hdd->EnableNtQueryPerformanceCounterHook = g_settings.opts().hookNtQueryPerformanceCounter;
    hdd->EnableNtSetInformationProcessHook = g_settings.opts().hookNtSetInformationProcess;

    hdd->EnableNtGetContextThreadHook = g_settings.opts().hookNtGetContextThread;
    hdd->EnableNtSetContextThreadHook = g_settings.opts().hookNtSetContextThread;
    hdd->EnableNtContinueHook = g_settings.opts().hookNtContinue | g_settings.opts().killAntiAttach;
    hdd->EnableKiUserExceptionDispatcherHook = g_settings.opts().hookKiUserExceptionDispatcher;
    hdd->EnableMalwareRunPeUnpacker = g_settings.opts().malwareRunpeUnpacker;

    hdd->isKernel32Hooked = FALSE;
    hdd->isNtdllHooked = FALSE;
    hdd->isUserDllHooked = FALSE;
}

bool RemoveDebugPrivileges(HANDLE hProcess)
{
    TOKEN_PRIVILEGES Debug_Privileges;

    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
    {
        HANDLE hToken = 0;
        if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            Debug_Privileges.Privileges[0].Attributes = 0;
            Debug_Privileges.PrivilegeCount = 1;

            AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL);
            CloseHandle(hToken);
            return true;
        }
    }

    return false;
}

#define DbgBreakPoint_FUNC_SIZE 0x10
#define DbgUiRemoteBreakin_FUNC_SIZE 0x80
#define NtContinue_FUNC_SIZE 0x40

typedef struct _PATCH_FUNC {
    PCHAR funcName;
    PVOID funcAddr;
    SIZE_T funcSize;
} PATCH_FUNC;


PATCH_FUNC patchFunctions[] = {
    {
        "DbgBreakPoint", 0, DbgBreakPoint_FUNC_SIZE
    },
    {
        "DbgUiRemoteBreakin", 0, DbgUiRemoteBreakin_FUNC_SIZE
    },
    {
        "NtContinue", 0, NtContinue_FUNC_SIZE
    }
};

bool ApplyAntiAntiAttach(DWORD targetPid)
{
    bool result = false;
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);

    if (!hProcess)
        return result;

    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");

    for (ULONG i = 0; i < _countof(patchFunctions); i++)
    {
        patchFunctions[i].funcAddr = (PVOID)GetProcAddress(hMod, patchFunctions[i].funcName);
    }

    for (ULONG i = 0; i < _countof(patchFunctions); i++)
    {
        ULONG oldProtection;
        if (VirtualProtectEx(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, PAGE_EXECUTE_READWRITE, &oldProtection) &&
            WriteProcessMemory(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, nullptr))
        {
            VirtualProtectEx(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, oldProtection, &oldProtection);
            result = true;
        }
        else
        {
            result = false;
            break;
        }
    }

    CloseHandle(hProcess);

    return result;
}
