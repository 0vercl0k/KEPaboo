// Axel '0vercl0k' Souchet - January 18 2023
#if defined(_WIN64)
#error "Only in 32b"
#endif

#include "mem.h"
#include "pe.h"
#include "reg.h"
#include "utils.h"
#include <array>
#include <fmt/printf.h>
#include <memory>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <windows.h>

namespace fs = std::filesystem;

struct Options_t {
  std::optional<std::string> ServiceName;
  std::optional<std::string> LaunchService;
};

const uintptr_t NtQueryInformationProcessMagic = 0xdeadbeef;
const uintptr_t NtSetInformationThreadMagic = 0xbaadc0de;
const uint32_t STATUS_SUCCESS = 0;
#define StubsSectionName ".stubs"
#pragma code_seg(push, StubsSectionName)

//
// When compile in DEBUG mode, a few options broke the hooking code
//   - Incremental linking introduced a thunk that jumps to the real function
//   which made my calculation of where the function is wrong.
//   - /RTCs (Run-time error checks) added instrumentation to check the stack by
//   inserting calls to a function; same for /JMC (JustMyCode debugging). The
//   function targets aren't copied in the remote process so it failed.
//

uint32_t NTAPI NtQueryInformationProcessHooked(HANDLE ProcessHandle,
                                               DWORD ProcessInformationClass,
                                               PVOID ProcessInformation,
                                               ULONG ProcessInformationLength,
                                               PULONG ReturnLength) {
  const DWORD ProcessDebugPort = 0x7;
  const DWORD ProcessDebugObjectHandle = 0x1e;
  if ((ProcessInformationClass == ProcessDebugPort ||
       ProcessInformationClass == ProcessDebugObjectHandle) &&
      ProcessInformationLength == sizeof(uint32_t)) {
    *(uint32_t *)ProcessInformation = 0;
    if (ReturnLength) {
      *ReturnLength = sizeof(uint32_t);
    }
    return STATUS_SUCCESS;
  }

  const DWORD ProcessDebugFlags = 0x1f;
  if (ProcessInformationClass == ProcessDebugFlags &&
      ProcessInformationLength == sizeof(uint32_t)) {
    *(uint32_t *)ProcessInformation = 0xff'ff'ff'ff;
    if (ReturnLength) {
      *ReturnLength = sizeof(uint32_t);
    }
    return STATUS_SUCCESS;
  }

  using NtQueryInformationProcess_t =
      decltype(&NtQueryInformationProcessHooked);

  return NtQueryInformationProcess_t(NtQueryInformationProcessMagic)(
      ProcessHandle, ProcessInformationClass, ProcessInformation,
      ProcessInformationLength, ReturnLength);
}

uint32_t NTAPI NtSetInformationThreadHooked(HANDLE ThreadHandle,
                                            DWORD ThreadInformationClass,
                                            PVOID ThreadInformation,
                                            ULONG ThreadInformationLength) {
  using NtSetInformationThread_t = decltype(&NtSetInformationThreadHooked);
  const DWORD ThreadHideFromDebugger = 0x11;
  if (ThreadInformationClass == ThreadHideFromDebugger) {
    return STATUS_SUCCESS;
  }

  return NtSetInformationThread_t(NtSetInformationThreadMagic)(
      ThreadHandle, ThreadInformationClass, ThreadInformation,
      ThreadInformationLength);
}
#pragma code_seg(pop)

struct RemoteStubInfo_t {
  uintptr_t Address = 0;
  size_t Size = 0;
};

std::optional<RemoteStubInfo_t> HookApis(const HANDLE Process) {
  //
  // Load NTDLL in the current process, the address will be the same in the
  // other process.
  //

  HMODULE Ntdll = LoadLibraryA("ntdll.dll");
  if (!Ntdll) {
    Print("LoadLibraryA ntdll failed, bailing\n");
    return {};
  }

  const auto &CleanNtdll = finally([&] { FreeLibrary(Ntdll); });

  //
  // Walk the EAT of NTDLL and look for NtQueryInformationProcess /
  // NtSetInformationThread's thunks.
  //

  uintptr_t NtQueryInformationProcessThunkAddress = 0;
  uintptr_t NtSetInformationThreadThunkAddress = 0;
  if (!pe::WalkEat32(uintptr_t(Ntdll), [&](const char *Name,
                                           const uintptr_t Address) {
        if (strcmp(Name, "NtQueryInformationProcess") == 0) {
          NtQueryInformationProcessThunkAddress = Address;
        } else if (strcmp(Name, "NtSetInformationThread") == 0) {
          NtSetInformationThreadThunkAddress = Address;
        }

        const bool Continue = (NtQueryInformationProcessThunkAddress == 0) ||
                              (NtSetInformationThreadThunkAddress == 0);
        return Continue;
      })) {
    Print("Failed to walk ntdll's EAT, bailing\n");
    return {};
  }

  //
  // If we haven't found both thunks, then something is wrong.
  //

  if (!NtSetInformationThreadThunkAddress ||
      !NtQueryInformationProcessThunkAddress) {
    Print("Failed to find the thunk of NtSetInformationThread / "
          "NtQueryInformationProcess, bailing\n");
    return {};
  }

  Print("NtSetInformationThread's EAT thunk is at {:x}\n",
        NtSetInformationThreadThunkAddress);
  Print("NtQueryInformationProcess's EAT thunk is at {:x}\n",
        NtQueryInformationProcessThunkAddress);

  //
  // Find the PE section in which we put the hooked functions.
  //

  const auto MyBaseAddress = uintptr_t(GetModuleHandleA(nullptr));
  const auto &StubsSection =
      pe::GetSectionHeader32(MyBaseAddress, StubsSectionName);
  if (!StubsSection) {
    Print("Failed to find '" StubsSectionName "' section, bailing\n");
    return {};
  }

  //
  // Allocate enough virtual memory in the remote process to be able to copy the
  // hooks there.
  //

  const auto StubsAddress = MyBaseAddress + StubsSection->VirtualAddress;
  RemoteStubInfo_t RemoteStubInfo = {};
  RemoteStubInfo.Size = StubsSection->Misc.VirtualSize;
  Print("Found {} section at {:x}, {}b\n", StubsSectionName, StubsAddress,
        RemoteStubInfo.Size);

  RemoteStubInfo.Address =
      uintptr_t(VirtualAllocEx(Process, nullptr, RemoteStubInfo.Size,
                               MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

  if (!RemoteStubInfo.Address) {
    Print("VirtualAllocEx +rw failed w/ GLE={}, bailing\n", GetLastError());
    return {};
  }

  auto FreeRemoteStub = finally([&] {
    VirtualFreeEx(Process, PVOID(RemoteStubInfo.Address), 0, MEM_RELEASE);
  });

  //
  // Copy the section's content over.
  //

  Print("Allocated {} bytes of memory in the remote process at {:x}..\n",
        RemoteStubInfo.Size, RemoteStubInfo.Address);

  if (!mem::VirtWrite(RemoteStubInfo.Address, PVOID(StubsAddress),
                      RemoteStubInfo.Size, Process)) {
    Print("VirtWrite failed, bailing\n", GetLastError());
    return {};
  }

  //
  // Scan the section of code to look for magics that need to be patched by the
  // API addresses. We distinguish which is which because the hooks used
  // different magics.
  //

  bool FixedNtQueryInformationProcess = false;
  bool FixedNtSetInformationThread = false;
  for (size_t Idx = 0; (Idx + sizeof(uint32_t)) <= RemoteStubInfo.Size; Idx++) {
    const auto PointerAddress = RemoteStubInfo.Address + Idx;
    const auto Pointer = mem::VirtReadPointer(PointerAddress, Process);
    if (Pointer == NtQueryInformationProcessMagic) {
      Print("Fixing NtQueryInformationProcess's stub ({:x})..\n",
            PointerAddress);
      const auto NtQueryInformationProcess =
          uintptr_t(GetProcAddress(Ntdll, "NtQueryInformationProcess"));
      FixedNtQueryInformationProcess =
          mem::VirtWrite(PointerAddress, NtQueryInformationProcess, Process);
    }

    if (Pointer == NtSetInformationThreadMagic) {
      Print("Fixing NtSetInformationThread's stub ({:x})..\n", PointerAddress);
      const auto NtSetInformationThread =
          uintptr_t(GetProcAddress(Ntdll, "NtSetInformationThread"));
      FixedNtSetInformationThread =
          mem::VirtWrite(PointerAddress, NtSetInformationThread, Process);
    }

    if (FixedNtSetInformationThread && FixedNtQueryInformationProcess) {
      break;
    }
  }

  //
  // If we haven't patched both of the functions, we're in trouble.
  //

  if (!FixedNtQueryInformationProcess || !FixedNtSetInformationThread) {
    Print("Failed to fix up the stubs, bailing\n", GetLastError());
    return {};
  }

  //
  // We are done doing memory writes in that region, so turn the region
  // executable.
  //

  Print("Turning the memory executable..\n");
  DWORD OldProtect = 0;
  if (!VirtualProtectEx(Process, PVOID(RemoteStubInfo.Address),
                        RemoteStubInfo.Size, PAGE_EXECUTE_READ, &OldProtect)) {
    Print("VirtualProtectEx +rx failed w/ GLE={}, bailing\n", GetLastError());
    return {};
  }

  //
  // It's time to patch both thunks, and have them point to our hooked
  // functions.
  //

  const auto NtQueryInformationProcessHookedRva =
      RemoteStubInfo.Address +
      utils::PageOffset(uintptr_t(NtQueryInformationProcessHooked)) -
      uintptr_t(Ntdll);
  Print("Patching the NtQueryInformationProcess EAT thunk w/ {:x}..\n",
        NtQueryInformationProcessHookedRva);
  if (!mem::VirtWrite(NtQueryInformationProcessThunkAddress,
                      NtQueryInformationProcessHookedRva, Process)) {
    Print("Patching NtQueryInformationProcess EAT thunk failed, bailing\n");
    return {};
  }

  //
  // Technically at this point, we patched up a thunk so it might be better to
  // not unmap the section.
  //

  FreeRemoteStub.Canceled = true;

  const auto NtSetInformationThreadHookedRva =
      RemoteStubInfo.Address +
      utils::PageOffset(uintptr_t(NtSetInformationThreadHooked)) -
      uintptr_t(Ntdll);
  Print("Patching the NtSetInformationThread EAT thunk w/ {:x}..\n",
        NtSetInformationThreadHookedRva);
  if (!mem::VirtWrite(NtSetInformationThreadThunkAddress,
                      NtSetInformationThreadHookedRva, Process)) {
    Print("Patching NtSetInformationThread EAT thunk failed, bailing\n");
    return {};
  }

  //
  // Woot, we made it!
  //

  return RemoteStubInfo;
}

bool FixInt2D(const PROCESS_INFORMATION &Pi) {
  Print("Waiting for INT 2D exception..\n");
  const auto &CleanDetach =
      finally([&] { DebugActiveProcessStop(Pi.dwProcessId); });
  std::unordered_map<DWORD, HANDLE> Threads;
  DEBUG_EVENT DebugEvent;
  const HANDLE Process = Pi.hProcess;
  while (1) {

    //
    // Listen for a debug event..
    //

    if (!WaitForDebugEvent(&DebugEvent, INFINITE)) {
      Print("WaitForDebugEvent failed w/ GLE={}\n", GetLastError());
      return false;
    }

    //
    // We don't handle every type of events but only care about a few.
    //

    bool Done = false;
    switch (DebugEvent.dwDebugEventCode) {
    case EXIT_PROCESS_DEBUG_EVENT: {
      Print("Process exited, bailing..\n");
      return false;
    }

    case CREATE_PROCESS_DEBUG_EVENT: {
      Print("Received CREATE_PROCESS_DEBUG_EVENT..\n");
      Threads.emplace(DebugEvent.dwThreadId,
                      DebugEvent.u.CreateProcessInfo.hThread);
      break;
    }

    case EXIT_THREAD_DEBUG_EVENT: {
      Print("Received EXIT_THREAD_DEBUG_EVENT..\n");
      Threads.erase(DebugEvent.dwThreadId);
      break;
    }

    case CREATE_THREAD_DEBUG_EVENT: {
      Print("Received CREATE_THREAD_DEBUG_EVENT..\n");
      Threads.emplace(DebugEvent.dwThreadId, DebugEvent.u.CreateThread.hThread);
      break;
    }

    case EXCEPTION_DEBUG_EVENT: {

      //
      // Ignore the initial breakpoint.
      //

      Print("Received EXCEPTION_DEBUG_EVENT..\n");
      static bool SeenInitialBreakpoint = false;
      if (!SeenInitialBreakpoint) {
        SeenInitialBreakpoint = true;
        break;
      }

      //
      // Get the thread context; we will need to patch EIP later.
      //

      const auto &Thread = Threads.at(DebugEvent.dwThreadId);
      CONTEXT Context = {};
      Context.ContextFlags = CONTEXT_CONTROL;
      if (!GetThreadContext(Thread, &Context)) {
        Print("Failed to get thread context w/ GLE={}, bailing\n",
              GetLastError());
        return false;
      }

      //
      // Get the image base address of libserver.dll.
      //

      const auto &LibServerBase =
          utils::GetModuleAddress(DebugEvent.dwProcessId, "libserver.dll");
      if (!LibServerBase) {
        Print("Failed to find the base of libserver.dll, bailing\n");
        return false;
      }

      Print("libserver.dll is @ {:x}\n", *LibServerBase);

      //
      // Parse libserver.dll's load config table to find the address of the
      // security cookie.
      //

      const auto &SecurityCookieAddr =
          pe::GetSecurityCookieAddress32(*LibServerBase, Process);
      if (!SecurityCookieAddr) {
        Print("Failed to get security cookie address, bailing\n");
        return false;
      }

      Print("SecurityCookie is @ {:x}\n", *SecurityCookieAddr);

      //
      // Read the value of the cookie; it will be used to decode the scope
      // table's address.
      //

      const auto &SecurityCookie =
          mem::VirtReadPointer(*SecurityCookieAddr, Process);
      if (!SecurityCookie) {
        Print("Failed to read the security cookie, bailing\n");
        return false;
      }

      Print("SecurityCookie is {:x}\n", *SecurityCookie);

      //
      // Verify that right before EIP, there is the INT 2D instruction.
      // clang-format off
      //   kd> !idt
      //   Dumping IDT: fffff8054fb5b000
      //   2d:	fffff8054ce72200 nt!KiDebugServiceTrap
      // clang-format on
      //
      //  Traps — A trap is an exception that is reported immediately following
      //  the execution of the trapping instruction. Traps allow execution of a
      //  program or task to be continued without loss of program continuity.
      //  The return address for the trap handler points to the instruction to
      //  be executed after the trapping instruction.
      //

      const std::array<uint8_t, 2> ExpectedInt2D = {0xcd, 0x2d};
      std::array<uint8_t, 2> Int2D = {};

      //
      // CD 2D | int 2dh
      // 33 C0 | xor eax, eax
      //

      Context.Eip -= sizeof(ExpectedInt2D) + 1;
      if (!mem::VirtRead(Context.Eip, Int2D, Process)) {
        Print("Failed to read the INT 2D instruction, bailing\n");
        return false;
      }

      if (Int2D != ExpectedInt2D) {
        Print("Expected INT 2D to generate an exception ({:x} {:x} @ {:x}), "
              "bailing\n",
              Int2D[0], Int2D[1], Context.Eip);
        return false;
      }

      Print("Received exception @ {:x} coming from INT 2D\n", Context.Eip);

      //
      // Get the TEB address.
      //

      const auto &TebAddress = utils::GetTebAddress(Thread);
      if (!TebAddress) {
        Print("Failed getting TEB, bailing\n");
        return false;
      }

      Print("TEB of the offending thread is @ {:x}\n", *TebAddress);

      //
      // Define a few structures used for parsing the SEH scope table. The scope
      // table holds the address of the code that handles the exception.
      //

      struct EH3_SCOPE_TABLE {
        uint32_t GSCookieOffset;
        uint32_t GSCookieXOROffset;
        uint32_t EHCookieOffset;
        uint32_t EHCookieXOROffset;
        struct {
          uint32_t EnclosingLevel;
          uintptr_t FilterFunc;
          uintptr_t HandlerFunc;
        } ScopeRecord;
      };

      static_assert(sizeof(EH3_SCOPE_TABLE) == 0x1c);

      struct EH3_EXCEPTION_REGISTRATION {
        uintptr_t Next;
        uintptr_t ExceptionHandler;
        uintptr_t ScopeTable;
        uint32_t TryLevel;
      };

      static_assert(sizeof(EH3_EXCEPTION_REGISTRATION) == 0x10);

      //
      // The first field in the TEB is a pointer to the exception handler list,
      // read it.
      //   0:000> dt ntdll!_TEB
      //      +0x000 NtTib            : _NT_TIB
      //   0:000> dt _NT_TIB
      //   ntdll!_NT_TIB
      //      +0x000 ExceptionList    : Ptr64 _EXCEPTION_REGISTRATION_RECORD
      //

      uintptr_t ExceptionListAddress = 0;
      if (!mem::VirtRead(*TebAddress, ExceptionListAddress, Process)) {
        Print("Failed to read the ExceptionList address, bailing\n");
        return EXIT_FAILURE;
      }

      //
      // Read the exception registration; we're interested in the scope table.
      //

      EH3_EXCEPTION_REGISTRATION Registration = {};
      if (!mem::VirtRead(ExceptionListAddress, Registration, Process)) {
        Print("Failed to read the top SEH, bailing\n");
        return EXIT_FAILURE;
      }

      //
      // The scope table pointer is encoded with the security cookie, so decode
      // it.
      //

      Registration.ScopeTable ^= *SecurityCookie;
      Print("ScopeTable is @ {:x}\n", Registration.ScopeTable);

      //
      // Finally, read the scope table.
      //

      EH3_SCOPE_TABLE ScopeTable = {};
      if (!mem::VirtRead(Registration.ScopeTable, ScopeTable, Process)) {
        Print("Failed to read the ScopeTable, bailing\n");
        return EXIT_FAILURE;
      }

      //
      // Ensure that the handler's address is after EIP.
      //

      const auto &HandlerFunc = ScopeTable.ScopeRecord.HandlerFunc;
      if (HandlerFunc <= Context.Eip) {
        Print("The handler function ({:x}) is expected to be placed after EIP "
              "({:x}), bailing\n",
              HandlerFunc, Context.Eip);
        return EXIT_FAILURE;
      }

      //
      // Calculate the offset between the INT 2D instruction, and the handler's
      // address. We are using a JMP REL8 for patching, so just making sure the
      // offset fits into int8_t.
      //

      const auto Offset = uint8_t(HandlerFunc - Context.Eip);
      if (Offset > 127) {
        Print("Offset for the JMP REL8 is too large, bailing\n");
        return EXIT_FAILURE;
      }

      //
      // Time to patch the instruction with a JMP REL8 that unconditionally
      // jumps to the handler.
      //

      Print("Patching INT 2D w/ a JMP REL8 @ {:x}..\n", Context.Eip);
      const uint8_t Branch[2] = {0xEB, Offset - sizeof(Branch)};
      if (!mem::VirtWrite(Context.Eip, Branch, Process)) {
        Print("Failed to write the JMP REL8, bailing\n");
        return EXIT_FAILURE;
      }

      //
      // Let's rewind EIP back to the JMP REL8, and let it go.
      //

      if (!SetThreadContext(Thread, &Context)) {
        Print("Failed to set thread context w/ GLE={}, bailing\n",
              GetLastError());
        return EXIT_FAILURE;
      }

      //
      // We are done, let's break out of the main loop.
      //

      Done = true;
      break;
    }

    default: {
      break;
    }
    }

    //
    // If we are done, break out of the main loop.
    //

    if (Done) {
      break;
    }

    //
    // Continue to receive debug event.
    //

    if (!ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId,
                            DBG_CONTINUE)) {
      Print("ContinueDebugEvent failed w/ GLE={}\n", GetLastError());
      return false;
    }
  }

  //
  // Boom, we did it!
  //

  return true;
}

void WaitForDebugger() {
  while (1) {
    if (IsDebuggerPresent()) {
      __debugbreak();
      return;
    }

    Sleep(1'000);
  }
}

int main(int argc, char *argv[]) {
  const char *Kep = "server_runtime.exe";
  struct WaitForMe_t {
    bool Canceled = false;
    ~WaitForMe_t() {
      if (Canceled) {
        return;
      }

#ifndef NDEBUG
      WaitForDebugger();
#endif
    }
  } WaitForMe;

  if (argc > 1) {
#ifndef NDEBUG
    WaitForDebugger();
#endif

    //
    // We are being invoke because of the IFEO, so let's retrieve the command
    // line.
    //

    std::string CommandLine;
    for (int Idx = 1; Idx < argc; Idx++) {
      const std::string_view Current(argv[Idx]);
      std::optional<std::string_view> Next;
      if (Idx + 1 < argc) {
        Next = argv[Idx + 1];
      }

      CommandLine.append(fmt::format("{}{}", Current, Next ? " " : ""));
    }

    //
    // Get a handle to the parent process. We'll use it to make the process
    // we're about to start its child.
    //

    const auto &ParentProcess =
        utils::GetParentProcessHandle(PROCESS_CREATE_PROCESS);
    if (!ParentProcess) {
      Print("GetParentProcessHandle failed\n");
      return EXIT_FAILURE;
    }

    const auto &CloseParentProcess =
        finally([&] { CloseHandle(*ParentProcess); });

    //
    // Prepare the THREAD_ATTRIBUTE_LIST.
    //

    STARTUPINFOEXA Si = {};
    GetStartupInfoA(&Si.StartupInfo);
    Si.StartupInfo.cb = sizeof(Si);

    SIZE_T Size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &Size);
    auto AttributeList = std::make_unique<uint8_t[]>(Size);
    Si.lpAttributeList = LPPROC_THREAD_ATTRIBUTE_LIST(AttributeList.get());
    InitializeProcThreadAttributeList(Si.lpAttributeList, 1, 0, &Size);
    const auto &CleanSi =
        finally([&] { DeleteProcThreadAttributeList(Si.lpAttributeList); });

    if (!UpdateProcThreadAttribute(
            Si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            PVOID(&ParentProcess.value()), sizeof(ParentProcess.value()),
            nullptr, nullptr)) {
      Print("UpdateProcThreadAttribute failed w/ GLE={}\n", GetLastError());
      return EXIT_FAILURE;
    }

    //
    // Make sure that if we crash / exit, it doesn't affect the debugee.
    //

    DebugSetProcessKillOnExit(false);

    //
    // Spawn the process as a debuggee, with a parent.
    //

    Print("Spawning {}..\n", CommandLine);
    PROCESS_INFORMATION Pi = {};
    DWORD CreationFlags =
        DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT;
    bool Created = CreateProcessA(nullptr, LPSTR(CommandLine.c_str()), nullptr,
                                  nullptr, false, CreationFlags, nullptr,
                                  nullptr, &Si.StartupInfo, &Pi);

    if (!Created) {

      //
      // Give it another shot w/o trying to change the parent (services.exe is
      // PPL).
      //

      Si.StartupInfo.cb = sizeof(Si.StartupInfo);
      CreationFlags ^= EXTENDED_STARTUPINFO_PRESENT;
      Created = CreateProcessA(nullptr, LPSTR(CommandLine.c_str()), nullptr,
                               nullptr, false, CreationFlags, nullptr, nullptr,
                               &Si.StartupInfo, &Pi);
    }

    if (!Created) {
      Print("CreateProcessA failed w/ GLE={}, bailing\n", GetLastError());
      return EXIT_FAILURE;
    }

    const auto &CleanPi = finally([&] {
      CloseHandle(Pi.hThread);
      CloseHandle(Pi.hProcess);
    });

    //
    // Hook NtQueryInformationProcess & NtSetThreadInformation to bypass some of
    // the anti-dbg.
    //

    if (!HookApis(Pi.hProcess)) {
      Print("Failed to hook the APIs, bailing\n");
      return EXIT_FAILURE;
    }

    //
    // Fix the INT 2D instruction trick.
    //

    if (!FixInt2D(Pi)) {
      Print("Failed to fix the INT 2D shennanigans, bailing\n");
      return EXIT_FAILURE;
    }

    //
    // We're done!
    //

    Print("Detached the debugger, happy debugging!\n");
    WaitForMe.Canceled = true;

    //
    // Wait until the service ends; this is so that services.exe doesn't think
    // the service died if we exit but server_runtime.exe keeps going.
    //

    WaitForSingleObject(Pi.hProcess, INFINITE);
    DWORD ExitCode = 0;
    if (!GetExitCodeProcess(Pi.hProcess, &ExitCode)) {
      return EXIT_FAILURE;
    }

    return ExitCode;
  }

  //
  // If we haven't registered KEPaboo yet, let's do it.
  //

  if (!reg::ReadIFEOString(Kep, "Debugger")) {
    Print("Writing into IFEO for {}..\n", Kep);
    const auto &MyPath = utils::GetCurrentExecutablePath();
    if (!MyPath) {
      Print("Failed to get my path, bailing\n");
      return EXIT_FAILURE;
    }

    const auto &Command = fmt::format("\"{}\"", MyPath->string());
    if (!reg::WriteIFEOString(Kep, "Debugger", Command)) {
      Print("Failed to write 'Debugger' IFEO value for {}, bailing\n", Kep);
      return EXIT_FAILURE;
    }

    Print("Successfully created a 'Debugger' IFEO value for \"{}\" w/ commad "
          "{}.\nFeel free to start up the server!\n",
          Kep, Command);

    WaitForMe.Canceled = true;
    return EXIT_SUCCESS;
  }

  //
  // We actually already are registered, so let's assume the user wants to clean
  // things up.
  //

  if (!reg::DeleteIFEOString(Kep, "Debugger")) {
    Print("Failed to clean up the IFEO entry, bailing\n");
    return EXIT_FAILURE;
  }

  Print("IFEO Debugger entry cleaned up!\n");
  WaitForMe.Canceled = true;
  return EXIT_SUCCESS;
}