// Axel '0vercl0k' Souchet - January 18 2023
#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <fmt/format.h>
#include <fmt/printf.h>
#include <optional>
#include <unordered_map>
#include <utility>

#include <windows.h>

#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

#ifndef NDEBUG
#define Print(...)                                                             \
  do {                                                                         \
    OutputDebugStringA(fmt::format(__VA_ARGS__).c_str());                      \
    fmt::print(__VA_ARGS__);                                                   \
  } while (0);
#else
#define Print(...) fmt::print(__VA_ARGS__)
#endif

template <typename F_t> [[nodiscard]] auto finally(F_t &&f) noexcept {
  struct Finally_t {
    F_t f_;
    bool Canceled = false;
    Finally_t(F_t &&f) noexcept : f_(f) {}
    ~Finally_t() noexcept {
      if (!Canceled) {
        f_();
      }
    }
  };

  return Finally_t(std::move(f));
}

namespace utils {
enum class THREADINFOCLASS : uint32_t { ThreadBasicInformation };

extern "C" uint32_t NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);

[[nodiscard]] uintptr_t PageSize() { return 0x1'000; }

[[nodiscard]] uintptr_t PageOffsetMask() { return PageSize() - 1; }

[[nodiscard]] uintptr_t PageAlign(const uintptr_t Addr) {
  return Addr & (~PageOffsetMask());
}

uintptr_t PageOffset(const uintptr_t &Addr) { return Addr & PageOffsetMask(); }

[[nodiscard]] std::optional<uintptr_t> GetTebAddress(const HANDLE Thread) {
  struct {
    uint32_t ExitStatus;
    uintptr_t TebBaseAddress;
    struct {
      HANDLE UniqueProcess;
      HANDLE UniqueThread;
    } ClientId;
    uintptr_t AffinityMask;
    uint32_t Priority;
    uint32_t BasePriority;
  } ThreadInformation = {};

  ULONG Length = 0;
  if (NtQueryInformationThread(Thread, THREADINFOCLASS::ThreadBasicInformation,
                               &ThreadInformation, sizeof(ThreadInformation),
                               &Length) != 0 ||
      Length != sizeof(ThreadInformation)) {
    return {};
  }

  return ThreadInformation.TebBaseAddress;
}

[[nodiscard]] std::optional<std::unordered_map<DWORD, PROCESSENTRY32>>
GetProcesses() {
  std::unordered_map<DWORD, PROCESSENTRY32> Processes;
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Snapshot == INVALID_HANDLE_VALUE) {
    Print("CreateToolhelp32Snapshot failed w/ GLE={}\n", GetLastError());
    return {};
  }

  PROCESSENTRY32 Entry = {};
  Entry.dwSize = sizeof(Entry);
  if (!Process32First(Snapshot, &Entry)) {
    Print("Process32First failed w/ GLE={}\n", GetLastError());
    CloseHandle(Snapshot);
    return {};
  }

  do {
    Processes.emplace(Entry.th32ProcessID, Entry);
  } while (Process32Next(Snapshot, &Entry));

  CloseHandle(Snapshot);
  return Processes;
}

[[nodiscard]] std::optional<DWORD>
GetParentProcessId(const DWORD WhoseParentPid = GetCurrentProcessId()) {
  const auto &Processes = GetProcesses();
  if (!Processes) {
    Print("GetProcesses failed\n");
    return {};
  }

  for (const auto &[Pid, Entry] : *Processes) {
    if (Pid != WhoseParentPid) {
      continue;
    }

    return Entry.th32ParentProcessID;
  }

  return {};
}

[[nodiscard]] std::optional<HANDLE>
ProcessIdToHandle(const DWORD Pid, const DWORD DesiredAccess) {
  HANDLE Handle = OpenProcess(DesiredAccess, false, Pid);
  if (Handle == INVALID_HANDLE_VALUE) {
    Print("OpenProcess failed w/ GLE={}\n", GetLastError());
    return {};
  }

  return Handle;
}

[[nodiscard]] std::optional<HANDLE>
GetParentProcessHandle(const DWORD DesiredAccess,
                       const DWORD WhosePid = GetCurrentProcessId()) {
  const auto &ParentProcessId = GetParentProcessId(WhosePid);
  if (!ParentProcessId) {
    Print("GetParentProcessId failed\n");
    return {};
  }

  return ProcessIdToHandle(*ParentProcessId, DesiredAccess);
}

[[nodiscard]] std::optional<fs::path> GetCurrentExecutablePath() {
  std::array<char, MAX_PATH> PathBuffer = {};
  if (!GetModuleFileNameA(nullptr, &PathBuffer[0], PathBuffer.size())) {
    Print("GetModuleFileNameA failed.\n");
    return {};
  }

  const fs::path ExePath(PathBuffer.data());
  const fs::path ParentDir(ExePath.parent_path());
  const HMODULE CurrentModule = GetModuleHandleA(nullptr);
  if (!GetModuleFileNameA(CurrentModule, &PathBuffer[0], PathBuffer.size())) {
    Print("GetModuleFileNameA failed.\n");
    return {};
  }

  return ParentDir / PathBuffer.data();
}

[[nodiscard]] std::optional<uintptr_t>
GetModuleAddress(const DWORD ProcessId, const std::string &ModuleName) {
  HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
  if (Snapshot == INVALID_HANDLE_VALUE) {
    Print("CreateToolhelp32Snapshot failed w/ GLE={}\n", GetLastError());
    return {};
  }

  const auto &CloseSnapshot = finally([&] { CloseHandle(Snapshot); });

  MODULEENTRY32 ModuleEntry = {};
  ModuleEntry.dwSize = sizeof(ModuleEntry);

  if (!Module32First(Snapshot, &ModuleEntry)) {
    Print("Module32First failed w/ GLE={}\n", GetLastError());
    return {};
  }

  do {
    const std::string_view Path = ModuleEntry.szExePath;
    const auto OffsetBackslash = Path.find_last_of('\\');
    const auto Offset = OffsetBackslash == Path.npos ? 0 : OffsetBackslash + 1;
    const auto &Name = Path.substr(Offset);
    if (!_stricmp(Name.data(), ModuleName.c_str())) {
      return uintptr_t(ModuleEntry.modBaseAddr);
    }
  } while (Module32Next(Snapshot, &ModuleEntry));
  return {};
}
} // namespace utils
