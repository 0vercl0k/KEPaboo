// Axel '0vercl0k' Souchet - January 18 2023
#pragma once
#include "utils.h"
#include <array>
#include <cstdint>
#include <fmt/printf.h>
#include <optional>
#include <string>
#include <windows.h>

namespace mem {
[[nodiscard]] bool VirtWrite(const uintptr_t RemoteAddress, const void *Value,
                             const size_t ValueSize,
                             const HANDLE Process = GetCurrentProcess(),
                             const bool Unprotect = false) {
  const uint64_t PageSize = 0x1'000;
  const auto AlignedRemoteAddressPage =
      PVOID(RemoteAddress & (~(PageSize - 1)));
  DWORD OldProtect = 0;
  if (Unprotect) {
    if (!VirtualProtectEx(Process, AlignedRemoteAddressPage, PageSize,
                          PAGE_READWRITE, &OldProtect)) {
      Print("VirtualProtectEx +rw failed w/ GLE={}, bailing\n",
                 GetLastError());
      return false;
    }
  }

  DWORD OldProtect2 = 0;
  SIZE_T AmountWritten = 0;
  const bool WriteSuccess = WriteProcessMemory(
      Process, PVOID(RemoteAddress), Value, ValueSize, &AmountWritten);
  if (Unprotect) {
    if (!VirtualProtectEx(Process, AlignedRemoteAddressPage, PageSize,
                          OldProtect, &OldProtect2)) {
      Print("VirtualProtectEx +old failed w/ GLE={}, bailing\n",
                 GetLastError());
      return false;
    }
  }

  if (!WriteSuccess || AmountWritten != ValueSize) {
    Print("WriteProcessMemory failed w/ GLE={}, bailing\n",
               GetLastError());
    return false;
  }

  return true;
}

template <typename Struct_t>
[[nodiscard]] bool VirtWrite(const uintptr_t RemoteAddress, Struct_t &Struct,
                             const HANDLE Process = GetCurrentProcess(),
                             const bool Unprotect = false) {
  return VirtWrite(RemoteAddress, &Struct, sizeof(Struct), Process, Unprotect);
}

[[nodiscard]] bool VirtRead(const uintptr_t RemoteAddress, void *Buffer,
                            const size_t BufferLength,
                            const HANDLE Process = GetCurrentProcess()) {
  SIZE_T AmountRead = 0;
  if (!ReadProcessMemory(Process, (void *)RemoteAddress, Buffer, BufferLength,
                         &AmountRead)) {
    return false;
  }

  return AmountRead == BufferLength;
}

[[nodiscard]] bool VirtReadPartial(const uintptr_t RemoteAddress, void *Buffer,
                                   const size_t BufferLength,
                                   const size_t *AmountRead,
                                   const HANDLE Process = GetCurrentProcess()) {
  if (!ReadProcessMemory(Process, (void *)RemoteAddress, Buffer, BufferLength,
                         PSIZE_T(AmountRead))) {
    return false;
  }

  if (*AmountRead < BufferLength) {

    //
    // We allow partial reads let's just be nice and fill it up.
    //

    const size_t Remaining = BufferLength - *AmountRead;
    if (Remaining) {
      memset((char *)Buffer + *AmountRead, 0, Remaining);
    }
  }

  return true;
}

[[nodiscard]] bool VirtRead(const uintptr_t RemoteAddress, void *Buffer,
                            const size_t BufferLength,
                            const DWORD Pid = GetCurrentProcessId()) {
  const HANDLE Process = OpenProcess(PROCESS_VM_READ, false, Pid);
  if (Process == nullptr) {
    return false;
  }

  const auto &CloseProcess = finally([&] { CloseHandle(Process); });
  return VirtRead(RemoteAddress, Buffer, BufferLength, Process);
}

template <typename Struct_t>
[[nodiscard]] bool VirtRead(const uintptr_t RemoteAddress, Struct_t &Struct,
                            const HANDLE Process = GetCurrentProcess()) {
  return VirtRead(RemoteAddress, &Struct, sizeof(Struct), Process);
}

[[nodiscard]] std::optional<uintptr_t>
VirtReadPointer(const uintptr_t RemoteAddress,
                const HANDLE Process = GetCurrentProcess()) {
  uintptr_t Pointer = 0;
  if (!VirtRead(RemoteAddress, Pointer, Process)) {
    return {};
  }

  return Pointer;
}

[[nodiscard]] std::optional<std::string>
VirtReadString(const uintptr_t RemoteAddress, const size_t MaxCharacters = 64,
               const HANDLE Process = GetCurrentProcess()) {

  //
  // We read the target process by chunk and we stop once we find a
  // null terminator.
  //

  const size_t ChunkSize = 128;
  std::array<uint8_t, ChunkSize> Chunk;

  uintptr_t CurrentRemoteAddress = RemoteAddress;
  size_t Left = MaxCharacters;
  std::string ReadString;
  while (Left > 0) {

    //
    // How many bytes do we need to read? Either a full chunk, or
    // whatever we have left.
    //

    const size_t Size2Read = std::min(Chunk.size(), Left);
    size_t AmountRead = 0;
    if (!VirtReadPartial(CurrentRemoteAddress, Chunk.data(), Size2Read,
                         &AmountRead, Process) &&
        AmountRead >= 1) {
      return {};
    }

    //
    // Scan the chunk to find a potential null terminator and
    // calculate the number of characters we need to copy / convert
    // in the returned string.
    //

    size_t NumberCharacters = 0;
    bool HasTerminator = false;
    for (size_t Idx = 0; Idx < AmountRead; Idx++) {
      HasTerminator = Chunk[Idx] == 0;
      if (HasTerminator) {
        break;
      }

      NumberCharacters++;
    }

    //
    // Extend the string by |NumberCharacters|.
    //

    const size_t OldSize = ReadString.size();
    const size_t NewSize = OldSize + NumberCharacters;
    ReadString.resize(NewSize);

    //
    // If we are dealing with a normal string, simply memcpy it.
    //

    std::memcpy(&ReadString[OldSize], Chunk.data(), NumberCharacters);

    //
    // All right, if we weren't able to read as much as we wanted,
    // let's stop there. If we encountered a terminator then we're
    // also done.
    //

    if (AmountRead != Size2Read || HasTerminator) {
      break;
    }

    //
    // We have more to read seems like, so move things along.
    //

    CurrentRemoteAddress += AmountRead;
    Left -= AmountRead;
  }

  //
  // If we truncate the string, at least adds "..." as a sign.
  //

  if (ReadString.size() == MaxCharacters) {
    ReadString.append("...");
  }

  return ReadString;
}
} // namespace mem