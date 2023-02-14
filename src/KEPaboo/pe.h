// Axel '0vercl0k' Souchet - January 18 2023
#pragma once
#include "mem.h"
#include <cstdint>
#include <fmt/printf.h>
#include <optional>
#include <windows.h>

namespace pe {
#define sizeof_including(Struct, Field)                                        \
  (offsetof(Struct, Field) + sizeof(Struct::Field))

enum class Bitness_t { _32bit, _64bit };

template <Bitness_t Bitness> struct ImageStructures_t {};
template <> struct ImageStructures_t<Bitness_t::_32bit> {
  using NtHeaders_t = IMAGE_NT_HEADERS32;
  using LoadConfigDirectory_t = IMAGE_LOAD_CONFIG_DIRECTORY32;
};
template <> struct ImageStructures_t<Bitness_t::_64bit> {
  using NtHeaders_t = IMAGE_NT_HEADERS64;
  using LoadConfigDirectory_t = IMAGE_LOAD_CONFIG_DIRECTORY64;
};

template <Bitness_t Bitness>
using NtHeaders_t = ImageStructures_t<Bitness>::NtHeaders_t;

template <Bitness_t Bitness>
using LoadConfigDirectory_t = ImageStructures_t<Bitness>::LoadConfigDirectory_t;

template <typename Bitness_t Bitness, typename Func_t>
[[nodiscard]] bool WalkEat(const uintptr_t ImageBaseAddress, Func_t &&F,
                           const HANDLE Process = GetCurrentProcess()) {
  auto Va = [&](const DWORD Rva) { return ImageBaseAddress + Rva; };

  //
  // Read the DOS header.
  //

  IMAGE_DOS_HEADER DosHeader = {};
  if (!mem::VirtRead(Va(0), DosHeader, Process)) {
    Print("Failed to read DOS header\n");
    return false;
  }

  //
  // Read the first part of the NT headers.
  //

  NtHeaders_t<Bitness> NtHeaders = {};
  const auto NoOptionalHeaderSize =
      sizeof_including(decltype(NtHeaders), FileHeader);
  if (!mem::VirtRead(Va(DosHeader.e_lfanew), &NtHeaders, NoOptionalHeaderSize,
                     Process)) {
    Print("Failed to read the NT HEADERS\n");
    return false;
  }

  //
  // Is the optional header big enough to have an EAT?
  //

  const auto OptionalHeaderMinimumSize =
      sizeof_including(decltype(NtHeaders.OptionalHeader),
                       DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
  if (NtHeaders.FileHeader.SizeOfOptionalHeader < OptionalHeaderMinimumSize) {
    Print("Optional header looks too small\n");
    return false;
  }

  //
  // All right, let's read the optional header including the EAT.
  //

  auto &OptionalHeader = NtHeaders.OptionalHeader;
  const auto OptionalHeaderVa = Va(DosHeader.e_lfanew + NoOptionalHeaderSize);
  if (!mem::VirtRead(OptionalHeaderVa, &OptionalHeader,
                     OptionalHeaderMinimumSize, Process)) {
    Print("Failed to read optional header\n");
    return false;
  }

  //
  // Read the actual directory.
  //

  const auto &EatDirectory =
      OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  IMAGE_EXPORT_DIRECTORY ExportDirectory = {};
  if (!mem::VirtRead(Va(EatDirectory.VirtualAddress), ExportDirectory,
                     Process)) {
    Print("Failed to read EXPORT DIRECTORY\n");
    return false;
  }

  //
  // Walk through the named entries; ignoring exported by ordinals as well as
  // forwarding exports.
  //

  const auto Names = (uint32_t *)(Va(ExportDirectory.AddressOfNames));
  const auto Functions = (uint32_t *)(Va(ExportDirectory.AddressOfFunctions));
  const auto NameOrdinals =
      (uint16_t *)(Va(ExportDirectory.AddressOfNameOrdinals));
  for (size_t Idx = 0; Idx < ExportDirectory.NumberOfNames; Idx++) {

    //
    // Read the Name RVA.
    //

    uint32_t NameRva = 0;
    if (!mem::VirtRead(uintptr_t(&Names[Idx]), NameRva, Process)) {
      Print("Failed to read the RVA of a Name\n");
      return false;
    }

    //
    // Read the actual function name.
    //

    const auto &Name = mem::VirtReadString(Va(NameRva), 32, Process);
    if (!Name) {
      Print("Failed to read the function name in the EAT\n");
      return false;
    }

    //
    // Read the name ordinal.
    //

    uint16_t NameOrdinal = 0;
    if (!mem::VirtRead(uintptr_t(&NameOrdinals[Idx]), NameOrdinal, Process)) {
      Print("Failed to read the RVA of a NameOrdinal\n");
      return false;
    }

    //
    // Invoke the user's callback, pass it the function pointer for hooking
    // purpose.
    //

    const auto Continue = F(Name->c_str(), uintptr_t(&Functions[NameOrdinal]));
    if (!Continue) {
      break;
    }
  }

  return true;
}

template <typename Func_t>
[[nodiscard]] bool WalkEat32(const uintptr_t ImageBaseAddress, Func_t &&F,
                             const HANDLE Process = GetCurrentProcess()) {
  return WalkEat<Bitness_t::_32bit>(ImageBaseAddress, std::move(F), Process);
}

template <typename Func_t>
[[nodiscard]] bool WalkEat64(const uintptr_t ImageBaseAddress, Func_t &&F,
                             const HANDLE Process = GetCurrentProcess()) {
  return WalkEat<Bitness_t::_64bit>(ImageBaseAddress, std::move(F), Process);
}

template <typename Bitness_t Bitness>
[[nodiscard]] std::optional<IMAGE_SECTION_HEADER>
GetSectionHeader(const uintptr_t Module, const char *SectionName,
                 const HANDLE Process = GetCurrentProcess()) {
  auto Va = [&](const DWORD Rva) { return Module + Rva; };

  //
  // Read the DOS header.
  //

  IMAGE_DOS_HEADER DosHeader = {};
  if (!mem::VirtRead(Va(0), DosHeader, Process)) {
    Print("Failed to read DOS header\n");
    return {};
  }

  //
  // Read the first part of the NT headers.
  //

  NtHeaders_t<Bitness> NtHeaders = {};
  const auto NoOptionalHeaderSize =
      sizeof_including(decltype(NtHeaders), FileHeader);
  if (!mem::VirtRead(Va(DosHeader.e_lfanew), &NtHeaders, NoOptionalHeaderSize,
                     Process)) {
    Print("Failed to read the NT HEADERS\n");
    return {};
  }

  //
  // The section headers are right after the NT headers, so figure out how big
  // is the optional header to jump over it.
  //

  const auto &FileHeader = NtHeaders.FileHeader;
  const auto SizeOfOptionalHeader = FileHeader.SizeOfOptionalHeader;
  const auto OffsetOptionalHeader =
      offsetof(decltype(NtHeaders), OptionalHeader);

  //
  // Calculate the address of the first section header.
  //

  const auto Sections = PIMAGE_SECTION_HEADER(
      Va(DosHeader.e_lfanew + OffsetOptionalHeader + SizeOfOptionalHeader));

  //
  // Walk through the different section headers.
  //

  for (size_t Idx = 0; Idx < FileHeader.NumberOfSections; Idx++) {
    //
    // Read a section header.
    //

    IMAGE_SECTION_HEADER Section = {};
    if (!mem::VirtRead(uintptr_t(&Sections[Idx]), Section, Process)) {
      Print("Failed to read IMAGE_SECTION_HEADER\n");
      return {};
    }

    //
    // Is this the section we are looking for?
    //

    if (std::strcmp((char *)Section.Name, SectionName) == 0) {
      return Section;
    }
  }

  //
  // Ugh, we haven't found the section.
  //

  return {};
}

[[nodiscard]] std::optional<IMAGE_SECTION_HEADER>
GetSectionHeader32(const uintptr_t Module, const char *SectionName,
                   const HANDLE Process = GetCurrentProcess()) {
  return GetSectionHeader<Bitness_t::_32bit>(Module, SectionName, Process);
}

[[nodiscard]] std::optional<IMAGE_SECTION_HEADER>
GetSectionHeader64(const uintptr_t Module, const char *SectionName,
                   const HANDLE Process = GetCurrentProcess()) {
  return GetSectionHeader<Bitness_t::_64bit>(Module, SectionName, Process);
}

template <Bitness_t Bitness>
[[nodiscard]] std::optional<uint64_t>
GetSecurityCookieAddress(const uintptr_t ImageBaseAddress,
                         const HANDLE Process = GetCurrentProcess()) {
  auto Va = [&](const DWORD Rva) { return ImageBaseAddress + Rva; };

  //
  // Read the DOS header.
  //

  IMAGE_DOS_HEADER DosHeader = {};
  if (!mem::VirtRead(ImageBaseAddress, DosHeader, Process)) {
    Print("Failed to read DOS header\n");
    return {};
  }

  //
  // Read the first part of the NT headers.
  //

  NtHeaders_t<Bitness> NtHeaders = {};
  const auto NoOptionalHeaderSize =
      sizeof_including(decltype(NtHeaders), FileHeader);
  if (!mem::VirtRead(Va(DosHeader.e_lfanew), &NtHeaders, NoOptionalHeaderSize,
                     Process)) {
    Print("Failed to read the NT HEADERS\n");
    return {};
  }

  //
  // Figure out if the optional header is big enough to have a load config
  // directory.
  //

  const auto OptionalHeaderMinimumSize =
      sizeof_including(decltype(NtHeaders.OptionalHeader),
                       DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]);
  if (NtHeaders.FileHeader.SizeOfOptionalHeader < OptionalHeaderMinimumSize) {
    Print("PE does not have a LOAD_CONFIG directory\n");
    return {};
  }

  //
  // Read the optional header until the load config directory.
  //

  auto &OptionalHeader = NtHeaders.OptionalHeader;
  const auto OptionalHeaderVa = Va(DosHeader.e_lfanew + NoOptionalHeaderSize);
  if (!mem::VirtRead(OptionalHeaderVa, &OptionalHeader,
                     OptionalHeaderMinimumSize, Process)) {
    Print("Failed to read optional header\n");
    return {};
  }

  //
  // Figure out if the load config directory is big enough to have a cookie.
  //

  const auto &LoadConfigDataDirectory =
      OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
  LoadConfigDirectory_t<Bitness> LoadConfig = {};
  const auto MinimumLoadConfigDirectorySize =
      sizeof_including(decltype(LoadConfig), SecurityCookie);
  if (LoadConfigDataDirectory.Size < MinimumLoadConfigDirectorySize) {
    Print("Load config directory is too small to have a SecurityCookie\n");
    return {};
  }

  //
  // Read the load config directory until the cookie.
  //

  if (!mem::VirtRead(Va(LoadConfigDataDirectory.VirtualAddress), &LoadConfig,
                     MinimumLoadConfigDirectorySize, Process)) {
    Print("Failed to read the load config directory\n");
    return {};
  }

  //
  // Yay, cookies!
  //

  return LoadConfig.SecurityCookie;
}

[[nodiscard]] std::optional<uint32_t>
GetSecurityCookieAddress32(const uintptr_t ImageBaseAddress,
                           const HANDLE Process = GetCurrentProcess()) {
  const auto &Cookie =
      GetSecurityCookieAddress<Bitness_t::_32bit>(ImageBaseAddress, Process);
  if (Cookie) {
    return uint32_t(Cookie.value());
  }

  return {};
}

[[nodiscard]] std::optional<uint64_t>
GetSecurityCookieAddress64(const uintptr_t ImageBaseAddress,
                           const HANDLE Process = GetCurrentProcess()) {
  return GetSecurityCookieAddress<Bitness_t::_64bit>(ImageBaseAddress, Process);
}

} // namespace pe
