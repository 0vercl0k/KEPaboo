// Axel '0vercl0k' Souchet - January 18 2023
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <windows.h>

namespace reg {
enum ValueType_t : uint32_t {
  Binary = REG_BINARY,
  Dword = REG_DWORD,
  String = REG_SZ,
};

const std::string_view IFEOPath(
    R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options)");

[[nodiscard]] bool WriteValue(const HKEY Key, const std::string &Subkey,
                              const std::string &ValueName,
                              const ValueType_t &ValueType, const void *Value,
                              const size_t ValueSize) {
  HKEY KeyHandle = 0;
  DWORD Disposition = 0;
  LONG Ret =
      RegCreateKeyExA(Key, Subkey.c_str(), 0, nullptr, REG_OPTION_VOLATILE,
                      KEY_SET_VALUE, nullptr, &KeyHandle, &Disposition);
  if (Ret != ERROR_SUCCESS) {
    return false;
  }

  Ret = RegSetValueExA(KeyHandle, ValueName.c_str(), 0, ValueType, PBYTE(Value),
                       DWORD(ValueSize));
  RegCloseKey(KeyHandle);

  if (Ret != ERROR_SUCCESS) {
    return false;
  }

  return true;
}

[[nodiscard]] bool WriteStringValue(const HKEY Key, const std::string &Subkey,
                                    const std::string &ValueName,
                                    const std::string &Value) {
  return WriteValue(Key, Subkey, ValueName, ValueType_t::String, Value.c_str(),
                    Value.size());
}

[[nodiscard]] bool WriteIFEOString(const std::string &Executable,
                                   const std::string &ValueName,
                                   const std::string &Value) {

  const auto &Subkey = fmt::format("{}\\{}", IFEOPath, Executable);
  return WriteStringValue(HKEY_LOCAL_MACHINE, Subkey, ValueName, Value);
}

[[nodiscard]] bool DeleteIFEOString(const std::string &Executable,
                                    const std::string &ValueName) {
  const auto &Subkey = fmt::format("{}\\{}", IFEOPath, Executable);
  return RegDeleteKeyValueA(HKEY_LOCAL_MACHINE, Subkey.c_str(),
                            ValueName.c_str()) == ERROR_SUCCESS;
}

[[nodiscard]] std::optional<std::string>
ReadStringValue(const HKEY Key, const std::string &Subkey,
                const std::string &ValueName) {
  std::string String;
  DWORD Length = 0;
  DWORD Status = RegGetValueA(Key, Subkey.c_str(), ValueName.c_str(),
                              RRF_RT_REG_SZ, nullptr, nullptr, &Length);
  if (Status == ERROR_FILE_NOT_FOUND) {
    return {};
  }

  if (Status != ERROR_SUCCESS || Length == 0) {
    Print("RegGetValueA to get the size failed w/ {}\n", Status);
    return {};
  }

  String.resize(Length);
  Status = RegGetValueA(Key, Subkey.c_str(), ValueName.c_str(), RRF_RT_REG_SZ,
                        nullptr, String.data(), &Length);
  if (Status != ERROR_SUCCESS) {
    Print("RegGetValueA failed w/ GLE={}\n", GetLastError());
    return {};
  }

  return String;
}

[[nodiscard]] std::optional<std::string>
ReadIFEOString(const std::string &Executable, const std::string &ValueName) {
  const auto &Subkey = fmt::format("{}\\{}", IFEOPath, Executable);
  return ReadStringValue(HKEY_LOCAL_MACHINE, Subkey.c_str(), ValueName);
}
} // namespace reg
