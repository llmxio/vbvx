#pragma once

#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>

namespace vbvx {

/** @brief Byte-swap a value if the host is little-endian. */
template <typename _Tp>
  requires std::integral<_Tp>
constexpr _Tp autoswap(_Tp tp) {
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(tp);
  } else {
    return tp;
  }
}

/** @brief Read a trivially copyable type from a byte array. */
template <typename _Tp>
  requires std::is_trivially_copyable_v<_Tp>
constexpr _Tp read_from_bytes(const uint8_t* src) {
  _Tp tp;
  std::memcpy(&tp, src, sizeof(_Tp));
  return tp;
}

} // namespace vbvx
