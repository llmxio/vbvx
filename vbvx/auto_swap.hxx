#pragma once

#include <bit>
#include <concepts>

namespace vbvx {

template <std::integral _Tp> constexpr _Tp autoswap(_Tp tp) {
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(tp);
  } else {
    return tp;
  }
}

} // namespace vbvx
