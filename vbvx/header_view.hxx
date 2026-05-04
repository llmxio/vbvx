#pragma once

#include <concepts>
#include <cstdint>
#include <cstring>

namespace vbvx {

template <typename _Tp>
concept WireHeader = std::is_trivially_copyable_v<_Tp> &&
                     std::is_standard_layout_v<_Tp> && (alignof(_Tp) == 1);

/**
 * @brief A lightweight view over a header inside a packet buffer.
 *
 * - Zero-copy: wraps a pointer into the packet data.
 * - Bounds are checked by BufferView before construction.
 * - Convenient: acts like a pointer and can be copied out when needed.
 *
 * @warning The byte-pointer constructor creates a `const H*` over arbitrary
 * packet bytes. This is a deliberate GCC/Clang-oriented zero-copy extension
 * used with `[[gnu::packed]]` wire structs; it relies on those compilers'
 * practical handling of packed object views over byte storage. It is not a
 * fully portable ISO C++ object-lifetime/effective-type pattern. Use `copy()`
 * when a portable local value is needed.
 */
template <WireHeader H> class HeaderView {
  using header_t = H;

public:
  constexpr HeaderView() noexcept = default;
  constexpr explicit HeaderView(const header_t* p) noexcept : p_{p} {}

  constexpr explicit HeaderView(const uint8_t* p) noexcept
      : p_{reinterpret_cast<const header_t*>(p)} {}

  constexpr explicit operator bool() const noexcept { return p_ != nullptr; }
  constexpr auto get() const noexcept -> const header_t* { return p_; }

  constexpr auto operator->() const noexcept -> const header_t* { return p_; }
  constexpr auto operator*() const noexcept -> const header_t& { return *p_; }

  constexpr auto copy() const noexcept -> header_t {
    header_t out{};
    if (p_) {
      std::memcpy(&out, p_, sizeof(header_t));
    }
    return out;
  }

private:
  const header_t* p_{};
};

} // namespace vbvx
