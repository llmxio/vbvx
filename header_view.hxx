#pragma once

#include <concepts>
#include <cstring>

namespace vbvx {

template <typename T>
concept WireHeader = std::is_trivially_copyable_v<T> &&
                     std::is_standard_layout_v<T> && (alignof(T) == 1);

/**
 * @brief A lightweight view over a header inside a packet buffer.
 *
 * - Zero-copy: wraps a pointer into the packet data.
 * - Safe: alignment is 1 due to alignas(1) on header structs.
 * - Convenient: acts like a pointer and can be copied out when needed.
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
