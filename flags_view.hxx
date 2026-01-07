#pragma once

#include <concepts>
#include <type_traits>
// #include <utility>

namespace vbvx {

template <typename T> struct enable_bitmask_operators : std::false_type {};

template <typename T>
constexpr bool enable_bitmask_operators_v = enable_bitmask_operators<T>::value;

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E operator|(E lhs, E rhs) {
  using T = std::underlying_type_t<E>;
  return static_cast<E>(static_cast<T>(lhs) | static_cast<T>(rhs));
}

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E operator&(E lhs, E rhs) {
  using T = std::underlying_type_t<E>;
  return static_cast<E>(static_cast<T>(lhs) & static_cast<T>(rhs));
}

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E operator^(E lhs, E rhs) {
  using T = std::underlying_type_t<E>;
  return static_cast<E>(static_cast<T>(lhs) ^ static_cast<T>(rhs));
}

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E operator~(E val) {
  using T = std::underlying_type_t<E>;
  return static_cast<E>(~static_cast<T>(val));
}

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E& operator|=(E& lhs, E rhs) {
  lhs = lhs | rhs;
  return lhs;
}

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E& operator&=(E& lhs, E rhs) {
  lhs = lhs & rhs;
  return lhs;
}

template <typename E>
  requires enable_bitmask_operators_v<E>
constexpr E& operator^=(E& lhs, E rhs) {
  lhs = lhs ^ rhs;
  return lhs;
}

template <typename E, std::integral U>
  requires enable_bitmask_operators_v<E>
constexpr E operator<<(E lhs, U shift) {
  using T = std::underlying_type_t<E>;
  return static_cast<E>(static_cast<T>(lhs) << shift);
}

template <typename E, std::integral U>
  requires enable_bitmask_operators_v<E>
constexpr E operator>>(E lhs, U shift) {
  using T = std::underlying_type_t<E>;
  return static_cast<E>(static_cast<T>(lhs) >> shift);
}

template <typename BitmaskEnum>
  requires std::is_enum_v<BitmaskEnum>
class ConstFlagsView;

/**
 * @brief A zero-copy mutable view for a bitmask enum.
 *
 * Provides a convenient, chainable interface for modifying and checking flags.
 */
template <typename BitmaskEnum>
  requires std::is_enum_v<BitmaskEnum>
class FlagsView {
public:
  explicit FlagsView(BitmaskEnum& flags) : flags_ref_(flags) {}

  constexpr auto set(BitmaskEnum mask) -> FlagsView& {
    flags_ref_ |= mask;
    return *this;
  }

  constexpr auto clear(BitmaskEnum mask) -> FlagsView& {
    flags_ref_ &= ~mask;
    return *this;
  }

  constexpr auto toggle(BitmaskEnum mask) -> FlagsView& {
    flags_ref_ ^= mask;
    return *this;
  }

  constexpr auto reset() -> FlagsView& {
    flags_ref_ = static_cast<BitmaskEnum>(0);
    return *this;
  }

  constexpr bool has(BitmaskEnum mask) const {
    return (flags_ref_ & mask) != static_cast<BitmaskEnum>(0);
  }

  constexpr bool has_all(BitmaskEnum mask) const {
    return (flags_ref_ & mask) == mask;
  }

  constexpr auto value() const -> BitmaskEnum { return flags_ref_; }
  constexpr operator BitmaskEnum() const { return flags_ref_; }

  constexpr operator ConstFlagsView<BitmaskEnum>() const {
    return ConstFlagsView<BitmaskEnum>(flags_ref_);
  }

private:
  BitmaskEnum& flags_ref_;
};

/**
 * @brief A zero-copy const view for a bitmask enum.
 *
 * Provides a convenient read-only interface for checking flags.
 */
template <typename BitmaskEnum>
  requires std::is_enum_v<BitmaskEnum>
class ConstFlagsView {
public:
  explicit ConstFlagsView(const BitmaskEnum& flags) : flags_ref_(flags) {}

  constexpr bool has(BitmaskEnum mask) const {
    return (flags_ref_ & mask) != static_cast<BitmaskEnum>(0);
  }

  constexpr bool has_all(BitmaskEnum mask) const {
    return (flags_ref_ & mask) == mask;
  }

  constexpr auto value() const->BitmaskEnum { return flags_ref_; }
  constexpr operator BitmaskEnum() const { return flags_ref_; }

private:
  const BitmaskEnum& flags_ref_;
};

} // namespace vbvx
