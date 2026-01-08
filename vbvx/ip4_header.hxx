#pragma once

#include <bit>
#include <cstdint>
#include <type_traits>
#include <utility>

#include "utils.hxx"
#include "ip_protocol.hxx"
#include "flags_view.hxx"

namespace vbvx {

static constexpr uint16_t FRAG_FLAGS_MASK = 0xE000u;
static constexpr uint16_t FRAG_OFFSET_MASK = 0x1FFFu;

/** @brief IPv4 fragmentation flags. */
enum class IPv4Flags : uint16_t {
  None = 0,
  MF = 0x2000, // More Fragments
  DF = 0x4000, // Don't Fragment
  RFU = 0x8000 // Reserved (must be zero)
};

template <> struct enable_bitmask_operators<IPv4Flags> : std::true_type {};

/**
 * @brief IPv4 header (minimum 20 bytes).
 *
 * @see IANA IPv4 Parameters:
 *   https://www.iana.org/assignments/ipv4-parameters/ipv4-parameters.xhtml
 * @see IETF RFC 791 (Internet Protocol):
 *   https://datatracker.ietf.org/doc/html/rfc791
 */
struct [[gnu::packed]] IPv4Header {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length_be;
  uint16_t id_be;
  uint16_t frag_off_be;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum_be;
  uint32_t src_addr_be;
  uint32_t dst_addr_be;

  constexpr auto version() const noexcept -> uint8_t {
    return (version_ihl >> 4) & 0x0Fu;
  }

  constexpr auto ihl_words() const noexcept -> uint16_t {
    return version_ihl & 0x0Fu;
  }

  constexpr auto ihl_bytes() const noexcept -> uint16_t {
    return ihl_words() * 4u;
  }

  constexpr auto dscp() const noexcept -> uint8_t { return (tos >> 2) & 0x3Fu; }
  constexpr auto ecn() const noexcept -> uint8_t { return tos & 0x03u; }

  constexpr auto total_length() const noexcept -> uint16_t {
    return autoswap(total_length_be);
  }

  constexpr auto id() const noexcept -> uint16_t { return autoswap(id_be); }

  constexpr auto frag_off() const noexcept -> uint16_t {
    return autoswap(frag_off_be);
  }

  constexpr auto frag_flags() const noexcept -> IPv4Flags {
    return static_cast<IPv4Flags>(frag_off() & FRAG_FLAGS_MASK);
  }

  constexpr bool has_flag(IPv4Flags flag) const noexcept {
    return (frag_flags() & flag) != IPv4Flags::None;
  }

  constexpr auto frag_offset_units8() const noexcept -> uint16_t {
    return static_cast<uint16_t>(frag_off() & FRAG_OFFSET_MASK);
  }

  constexpr auto frag_offset_bytes() const noexcept -> uint16_t {
    return static_cast<uint16_t>(frag_offset_units8() * 8u);
  }

  constexpr bool is_fragmented() const noexcept {
    return has_flag(IPv4Flags::MF) || frag_offset_units8() != 0;
  }

  constexpr void set_frag_flags(IPv4Flags flags) noexcept {
    auto raw = frag_off();
    raw &= FRAG_OFFSET_MASK;
    raw |= static_cast<uint16_t>(std::to_underlying(flags) & FRAG_FLAGS_MASK);
    frag_off_be = autoswap(raw);
  }

  constexpr void set_frag_offset_units8(uint16_t units8) noexcept {
    auto raw = frag_off();
    raw &= FRAG_FLAGS_MASK;
    raw |= static_cast<uint16_t>(units8 & FRAG_OFFSET_MASK);
    frag_off_be = autoswap(raw);
  }

  constexpr void set_frag_offset_bytes(uint16_t bytes) noexcept {
    set_frag_offset_units8(static_cast<uint16_t>(bytes >> 3));
  }

  constexpr void set_df(bool enabled) noexcept {
    set_flag(IPv4Flags::DF, enabled);
  }

  constexpr void set_mf(bool enabled) noexcept {
    set_flag(IPv4Flags::MF, enabled);
  }

  constexpr auto l4_protocol() const noexcept -> IpProtocol {
    return static_cast<IpProtocol>(protocol);
  }

  constexpr auto checksum() const noexcept -> uint16_t {
    return autoswap(checksum_be);
  }

  constexpr void set_checksum(uint16_t v) noexcept {
    checksum_be = autoswap(v);
  }

  constexpr auto src_addr() const noexcept -> uint32_t {
    return autoswap(src_addr_be);
  }

  constexpr auto dst_addr() const noexcept -> uint32_t {
    return autoswap(dst_addr_be);
  }

  constexpr void set_src(uint32_t v) noexcept { src_addr_be = autoswap(v); }
  constexpr void set_dst(uint32_t v) noexcept { dst_addr_be = autoswap(v); }
  constexpr bool valid_min_size() const noexcept { return ihl_bytes() >= 20; }

private:
  constexpr void set_flag(IPv4Flags flag, bool enabled) noexcept {
    auto raw = frag_off();
    const auto mask = std::to_underlying(flag);
    if (enabled)
      raw |= static_cast<uint16_t>(mask);
    else
      raw &= static_cast<uint16_t>(~mask);
    frag_off_be = autoswap(raw);
  }
};

static_assert(sizeof(IPv4Header) == 20, "Wrong IPv4 header size");
static_assert(alignof(IPv4Header) == 1, "Wrong IPv4 header alignment");

} // namespace vbvx
