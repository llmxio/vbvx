#pragma once

#include <bit>
#include <cstdint>
#include <span>

#include "utils.hxx"

namespace vbvx {

/**
 * @brief Ethernet frame EtherType values (network byte order).
 *
 * @see IANA registry (EtherType / Ethernet Numbers):
 *   https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
 * @see RFC894 (Ethernet encapsulation of IP datagrams):
 *   https://datatracker.ietf.org/doc/html/rfc894
 */
enum class EtherType : uint16_t {
  IPv4 = 0x0800,
  ARP = 0x0806,
  VLAN = 0x8100,
  IPv6 = 0x86DD
};

/**
 * @brief Ethernet frame header (14 bytes).
 *
 * @see IANA registry (Ethernet numbers / EtherType):
 *   https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
 * @see RFC RFC894 (Ethernet encapsulation of IP datagrams):
 *   https://datatracker.ietf.org/doc/html/rfc894
 */
struct [[gnu::packed]] EtherHeader {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type_be;

  constexpr auto dst_mac() const noexcept -> std::span<const uint8_t, 6> {
    return std::span<const uint8_t, 6>(dst, 6);
  }

  constexpr auto src_mac() const noexcept -> std::span<const uint8_t, 6> {
    return std::span<const uint8_t, 6>(src, 6);
  }

  constexpr auto type() const noexcept -> uint16_t { return autoswap(type_be); }
};

static_assert(sizeof(EtherHeader) == 14, "Wrong Ethernet header size");
static_assert(alignof(EtherHeader) == 1, "Wrong Ethernet header alignment");

/**
 * @brief VLAN Priority Code Point (PCP) values (3 bits).
 *
 * @see IEEE 802.1Q and IANA Ethernet numbers. IANA:
 *   https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
 * @see IEEE 802.1Q:
 *   https://standards.ieee.org/standard/802_1Q-2018.html
 */
enum class VlanPcp : uint8_t {
  p0 = 0,
  p1 = 1,
  p2 = 2,
  p3 = 3,
  p4 = 4,
  p5 = 5,
  p6 = 6,
  p7 = 7
};

/**
 * @brief VLAN Tag Control Information (TCI) helpers and layout.
 *
 * @see IANA (EtherType 802.1Q / 0x8100):
 *   https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
 * @see (EtherType 0x8100). IEEE 802.1Q:
 *   https://standards.ieee.org/standard/802_1Q-2018.html
 */
struct [[gnu::packed]] VlanTci {
  uint16_t raw{};

  constexpr auto pcp() const noexcept -> VlanPcp {
    return static_cast<VlanPcp>((raw >> 13) & 0x7u);
  }

  constexpr bool dei() const noexcept { return ((raw >> 12) & 0x1u) != 0; }

  constexpr auto vid() const noexcept -> uint16_t {
    return static_cast<uint16_t>(raw & 0x0FFFu);
  }

  constexpr void set_pcp(VlanPcp v) noexcept {
    raw = static_cast<uint16_t>((raw & 0x1FFFu) | ((uint16_t(v) & 0x7u) << 13));
  }

  constexpr void set_dei(bool v) noexcept {
    raw = static_cast<uint16_t>((raw & 0xEFFFu) | (uint16_t(v ? 1 : 0) << 12));
  }

  constexpr void set_vid(uint16_t v) noexcept {
    raw = static_cast<uint16_t>((raw & 0xF000u) | (v & 0x0FFFu));
  }
};

/**
 * @brief VLAN (802.1Q) header (4 bytes after Ethernet header).
 *
 * @see IANA (EtherType 802.1Q / 0x8100):
 *   https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml
 * @see IEEE 802.1Q for 802.1Q VLAN tag format:
 *   https://standards.ieee.org/standard/802_1Q-2018.html
 */
struct [[gnu::packed]] VlanHeader {
  uint16_t tci_be;
  uint16_t type_be;

  constexpr auto tci() const noexcept -> uint16_t { return autoswap(tci_be); }
  constexpr auto type() const noexcept -> uint16_t { return autoswap(type_be); }
  constexpr void set_tci(uint16_t tci) noexcept { tci_be = autoswap(tci); }
  constexpr void set_type(uint16_t type) noexcept { type_be = autoswap(type); }
};

static_assert(sizeof(VlanHeader) == 4, "Wrong VLAN header size");
static_assert(alignof(VlanHeader) == 1, "Wrong VLAN header alignment");

} // namespace vbvx
