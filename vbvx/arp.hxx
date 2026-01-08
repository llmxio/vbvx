#pragma once

#include <bit>
#include <cstdint>
#include <span>
#include <cstring>

#include "utils.hxx"
#include "ether.hxx"

namespace vbvx {

/** @brief ARP hardware type values. */
enum class ArpHType : uint16_t { Ethernet = 1 };

/** @brief ARP opcode values. */
enum class ArpOpCode : uint16_t { Request = 1, Reply = 2 };

/**
 * @brief Address Resolution Protocol (ARP) header
 *
 * @see IANA ARP Parameters:
 *   https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
 * @see IETF RFC 826 (Ethernet Address Resolution Protocol):
 *   https://datatracker.ietf.org/doc/html/rfc826
 */
struct [[gnu::packed]] ArpHeader {
  uint16_t htype_be;
  uint16_t ptype_be;
  uint8_t hlen;
  uint8_t plen;
  uint16_t oper_be;
  uint8_t sha[6];
  uint8_t spa[4];
  uint8_t tha[6];
  uint8_t tpa[4];

  constexpr auto htype() const noexcept -> ArpHType {
    return static_cast<ArpHType>(autoswap(htype_be));
  }

  constexpr auto ptype() const noexcept -> EtherType {
    return static_cast<EtherType>(autoswap(ptype_be));
  }

  constexpr auto opcode() const noexcept -> ArpOpCode {
    return static_cast<ArpOpCode>(autoswap(oper_be));
  }

  constexpr auto sender_mac() const noexcept -> std::span<const uint8_t, 6> {
    return std::span<const uint8_t, 6>{sha, sha + 6};
  }

  constexpr auto target_mac() const noexcept -> std::span<const uint8_t, 6> {
    return std::span<const uint8_t, 6>{tha, tha + 6};
  }

  constexpr auto sender_ipv4() const noexcept -> std::span<const uint8_t, 4> {
    return std::span<const uint8_t, 4>{spa, spa + 4};
  }

  constexpr auto target_ipv4() const noexcept -> std::span<const uint8_t, 4> {
    return std::span<const uint8_t, 4>{tpa, tpa + 4};
  }

  constexpr auto sender_ipv4_host() const noexcept -> uint32_t {
    return autoswap(read_from_bytes<uint32_t>(spa));
  }

  constexpr auto target_ipv4_host() const noexcept -> uint32_t {
    return autoswap(read_from_bytes<uint32_t>(tpa));
  }

  constexpr void set_opcode(ArpOpCode code) noexcept {
    oper_be = autoswap(static_cast<uint16_t>(code));
  }
};

static_assert(sizeof(ArpHeader) == 28, "Wrong ARP header size");
static_assert(alignof(ArpHeader) == 1, "Wrong ARP header alignment");

} // namespace vbvx
