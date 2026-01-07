#pragma once

#include <cstdint>

#include "auto_swap.hxx"
#include "ip_protocol.hxx"

namespace vbvx {

/**
 * @brief IPv6 header (40 bytes).
 *
 * @see IANA IPv6 Parameters:
 *   https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
 * @see IETF RFC 8200 (Internet Protocol, Version 6 (IPv6) Specification):
 *   https://datatracker.ietf.org/doc/html/rfc8200
 */
struct [[gnu::packed]] IPv6Header {
  uint32_t ver_tc_flow_be;
  uint16_t payload_length_be;
  uint8_t next_header;
  uint8_t hop_limit;
  uint8_t src_addr[16];
  uint8_t dst_addr[16];

  constexpr auto ver_tc_flow_host() const noexcept -> uint32_t {
    return autoswap(ver_tc_flow_be);
  }

  constexpr auto version() const noexcept -> uint8_t {
    return static_cast<uint8_t>((ver_tc_flow_host() >> 28) & 0x0Fu);
  }

  constexpr auto traffic_class() const noexcept -> uint8_t {
    return static_cast<uint8_t>((ver_tc_flow_host() >> 20) & 0xFFu);
  }

  constexpr auto flow_label() const noexcept -> uint32_t {
    return static_cast<uint32_t>(ver_tc_flow_host() & 0x000FFFFFu);
  }

  constexpr auto payload_length() const noexcept -> uint16_t {
    return autoswap(payload_length_be);
  }

  constexpr auto l4_protocol() const noexcept -> IpProtocol {
    return static_cast<IpProtocol>(next_header);
  }

  constexpr auto src_bytes() const noexcept -> std::span<const uint8_t, 16> {
    return std::span<const uint8_t, 16>{src_addr, 16};
  }

  constexpr auto dst_bytes() const noexcept -> std::span<const uint8_t, 16> {
    return std::span<const uint8_t, 16>{dst_addr, 16};
  }
};

static_assert(sizeof(IPv6Header) == 40, "Wrong IPv6 header size");
static_assert(alignof(IPv6Header) == 1, "Wrong IPv6 header alignment");

} // namespace vbvx
