#pragma once

#include <cstdint>

#include "auto_swap.hxx"

namespace vbvx {

/**
 * @brief UDP header (8 bytes).
 *
 * @see IANA Service Name and Transport Protocol Port Number Registry:
 *   https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
 * @see RFC 768 - User Datagram Protocol:
 *   https://datatracker.ietf.org/doc/html/rfc768
 */
struct [[gnu::packed]] UDPHeader {
  uint16_t src_port_be;
  uint16_t dst_port_be;
  uint16_t length_be;
  uint16_t checksum_be;

  constexpr auto src_port() const noexcept -> uint16_t {
    return autoswap(src_port_be);
  }

  constexpr auto dst_port() const noexcept -> uint16_t {
    return autoswap(dst_port_be);
  }

  constexpr auto length() const noexcept -> uint16_t {
    return autoswap(length_be);
  }

  constexpr auto checksum() const noexcept -> uint16_t {
    return autoswap(checksum_be);
  }

  void set_src_port(uint16_t v) noexcept { src_port_be = autoswap(v); }
  void set_dst_port(uint16_t v) noexcept { dst_port_be = autoswap(v); }
  void set_length(uint16_t v) noexcept { length_be = autoswap(v); }
  void set_checksum(uint16_t v) noexcept { checksum_be = autoswap(v); }
};

static_assert(sizeof(UDPHeader) == 8, "Wrong UDP header size");
static_assert(alignof(UDPHeader) == 1, "Wrong UDP header alignment");

} // namespace vbvx
