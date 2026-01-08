#pragma once

#include <cstdint>

#include "utils.hxx"
#include "flags_view.hxx"

namespace vbvx {

enum class TCPFlags : uint8_t {
  None = 0,
  FIN = 0x01,
  SYN = 0x02,
  RST = 0x04,
  PSH = 0x08,
  ACK = 0x10,
  URG = 0x20,
  ECE = 0x40,
  CWR = 0x80
};

template <> struct enable_bitmask_operators<TCPFlags> : std::true_type {};

/**
 * @brief TCP header (minimum 20 bytes).
 *
 * @see IANA Service Name and Transport Protocol Port Number Registry:
 *   https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
 * @see IETF RFC 793 (Transmission Control Protocol):
 *   https://datatracker.ietf.org/doc/html/rfc793
 */
struct [[gnu::packed]] TCPHeader {
  uint16_t src_port_be;
  uint16_t dst_port_be;
  uint32_t seq_num_be;
  uint32_t ack_num_be;
  uint8_t data_offset;
  uint8_t tcp_flags;
  uint16_t window_be;
  uint16_t checksum_be;
  uint16_t urgent_ptr_be;

  constexpr auto src_port() const noexcept -> uint16_t {
    return autoswap(src_port_be);
  }

  constexpr auto dst_port() const noexcept -> uint16_t {
    return autoswap(dst_port_be);
  }

  constexpr auto seq_num() const noexcept -> uint32_t {
    return autoswap(seq_num_be);
  }

  constexpr auto ack_num() const noexcept -> uint32_t {
    return autoswap(ack_num_be);
  }

  constexpr auto header_words() const noexcept -> uint8_t {
    return static_cast<uint8_t>((data_offset >> 4) & 0x0Fu);
  }

  constexpr auto header_bytes() const noexcept -> uint16_t {
    return static_cast<uint16_t>(header_words() * 4u);
  }

  constexpr auto flags() const noexcept -> TCPFlags {
    return static_cast<TCPFlags>(tcp_flags);
  }

  constexpr auto window() const noexcept -> uint16_t {
    return autoswap(window_be);
  }
  constexpr auto checksum() const noexcept -> uint16_t {
    return autoswap(checksum_be);
  }

  constexpr auto urgent_ptr() const noexcept -> uint16_t {
    return autoswap(urgent_ptr_be);
  }

  constexpr void set_src_port(uint16_t v) noexcept {
    src_port_be = autoswap(v);
  }

  constexpr void set_dst_port(uint16_t v) noexcept {
    dst_port_be = autoswap(v);
  }

  constexpr void set_seq_num(uint32_t v) noexcept { seq_num_be = autoswap(v); }
  constexpr void set_ack_num(uint32_t v) noexcept { ack_num_be = autoswap(v); }
  constexpr void set_flags(uint8_t f) noexcept { tcp_flags = f; }
  constexpr void set_window(uint16_t v) noexcept { window_be = autoswap(v); }

  constexpr void set_checksum(uint16_t v) noexcept {
    checksum_be = autoswap(v);
  }

  constexpr void set_urgent_ptr(uint16_t v) noexcept {
    urgent_ptr_be = autoswap(v);
  }

  constexpr bool valid_min_size() const noexcept {
    return header_bytes() >= 20;
  }
};

static_assert(sizeof(TCPHeader) == 20, "Wrong TCP header size");
static_assert(alignof(TCPHeader) == 1, "Wrong TCP header alignment");

} // namespace vbvx
