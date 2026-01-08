#pragma once

#include <cstdint>
#include <span>

#include "auto_swap.hxx"

namespace vbvx {

/** @brief SRv6 Segment Routing Header (SRH) TLV types. */
enum class SRv6TlvType : uint8_t { Pad1 = 0u, PadN = 4u, Hmac = 5u };

/**
 * @brief IPv6 Segment Routing Header (SRH) as defined in RFC 8754.
 *
 * @see IANA IPv6 Parameters — Segment Routing Header TLVs & Routing Types:
 *   https://www.iana.org/assignments/ipv6-parameters/)
 * @see RFC 8754:
 *   https://datatracker.ietf.org/doc/rfc8754/
 */
struct [[gnu::packed]] SRv6Header {
  uint8_t next_header;
  uint8_t hdr_ext_len;
  uint8_t routing_type;
  uint8_t segments_left;
  uint8_t last_entry;
  uint8_t flags;
  uint16_t tag_be;

  constexpr auto header_length_bytes() const noexcept -> uint16_t {
    return ((static_cast<uint16_t>(hdr_ext_len) + 1u) * 8u);
  }

  constexpr auto last_entry_index() const noexcept -> uint8_t {
    return last_entry;
  }

  constexpr auto segments_count() const noexcept -> uint8_t {
    return static_cast<uint8_t>(static_cast<uint8_t>(last_entry) + 1u);
  }

  constexpr auto tag() const noexcept -> uint16_t { return autoswap(tag_be); }

  constexpr auto routing_type_value() const noexcept -> uint8_t {
    return routing_type;
  }

  constexpr bool is_valid_routing_type() const noexcept {
    return routing_type == 4u;
  }

  constexpr auto segment_list_ptr() const noexcept -> const uint8_t* {
    return reinterpret_cast<const uint8_t*>(this) + 8u;
  }

  constexpr auto segment_at(uint8_t idx) const noexcept
      -> std::span<const uint8_t, 16> {
    return std::span<const uint8_t, 16>{
        segment_list_ptr() + (static_cast<size_t>(idx) * 16u), 16u};
  }

  constexpr auto segment_list_bytes_len() const noexcept -> size_t {
    return static_cast<size_t>(segments_count()) * 16u;
  }

  constexpr auto tlv_offset() const noexcept -> size_t {
    return 8u + segment_list_bytes_len();
  }

  constexpr auto tlv_bytes_len() const noexcept -> size_t {
    auto total = header_length_bytes();
    if (total <= tlv_offset()) {
      return 0u;
    }
    return static_cast<size_t>(total - tlv_offset());
  }

  constexpr auto tlv_first_ptr() const noexcept -> const uint8_t* {
    return reinterpret_cast<const uint8_t*>(this) + tlv_offset();
  }
};

/** @brief TLV view returned by the iterator. */
struct SRv6Tlv {
  uint8_t type;
  uint8_t length;
  const uint8_t* value;
  size_t total_len;
};

/** @brief Iterator over TLVs in an SRH's TLV area. Does not allocate. */
class SRv6TlvIterator {
public:
  constexpr SRv6TlvIterator(const uint8_t* ptr, size_t len) noexcept
      : ptr_{ptr}, len_{len}, pos_{0} {}

  constexpr bool next(SRv6Tlv& out) noexcept {
    if (pos_ >= len_) {
      return false;
    }

    const uint8_t t = ptr_[pos_];
    if (t == static_cast<uint8_t>(SRv6TlvType::Pad1)) {
      out = SRv6Tlv{t, 0, nullptr, 1u};
      pos_ += 1u;
      return true;
    }

    // Need at least type + length
    if (pos_ + 2u > len_) {
      return false;
    }

    const uint8_t len = ptr_[pos_ + 1u];
    if (static_cast<size_t>(pos_) + 2u + static_cast<size_t>(len) > len_) {
      return false;
    }

    out = SRv6Tlv{t, len, ptr_ + pos_ + 2u, 2u + static_cast<size_t>(len)};
    pos_ += out.total_len;
    return true;
  }

private:
  const uint8_t* ptr_;
  size_t len_;
  size_t pos_;
};

/**
 * @brief HMAC TLV view for type==5 (HMAC). The 'value' pointer is the TLV
 * variable data where the first two bytes are D/reserved, followed by a 4-octet
 * HMAC Key ID, then the HMAC bytes.
 */
struct SRv6HmacTlvView {
  const uint8_t* value;
  uint8_t length; // length of the variable data (as in the TLV length field)

  constexpr bool valid() const noexcept { return value && (length >= 6u); }

  constexpr bool d_bit() const noexcept {
    if (!valid())
      return false;
    uint16_t b;
    std::memcpy(&b, value, sizeof(b));
    return ((autoswap(b) >> 15) & 0x1u) != 0u;
  }

  constexpr auto key_id() const noexcept -> uint32_t {
    if (!valid())
      return 0u;
    uint32_t v;
    std::memcpy(&v, value + 2u, sizeof(v));
    return autoswap(v);
  }

  constexpr auto hmac() const noexcept -> std::span<const uint8_t> {
    if (!valid())
      return {};
    const uint8_t* p = value + 6u;
    return std::span<const uint8_t>{p, static_cast<size_t>(length - 6u)};
  }
};

static_assert(sizeof(SRv6Header) == 8, "Wrong SRH header size");
static_assert(alignof(SRv6Header) == 1, "Wrong SRH header alignment");

} // namespace vbvx
