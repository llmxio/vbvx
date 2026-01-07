#pragma once

#include <bit>
#include <cstdint>
#include <optional>

#include "auto_swap.hxx"

namespace vbvx {

/**
 * @brief ICMPv4 Type Numbers
 *
 * @see IANA "ICMP Type Numbers" registry:
 *   https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
 * @see RFC 792:
 *   https://datatracker.ietf.org/doc/html/rfc792
 */
enum class ICMPv4Type : uint8_t {
  EchoReply = 0,
  DestinationUnreachable = 3,
  SourceQuench = 4,
  Redirect = 5,
  AlternateHostAddress = 6,
  EchoRequest = 8,
  RouterAdvertisement = 9,
  RouterSolicitation = 10,
  TimeExceeded = 11,
  ParameterProblem = 12,
  Timestamp = 13,
  TimestampReply = 14,
  InformationRequest = 15,
  InformationReply = 16,
  AddressMaskRequest = 17,
  AddressMaskReply = 18,
  ReservedForSecurity = 19,
  Traceroute = 30,
  DatagramConversionError = 31,
  MobileHostRedirect = 32,
  IPv6WhereAreYou = 33,
  IPv6IamHere = 34,
  MobileRegistrationRequest = 35,
  MobileRegistrationReply = 36,
  DomainNameRequest = 37,
  DomainNameReply = 38,
  SKIP = 39,
  Photuris = 40,
  MobilityExperimental = 41,
  ExtendedEchoRequest = 42,
  ExtendedEchoReply = 43,
  Experiment1 = 253,
  Experiment2 = 254,
  Reserved = 255
};

/** @brief ICMP header (type, code, checksum) (4 bytes).
 *  IANA: ICMP Parameters
 * https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml IETF
 * RFC: RFC792 https://datatracker.ietf.org/doc/html/rfc792
 */
struct [[gnu::packed]] ICMPHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum_be;

  constexpr auto type_u8() const noexcept -> uint8_t { return type; }
  constexpr auto code_u8() const noexcept -> uint8_t { return code; }

  constexpr auto checksum() const noexcept -> uint16_t {
    return autoswap(checksum_be);
  }

  constexpr auto type_known() const noexcept -> std::optional<ICMPv4Type> {
    using enum ICMPv4Type;

    switch (type) {
    case 0: return EchoReply;
    case 3: return DestinationUnreachable;
    case 4: return SourceQuench;
    case 5: return Redirect;
    case 6: return AlternateHostAddress;
    case 8: return EchoRequest;
    case 9: return RouterAdvertisement;
    case 10: return RouterSolicitation;
    case 11: return TimeExceeded;
    case 12: return ParameterProblem;
    case 13: return Timestamp;
    case 14: return TimestampReply;
    case 15: return InformationRequest;
    case 16: return InformationReply;
    case 17: return AddressMaskRequest;
    case 18: return AddressMaskReply;
    case 19: return ReservedForSecurity;
    case 30: return Traceroute;
    case 31: return DatagramConversionError;
    case 32: return MobileHostRedirect;
    case 33: return IPv6WhereAreYou;
    case 34: return IPv6IamHere;
    case 35: return MobileRegistrationRequest;
    case 36: return MobileRegistrationReply;
    case 37: return DomainNameRequest;
    case 38: return DomainNameReply;
    case 39: return SKIP;
    case 40: return Photuris;
    case 41: return MobilityExperimental;
    case 42: return ExtendedEchoRequest;
    case 43: return ExtendedEchoReply;
    case 253: return Experiment1;
    case 254: return Experiment2;
    case 255: return Reserved;
    default: return std::nullopt;
    }
  }

  constexpr void set_checksum(uint16_t v) noexcept {
    checksum_be = autoswap(v);
  }
};

static_assert(sizeof(ICMPHeader) == 4, "Wrong ICMP header size");
static_assert(alignof(ICMPHeader) == 1, "Wrong ICMP header alignment");

} // namespace vbvx
