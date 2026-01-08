#pragma once

#include <bit>
#include <cstdint>
#include <optional>

#include "utils.hxx"

namespace vbvx {

/**
 * @brief ICMPv6 Type Numbers
 *
 * @see IANA "ICMPv6 Parameters" registry:
 *   https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
 * @see RFC 4443:
 *   https://datatracker.ietf.org/doc/html/rfc4443
 */
enum class ICMPv6Type : uint8_t {
  DestinationUnreachable = 1,
  PacketTooBig = 2,
  TimeExceeded = 3,
  ParameterProblem = 4,

  // 5-99 unassigned
  PrivateExperiment100 = 100,
  PrivateExperiment101 = 101,

  // Informational messages
  EchoRequest = 128,
  EchoReply = 129,
  MulticastListenerQuery = 130,
  MulticastListenerReport = 131,
  MulticastListenerDone = 132,
  RouterSolicitation = 133,
  RouterAdvertisement = 134,
  NeighborSolicitation = 135,
  NeighborAdvertisement = 136,
  RedirectMessage = 137,
  RouterRenumbering = 138,
  NodeInformationQuery = 139,
  NodeInformationResponse = 140,
  InverseNeighborDiscoverySolicitation = 141,
  InverseNeighborDiscoveryAdvertisement = 142,
  Version2MulticastListenerReport = 143,
  HomeAgentAddressDiscoveryRequest = 144,
  HomeAgentAddressDiscoveryReply = 145,
  MobilePrefixSolicitation = 146,
  MobilePrefixAdvertisement = 147,
  MobilityExperimental = 150,
  MulticastRouterAdvertisement = 151,
  MulticastRouterSolicitation = 152,
  MulticastRouterTermination = 153,
  FMIPv6 = 154,
  RPLControlMessage = 155,
  ILNPv6LocatorUpdate = 156,
  DuplicateAddressRequest = 157,
  DuplicateAddressConfirmation = 158,
  MPLControlMessage = 159,
  ExtendedEchoRequest = 160,
  ExtendedEchoReply = 161,

  PrivateExperiment200 = 200,
  PrivateExperiment201 = 201,

  Reserved = 255
};

/**
 * @brief ICMPv6 header (type, code, checksum) (4 bytes).
 *
 * @see IANA ICMPv6 Parameters:
 *   https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml IETF
 * @see RFC 4443:
 *   https://datatracker.ietf.org/doc/html/rfc4443
 */
struct [[gnu::packed]] ICMPv6Header {
  uint8_t type;
  uint8_t code;
  uint16_t checksum_be;

  constexpr auto type_u8() const noexcept -> uint8_t { return type; }
  constexpr auto code_u8() const noexcept -> uint8_t { return code; }

  constexpr auto checksum() const noexcept -> uint16_t {
    return autoswap(checksum_be);
  }

  constexpr auto type_known() const noexcept -> std::optional<ICMPv6Type> {
    using enum ICMPv6Type;

    switch (type) {
    case 1: return DestinationUnreachable;
    case 2: return PacketTooBig;
    case 3: return TimeExceeded;
    case 4: return ParameterProblem;
    case 100: return PrivateExperiment100;
    case 101: return PrivateExperiment101;
    case 128: return EchoRequest;
    case 129: return EchoReply;
    case 130: return MulticastListenerQuery;
    case 131: return MulticastListenerReport;
    case 132: return MulticastListenerDone;
    case 133: return RouterSolicitation;
    case 134: return RouterAdvertisement;
    case 135: return NeighborSolicitation;
    case 136: return NeighborAdvertisement;
    case 137: return RedirectMessage;
    case 138: return RouterRenumbering;
    case 139: return NodeInformationQuery;
    case 140: return NodeInformationResponse;
    case 141: return InverseNeighborDiscoverySolicitation;
    case 142: return InverseNeighborDiscoveryAdvertisement;
    case 143: return Version2MulticastListenerReport;
    case 144: return HomeAgentAddressDiscoveryRequest;
    case 145: return HomeAgentAddressDiscoveryReply;
    case 146: return MobilePrefixSolicitation;
    case 147: return MobilePrefixAdvertisement;
    case 150: return MobilityExperimental;
    case 151: return MulticastRouterAdvertisement;
    case 152: return MulticastRouterSolicitation;
    case 153: return MulticastRouterTermination;
    case 154: return FMIPv6;
    case 155: return RPLControlMessage;
    case 156: return ILNPv6LocatorUpdate;
    case 157: return DuplicateAddressRequest;
    case 158: return DuplicateAddressConfirmation;
    case 159: return MPLControlMessage;
    case 160: return ExtendedEchoRequest;
    case 161: return ExtendedEchoReply;
    case 200: return PrivateExperiment200;
    case 201: return PrivateExperiment201;
    case 255: return Reserved;
    default: return std::nullopt;
    }
  }

  constexpr void set_checksum(uint16_t v) noexcept {
    checksum_be = autoswap(v);
  }
};

static_assert(sizeof(ICMPv6Header) == 4, "Wrong ICMPv6 header size");
static_assert(alignof(ICMPv6Header) == 1, "Wrong ICMPv6 header alignment");

} // namespace vbvx
