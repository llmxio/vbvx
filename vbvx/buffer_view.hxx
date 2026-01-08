#pragma once

#include <concepts>
#include <optional>
#include <span>
#include <utility>
#include <cstring>

#include "header_view.hxx"

#include "arp.hxx"
#include "ether.hxx"
#include "icmp4.hxx"
#include "icmp6.hxx"
#include "ip_protocol.hxx"
#include "ip4_header.hxx"
#include "ip6_header.hxx"
#include "srv6_header.hxx"
#include "tcp_header.hxx"
#include "udp_header.hxx"

namespace vbvx {

/**
 * @brief A view over a packet buffer providing access to various protocol
 * headers.
 */
class BufferView {
  using buffer_t = uint8_t;

public:
  constexpr BufferView(const void* data, uint16_t length) noexcept
      : data_{static_cast<const buffer_t*>(data)}, length_{length} {}

  /** @brief Get the underlying buffer data as a span. */
  constexpr auto data() const noexcept -> std::span<const buffer_t> {
    if (!data_) {
      return {};
    }
    return {data_, length_};
  }

  /** @brief Get the length of the buffer. */
  constexpr auto length() const noexcept -> uint16_t { return length_; }

  /** @brief Get Ethernet header view. */
  constexpr auto ether_header() const noexcept -> HeaderView<EtherHeader> {
    return header_at<EtherHeader>(0);
  }

  /** @brief Get the EtherType of the packet for possible VLAN tag. */
  constexpr auto ether_type() const noexcept -> std::optional<EtherType> {
    auto eth = ether_header();
    if (!eth) {
      return std::nullopt;
    }

    auto type = eth->type();
    if (type == std::to_underlying(EtherType::VLAN)) {
      auto vlan = vlan_header();
      if (!vlan) {
        return std::nullopt;
      }
      return static_cast<EtherType>(vlan->type());
    }

    return static_cast<EtherType>(type);
  }

  /** @brief Get VLAN header view. */
  constexpr auto vlan_header() const noexcept -> HeaderView<VlanHeader> {
    auto eth = ether_header();
    if (!eth) {
      return {};
    }

    auto type = eth->type();
    if (type != std::to_underlying(EtherType::VLAN)) {
      return {};
    }

    return header_at<VlanHeader>(sizeof(EtherHeader));
  }

  /** @brief Get VLAN ID if VLAN tag is present. */
  constexpr auto vlan_id() const noexcept -> std::optional<uint16_t> {
    auto vlan = vlan_header();
    if (!vlan) {
      return std::nullopt;
    }
    return static_cast<uint16_t>(vlan->tci() & 0x0FFFu);
  }

  /** @brief Get the offset of the Layer 3 header. */
  constexpr auto l3_offset() const noexcept -> uint16_t {
    auto eth = ether_header();
    if (!eth) {
      return 0;
    }
    auto type = eth->type();
    return (type == std::to_underlying(EtherType::VLAN))
               ? static_cast<uint16_t>(sizeof(EtherHeader) + sizeof(VlanHeader))
               : static_cast<uint16_t>(sizeof(EtherHeader));
  }

  /** @brief Get ARP header view. */
  constexpr auto arp_header() const noexcept -> HeaderView<ArpHeader> {
    auto et = ether_type();
    if (!et || *et != EtherType::ARP) {
      return {};
    }
    return header_at<ArpHeader>(l3_offset());
  }

  /** @brief Get IPv4 header view. */
  constexpr auto ip4_header() const noexcept -> HeaderView<IPv4Header> {
    auto et = ether_type();
    if (!et || *et != EtherType::IPv4) {
      return {};
    }
    return header_at<IPv4Header>(l3_offset());
  }

  /** @brief Get IPv6 header view. */
  constexpr auto ip6_header() const noexcept -> HeaderView<IPv6Header> {
    auto et = ether_type();
    if (!et || *et != EtherType::IPv6) {
      return {};
    }
    return header_at<IPv6Header>(l3_offset());
  }

  /** @brief Get the number of bytes in the IPv4 header. */
  constexpr auto ip4_ihl_bytes() const noexcept -> std::optional<uint8_t> {
    auto ip = ip4_header();
    if (!ip) {
      return std::nullopt;
    }
    const buffer_t ihl = static_cast<uint8_t>(ip->version_ihl & 0x0Fu);
    const buffer_t bytes = static_cast<uint8_t>(ihl * 4u);
    if (bytes < 20) {
      return std::nullopt;
    }
    return bytes;
  }

  /** @brief Get the IP protocol (IPv4 or IPv6). */
  constexpr auto ip_protocol() const noexcept -> std::optional<IpProtocol> {
    if (auto ip4 = ip4_header()) {
      return static_cast<IpProtocol>(ip4->protocol);
    }
    if (auto ip6 = ip6_header()) {
      return static_cast<IpProtocol>(ip6->next_header);
    }
    return std::nullopt;
  }

  /** @brief Get the offset of the Layer 4 header. */
  constexpr auto l4_offset() const noexcept -> std::optional<uint16_t> {
    if (ip4_header()) {
      auto ihl = ip4_ihl_bytes();
      if (!ihl) {
        return std::nullopt;
      }
      return l3_offset() + *ihl;
    }
    if (ip6_header()) {
      return l3_offset() + static_cast<uint16_t>(sizeof(IPv6Header));
    }
    return std::nullopt;
  }

  /** @brief Get TCP header view. */
  constexpr auto tcp_header() const noexcept -> HeaderView<TCPHeader> {
    auto proto = ip_protocol();
    auto off = l4_offset();
    if (!proto || !off) {
      return {};
    }
    if (*proto != IpProtocol::TCP) {
      return {};
    }
    return header_at<TCPHeader>(*off);
  }

  /** @brief Get UDP header view. */
  constexpr auto udp_header() const noexcept -> HeaderView<UDPHeader> {
    auto proto = ip_protocol();
    auto off = l4_offset();
    if (!proto || !off) {
      return {};
    }
    if (*proto != IpProtocol::UDP) {
      return {};
    }
    return header_at<UDPHeader>(*off);
  }

  /** @brief Get ICMPv4 header view. */
  constexpr auto icmp4_header() const noexcept -> HeaderView<ICMPv4Header> {
    auto proto = ip_protocol();
    auto off = l4_offset();
    if (!proto || !off || *proto != IpProtocol::ICMPv4) {
      return {};
    }

    return header_at<ICMPv4Header>(*off);
  }

  /** @brief Get ICMPv6 header view. */
  constexpr auto icmp6_header() const noexcept -> HeaderView<ICMPv6Header> {
    auto proto = ip_protocol();
    auto off = l4_offset();
    if (!proto || !off || *proto != IpProtocol::ICMPv6) {
      return {};
    }

    return header_at<ICMPv6Header>(*off);
  }

  /** @brief Get SRv6 Header view if present. */
  constexpr auto srv6_header() const noexcept -> HeaderView<SRv6Header> {
    auto ip6 = ip6_header();
    if (!ip6) {
      return {};
    }
    if (ip6->next_header != static_cast<uint8_t>(IpProtocol::IPv6_Route)) {
      return {};
    }

    auto offset = static_cast<uint16_t>(l3_offset() + sizeof(IPv6Header));
    return header_at<SRv6Header>(offset);
  }

private:
  template <WireHeader H>
  constexpr auto header_at(uint16_t offset) const noexcept -> HeaderView<H> {
    auto _data = data();
    if (offset + sizeof(H) > _data.size()) {
      return {};
    }
    return HeaderView<H>{_data.data() + offset};
  }

  const buffer_t* data_{};
  uint16_t length_{};
};

} // namespace vbvx
