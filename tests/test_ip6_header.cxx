#include <gtest/gtest.h>

#include "header_view.hxx"
#include "auto_swap.hxx"
#include "buffer_view.hxx"
#include "vbvx/ether.hxx"
#include "vbvx/ip_protocol.hxx"
#include "vbvx/ip6_header.hxx"
#include "vbvx/udp_header.hxx"
#include "vbvx/tcp_header.hxx"

#include <array>
#include <bit>
#include <cstring>
#include <type_traits>

using namespace vbvx;

TEST(IPv6HeaderTest, DefaultsAreZero) {
  IPv6Header h{};
  // default constructed -> zeros
  EXPECT_EQ(h.version(), 0u);
  EXPECT_EQ(h.traffic_class(), 0u);
  EXPECT_EQ(h.flow_label(), 0u);
  EXPECT_EQ(h.payload_length(), 0u);
  EXPECT_EQ(h.l4_protocol(), IpProtocol::HOPOPT);
}

TEST(IPv6HeaderTest, VersionTrafficClassAndFlowLabelParsing) {
  IPv6Header tmp{};
  constexpr uint8_t ver = 6u;
  constexpr uint8_t tc = 0xABu;       // 8 bits
  constexpr uint32_t flow = 0xABCDEu; // 20 bits

  const uint32_t host = (static_cast<uint32_t>(ver) << 28) |
                        (static_cast<uint32_t>(tc) << 20) |
                        (flow & 0x000FFFFFu);

  tmp.ver_tc_flow_be = autoswap(static_cast<uint32_t>(host));

  std::array<uint8_t, sizeof(IPv6Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv6Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->ver_tc_flow_host(), host);
  EXPECT_EQ(hv->version(), ver);
  EXPECT_EQ(hv->traffic_class(), tc);
  EXPECT_EQ(hv->flow_label(), (flow & 0x000FFFFFu));
}

TEST(IPv6HeaderTest, MaxTrafficClassAndFlowLabel) {
  IPv6Header tmp{};
  constexpr uint8_t ver = 6u;
  constexpr uint8_t tc = 0xFFu;       // max 8 bits
  constexpr uint32_t flow = 0xFFFFFu; // max 20 bits

  const uint32_t host = (static_cast<uint32_t>(ver) << 28) |
                        (static_cast<uint32_t>(tc) << 20) |
                        (flow & 0x000FFFFFu);

  tmp.ver_tc_flow_be = autoswap(static_cast<uint32_t>(host));

  std::array<uint8_t, sizeof(IPv6Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv6Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->traffic_class(), tc);
  EXPECT_EQ(hv->flow_label(), flow);
}

TEST(IPv6HeaderTest, PayloadLengthAndL4ProtocolParsing) {
  IPv6Header tmp{};
  tmp.payload_length_be = autoswap(static_cast<uint16_t>(0x1234u));
  tmp.next_header = static_cast<uint8_t>(IpProtocol::UDP);

  std::array<uint8_t, sizeof(IPv6Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv6Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->payload_length(), 0x1234u);
  EXPECT_EQ(hv->l4_protocol(), IpProtocol::UDP);
}

TEST(IPv6HeaderTest, SrcAndDstBytesRoundTrip) {
  IPv6Header tmp{};
  for (size_t i = 0; i < 16; ++i) {
    tmp.src_addr[i] = static_cast<uint8_t>(i + 1);
    tmp.dst_addr[i] = static_cast<uint8_t>(0xF0 + i);
  }

  std::array<uint8_t, sizeof(IPv6Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv6Header> hv(raw.data());
  ASSERT_TRUE(hv);

  const auto s = hv->src_bytes();
  const auto d = hv->dst_bytes();
  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ(s[i], static_cast<uint8_t>(i + 1));
    EXPECT_EQ(d[i], static_cast<uint8_t>(0xF0 + i));
  }
}

TEST(IPv6HeaderTest, SizeAndAlignment) {
  // Verify ABI assumptions
  EXPECT_EQ(sizeof(IPv6Header), 40u);
  EXPECT_EQ(alignof(IPv6Header), 1u);
}

TEST(IPv6HeaderEdgeCases, NonStandardVersionIsReturned) {
  // If the version field is not 6, it should still be parsed from the top 4
  // bits
  IPv6Header tmp{};
  const uint32_t host = (static_cast<uint32_t>(0xFu) << 28);
  tmp.ver_tc_flow_be = autoswap(static_cast<uint32_t>(host));

  HeaderView<IPv6Header> hv(reinterpret_cast<const uint8_t*>(&tmp));
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->version(), 0xFu);
}

TEST(IPv6HeaderEdgeCases, HopLimitAndZeroAddresses) {
  IPv6Header tmp{};
  tmp.hop_limit = 255u;
  for (auto& b : tmp.src_addr)
    b = 0u;
  for (auto& b : tmp.dst_addr)
    b = 0u;

  std::array<uint8_t, sizeof(IPv6Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv6Header> hv(raw.data());
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->hop_limit, 255u);
  for (auto v : hv->src_bytes())
    EXPECT_EQ(v, 0u);
  for (auto v : hv->dst_bytes())
    EXPECT_EQ(v, 0u);
}

TEST(IPv6HeaderEdgeCases, PayloadLengthBoundaries) {
  IPv6Header low{};
  low.payload_length_be = autoswap(static_cast<uint16_t>(0u));
  IPv6Header high{};
  high.payload_length_be = autoswap(static_cast<uint16_t>(0xFFFFu));

  HeaderView<IPv6Header> hlo(reinterpret_cast<const uint8_t*>(&low));
  HeaderView<IPv6Header> hhi(reinterpret_cast<const uint8_t*>(&high));
  ASSERT_TRUE(hlo);
  ASSERT_TRUE(hhi);

  EXPECT_EQ(hlo->payload_length(), 0u);
  EXPECT_EQ(hhi->payload_length(), 0xFFFFu);
}

TEST(IPv6HeaderEdgeCases, NextHeaderVariants) {
  IPv6Header a{};
  a.next_header = static_cast<uint8_t>(IpProtocol::IPv6_NoNxt);
  IPv6Header b{};
  b.next_header = static_cast<uint8_t>(IpProtocol::ICMPv6);
  IPv6Header c{};
  c.next_header = static_cast<uint8_t>(250u); // unassigned/unknown value

  HeaderView<IPv6Header> ha(reinterpret_cast<const uint8_t*>(&a));
  HeaderView<IPv6Header> hb(reinterpret_cast<const uint8_t*>(&b));
  HeaderView<IPv6Header> hc(reinterpret_cast<const uint8_t*>(&c));
  ASSERT_TRUE(ha);
  ASSERT_TRUE(hb);
  ASSERT_TRUE(hc);

  EXPECT_EQ(ha->l4_protocol(), IpProtocol::IPv6_NoNxt);
  EXPECT_EQ(hb->l4_protocol(), IpProtocol::ICMPv6);
  EXPECT_EQ(hc->l4_protocol(), static_cast<IpProtocol>(250u));
}

TEST(IPv6HeaderEdgeCases, ZeroCopyReflectsMutations) {
  std::array<uint8_t, sizeof(IPv6Header)> raw{};
  // set hop limit to 1 in the array directly
  raw[7] = 1u; // hop_limit is at offset 7

  HeaderView<IPv6Header> hv(raw.data());
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->hop_limit, 1u);

  // mutate raw bytes and ensure view sees change
  raw[7] = 99u;
  EXPECT_EQ(hv->hop_limit, 99u);
}

TEST(IPv6HeaderEdgeCases, NullHeaderViewIsFalse) {
  HeaderView<IPv6Header> hv(static_cast<const IPv6Header*>(nullptr));
  EXPECT_FALSE(hv);
}

// ---------------------------------------------------------------------
// BufferView negative / malformed header tests
// ---------------------------------------------------------------------

TEST(BufferViewIPv6MalformedTest, Ipv6HeaderTooShort) {
  // Ethernet frame that claims IPv6 but is too short to contain an IPv6 header
  std::array<uint8_t, sizeof(EtherHeader) + 20> raw{};
  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_FALSE(buf.ip6_header());
  EXPECT_FALSE(buf.l4_offset());
  EXPECT_FALSE(buf.ip_protocol().has_value());
}

TEST(BufferViewIPv6MalformedTest, Ipv6HeaderPresentAndL4Offset) {
  // Enough room for IPv6 + UDP header
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(IPv6Header) + sizeof(UDPHeader);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

  auto ip = reinterpret_cast<IPv6Header*>(raw.data() + sizeof(EtherHeader));
  ip->next_header = static_cast<uint8_t>(IpProtocol::UDP);
  ip->payload_length_be = autoswap(static_cast<uint16_t>(sizeof(UDPHeader)));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip6_header());
  ASSERT_TRUE(buf.ip_protocol().has_value());
  EXPECT_EQ(buf.ip_protocol().value(), IpProtocol::UDP);
  ASSERT_TRUE(buf.l4_offset());
  EXPECT_EQ(buf.l4_offset().value(),
            static_cast<uint16_t>(sizeof(EtherHeader) + sizeof(IPv6Header)));

  auto uh = buf.udp_header();
  ASSERT_TRUE(uh);
  // default constructed UDP header fields should be zeros
  EXPECT_EQ(uh->src_port(), 0u);
  EXPECT_EQ(uh->dst_port(), 0u);
}

TEST(BufferViewIPv6MalformedTest, TcpHeaderTooShortWhenProtoIsTcp) {
  // IPv6 present but not enough bytes for a TCP header
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(IPv6Header) + 2; // too small for TCP
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

  auto ip = reinterpret_cast<IPv6Header*>(raw.data() + sizeof(EtherHeader));
  ip->next_header = static_cast<uint8_t>(IpProtocol::TCP);
  ip->payload_length_be = autoswap(static_cast<uint16_t>(2u));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_FALSE(buf.tcp_header());
}

TEST(BufferViewIPv6MalformedTest, VlanIpv6Offset) {
  // VLAN tagged frame where the inner type is IPv6
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(VlanHeader) + sizeof(IPv6Header);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::VLAN));

  auto vlan = reinterpret_cast<VlanHeader*>(raw.data() + sizeof(EtherHeader));
  vlan->type_be = autoswap(std::to_underlying(EtherType::IPv6));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_EQ(buf.l3_offset(),
            static_cast<uint16_t>(sizeof(EtherHeader) + sizeof(VlanHeader)));
  EXPECT_TRUE(buf.ip6_header());
}

TEST(BufferViewIPv6MalformedTest, IpProtocolNullOnNonIpFrames) {
  std::array<uint8_t, sizeof(EtherHeader)> raw{};
  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::ARP));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_FALSE(buf.ip4_header());
  EXPECT_FALSE(buf.ip6_header());
  EXPECT_FALSE(buf.ip_protocol().has_value());
}

TEST(BufferViewIPv6MalformedTest, TcpOptionsTruncated) {
  // IPv6 + TCP header present but TCP data_offset (options length) extends
  // beyond available transport bytes (truncated options)
  constexpr size_t tcp_area = 30u; // only 30 bytes available for TCP (20 + 10)
  constexpr size_t total = sizeof(EtherHeader) + sizeof(IPv6Header) + tcp_area;
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

  auto ip = reinterpret_cast<IPv6Header*>(raw.data() + sizeof(EtherHeader));
  ip->next_header = static_cast<uint8_t>(IpProtocol::TCP);
  ip->payload_length_be = autoswap(static_cast<uint16_t>(tcp_area));

  auto tcp = reinterpret_cast<TCPHeader*>(raw.data() + sizeof(EtherHeader) +
                                          sizeof(IPv6Header));
  // indicate a large header_words (10 -> 40 bytes) but only 30 bytes available
  tcp->data_offset = static_cast<uint8_t>((10u << 4) & 0xF0u);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip6_header());
  auto th = buf.tcp_header();
  ASSERT_TRUE(th);
  EXPECT_EQ(th->header_words(), 10u);
  EXPECT_EQ(th->header_bytes(), 40u);

  const auto l3 = buf.l3_offset();
  ASSERT_EQ(l3, static_cast<uint16_t>(sizeof(EtherHeader)));
  const auto ihl = static_cast<uint16_t>(sizeof(IPv6Header));
  const auto avail_transport = static_cast<uint16_t>(raw.size()) - (l3 + ihl);
  // available transport bytes are smaller than declared header_bytes ->
  // truncated
  EXPECT_LT(avail_transport, th->header_bytes());
}

TEST(BufferViewIPv6MalformedTest, TcpDataOffsetTooSmall) {
  // TCP header declares a data_offset < 5 (invalid header size)
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(IPv6Header) + sizeof(TCPHeader);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

  auto ip = reinterpret_cast<IPv6Header*>(raw.data() + sizeof(EtherHeader));
  ip->next_header = static_cast<uint8_t>(IpProtocol::TCP);
  ip->payload_length_be = autoswap(static_cast<uint16_t>(sizeof(TCPHeader)));

  auto tcp = reinterpret_cast<TCPHeader*>(raw.data() + sizeof(EtherHeader) +
                                          sizeof(IPv6Header));
  // data_offset nibble = 4 -> header_bytes = 16 (invalid, less than min 20)
  tcp->data_offset = static_cast<uint8_t>((4u << 4) & 0xF0u);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip6_header());
  auto th = buf.tcp_header();
  // header_at requires at least 20 bytes so HeaderView exists, but data_offset
  // indicates invalid header size
  ASSERT_TRUE(th);
  EXPECT_FALSE(th->valid_min_size());
}

TEST(BufferViewIPv6MalformedTest, UdpLengthTooSmallAndTooLarge) {
  // Case A: UDP length field smaller than header size (malformed)
  {
    constexpr size_t total =
        sizeof(EtherHeader) + sizeof(IPv6Header) + sizeof(UDPHeader);
    std::vector<uint8_t> raw(total);

    auto eth = reinterpret_cast<EtherHeader*>(raw.data());
    eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

    auto ip = reinterpret_cast<IPv6Header*>(raw.data() + sizeof(EtherHeader));
    ip->next_header = static_cast<uint8_t>(IpProtocol::UDP);
    ip->payload_length_be = autoswap(static_cast<uint16_t>(sizeof(UDPHeader)));

    auto uh = reinterpret_cast<UDPHeader*>(raw.data() + sizeof(EtherHeader) +
                                           sizeof(IPv6Header));
    uh->length_be = autoswap(static_cast<uint16_t>(4u)); // less than 8

    BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
    ASSERT_TRUE(buf.ip6_header());
    auto u = buf.udp_header();
    ASSERT_TRUE(u);
    EXPECT_LT(u->length(), static_cast<uint16_t>(sizeof(UDPHeader)));
  }

  // Case B: UDP length field larger than IPv6 payload
  {
    constexpr size_t total =
        sizeof(EtherHeader) + sizeof(IPv6Header) + sizeof(UDPHeader);
    std::vector<uint8_t> raw(total);

    auto eth = reinterpret_cast<EtherHeader*>(raw.data());
    eth->type_be = autoswap(std::to_underlying(EtherType::IPv6));

    auto ip = reinterpret_cast<IPv6Header*>(raw.data() + sizeof(EtherHeader));
    ip->next_header = static_cast<uint8_t>(IpProtocol::UDP);
    // total payload only covers minimal UDP header, no payload
    ip->payload_length_be = autoswap(static_cast<uint16_t>(sizeof(UDPHeader)));

    auto uh = reinterpret_cast<UDPHeader*>(raw.data() + sizeof(EtherHeader) +
                                           sizeof(IPv6Header));
    uh->length_be = autoswap(
        static_cast<uint16_t>(sizeof(UDPHeader) + 10u)); // larger than payload

    BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
    ASSERT_TRUE(buf.ip6_header());
    auto u = buf.udp_header();
    ASSERT_TRUE(u);
    // UDP length > IPv6 payload length
    EXPECT_GT(u->length(), buf.ip6_header()->payload_length());
  }
}
