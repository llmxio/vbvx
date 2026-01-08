#include <gtest/gtest.h>
#include "buffer_view.hxx"
#include "utils.hxx"

#include <array>
#include <bit>
#include <vector>
#include <cstring>
#include <cstddef>

using namespace vbvx;

TEST(BufferViewTest, CopyAndEthertype) {
  std::array<uint8_t, sizeof(EtherHeader)> data{};
  auto hdr = reinterpret_cast<EtherHeader*>(data.data());
  hdr->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  BufferView buf(data.data(), static_cast<uint16_t>(data.size()));
  auto eth = buf.ether_header();
  ASSERT_TRUE(eth);

  auto copy = eth.copy();
  EXPECT_EQ(copy.type(), hdr->type());

  auto t = buf.ether_type();
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(t.value(), EtherType::IPv4);
}

TEST(BufferViewTest, EmptyBufferNullptr) {
  BufferView buf(nullptr, 0);
  EXPECT_EQ(buf.data().size(), 0u);
  EXPECT_EQ(buf.length(), 0u);
  EXPECT_FALSE(buf.ether_header());
  EXPECT_FALSE(buf.ether_type().has_value());
  EXPECT_FALSE(buf.vlan_header());
  EXPECT_FALSE(buf.ip4_header());
  EXPECT_FALSE(buf.ip6_header());
  EXPECT_FALSE(buf.arp_header());
  EXPECT_FALSE(buf.tcp_header());
  EXPECT_FALSE(buf.udp_header());
  EXPECT_FALSE(buf.icmp4_header());
}

TEST(BufferViewTest, TruncatedEtherHeader) {
  std::array<uint8_t, sizeof(EtherHeader) - 1> data{};
  BufferView buf(data.data(), static_cast<uint16_t>(data.size()));
  EXPECT_FALSE(buf.ether_header());
  EXPECT_FALSE(buf.ether_type().has_value());
  EXPECT_EQ(buf.l3_offset(), 0u);
}

TEST(BufferViewTest, VlanMissingHeader) {
  std::array<uint8_t, sizeof(EtherHeader)> data{};
  auto eth = reinterpret_cast<EtherHeader*>(data.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::VLAN));

  BufferView buf(data.data(), static_cast<uint16_t>(data.size()));
  ASSERT_TRUE(buf.ether_header());
  EXPECT_FALSE(buf.vlan_header());
  EXPECT_FALSE(buf.ether_type().has_value());
}

TEST(BufferViewTest, VlanWithHeader) {
  std::array<uint8_t, sizeof(EtherHeader) + sizeof(VlanHeader)> data{};
  EtherHeader eth_tmp{};
  eth_tmp.type_be = autoswap(std::to_underlying(EtherType::VLAN));
  std::memcpy(data.data(), &eth_tmp, sizeof(eth_tmp));

  VlanHeader vlan_tmp{};
  vlan_tmp.set_tci(0x0ABC);
  vlan_tmp.set_type(std::to_underlying(EtherType::IPv4));
  std::memcpy(data.data() + sizeof(EtherHeader), &vlan_tmp, sizeof(vlan_tmp));

  BufferView buf(data.data(), static_cast<uint16_t>(data.size()));
  ASSERT_TRUE(buf.ether_header());
  auto vh = buf.vlan_header();
  ASSERT_TRUE(vh);
  EXPECT_EQ(buf.ether_type().value(), EtherType::IPv4);
  EXPECT_TRUE(buf.vlan_id().has_value());
  EXPECT_EQ(buf.vlan_id().value(), static_cast<uint16_t>(0x0ABC & 0x0FFFu));
  EXPECT_EQ(buf.l3_offset(),
            static_cast<uint16_t>(sizeof(EtherHeader) + sizeof(VlanHeader)));
}

TEST(BufferViewTest, ArpTruncated) {
  // Write an ARP Ethertype but not enough room for the ARP header
  std::array<uint8_t, sizeof(EtherHeader) + sizeof(ArpHeader) - 1> data{};
  EtherHeader eth_tmp{};
  eth_tmp.type_be = autoswap(std::to_underlying(EtherType::ARP));
  std::memcpy(data.data(), &eth_tmp, sizeof(eth_tmp));

  BufferView buf(data.data(), static_cast<uint16_t>(data.size()));
  EXPECT_FALSE(buf.arp_header());
}

TEST(BufferViewTest, IPv4IhlTooSmall) {
  std::array<uint8_t, sizeof(EtherHeader) + sizeof(IPv4Header)> data{};
  // Ether header -> IPv4
  EtherHeader eth_tmp{};
  eth_tmp.type_be = autoswap(std::to_underlying(EtherType::IPv4));
  std::memcpy(data.data(), &eth_tmp, sizeof(eth_tmp));

  // IPv4 header with IHL == 4 (16 bytes) which is < 20
  IPv4Header ip{};
  ip.version_ihl = static_cast<uint8_t>((4u << 4) | 4u);
  ip.protocol = static_cast<uint8_t>(IpProtocol::TCP);
  std::memcpy(data.data() + sizeof(EtherHeader), &ip, sizeof(ip));

  BufferView buf(data.data(), static_cast<uint16_t>(data.size()));
  auto ip_hdr = buf.ip4_header();
  ASSERT_TRUE(ip_hdr); // header struct is present (bounds ok)
  EXPECT_FALSE(buf.ip4_ihl_bytes().has_value());
  EXPECT_FALSE(buf.l4_offset().has_value());
  EXPECT_FALSE(buf.tcp_header());
}

TEST(BufferViewTest, IPv4TcpHeaderPresentAndTruncated) {
  // Enough for IPv4 header but TCP header is truncated in one case and present
  // in another
  {
    std::vector<uint8_t> small_buf(sizeof(EtherHeader) + sizeof(IPv4Header) +
                                   sizeof(TCPHeader) - 1);
    std::memset(small_buf.data(), 0, small_buf.size());
    EtherHeader eth_tmp{};
    eth_tmp.type_be = autoswap(std::to_underlying(EtherType::IPv4));
    std::memcpy(small_buf.data(), &eth_tmp, sizeof(eth_tmp));

    IPv4Header ip{};
    ip.version_ihl = static_cast<uint8_t>((4u << 4) | 5u); // 20 bytes
    ip.protocol = static_cast<uint8_t>(IpProtocol::TCP);
    std::memcpy(small_buf.data() + sizeof(EtherHeader), &ip, sizeof(ip));

    BufferView buf(small_buf.data(), static_cast<uint16_t>(small_buf.size()));
    EXPECT_FALSE(buf.tcp_header());
  }

  {
    std::vector<uint8_t> good_buf(sizeof(EtherHeader) + sizeof(IPv4Header) +
                                  sizeof(TCPHeader));
    std::memset(good_buf.data(), 0, good_buf.size());
    EtherHeader eth_tmp{};
    eth_tmp.type_be = autoswap(std::to_underlying(EtherType::IPv4));
    std::memcpy(good_buf.data(), &eth_tmp, sizeof(eth_tmp));

    IPv4Header ip{};
    ip.version_ihl = static_cast<uint8_t>((4u << 4) | 5u); // 20 bytes
    ip.protocol = static_cast<uint8_t>(IpProtocol::TCP);
    std::memcpy(good_buf.data() + sizeof(EtherHeader), &ip, sizeof(ip));

    TCPHeader tcp{};
    tcp.set_src_port(1234);
    tcp.set_dst_port(4321);
    std::memcpy(good_buf.data() + sizeof(EtherHeader) + sizeof(IPv4Header),
                &tcp, sizeof(tcp));

    BufferView buf(good_buf.data(), static_cast<uint16_t>(good_buf.size()));
    auto t = buf.tcp_header();
    ASSERT_TRUE(t);
    EXPECT_EQ(t->src_port(), 1234u);
    EXPECT_EQ(t->dst_port(), 4321u);
    EXPECT_EQ(buf.ip_protocol().value(), IpProtocol::TCP);
    EXPECT_TRUE(buf.l4_offset().has_value());
  }
}

TEST(BufferViewTest, IPv4UdpHeaderPresent) {
  std::vector<uint8_t> buf_bytes(sizeof(EtherHeader) + sizeof(IPv4Header) +
                                 sizeof(UDPHeader));
  std::memset(buf_bytes.data(), 0, buf_bytes.size());

  EtherHeader eth_tmp{};
  eth_tmp.type_be = autoswap(std::to_underlying(EtherType::IPv4));
  std::memcpy(buf_bytes.data(), &eth_tmp, sizeof(eth_tmp));

  IPv4Header ip{};
  ip.version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip.protocol = static_cast<uint8_t>(IpProtocol::UDP);
  std::memcpy(buf_bytes.data() + sizeof(EtherHeader), &ip, sizeof(ip));

  UDPHeader udp{};
  udp.set_src_port(5555);
  udp.set_dst_port(6666);
  std::memcpy(buf_bytes.data() + sizeof(EtherHeader) + sizeof(IPv4Header), &udp,
              sizeof(udp));

  BufferView buf(buf_bytes.data(), static_cast<uint16_t>(buf_bytes.size()));
  auto u = buf.udp_header();
  ASSERT_TRUE(u);
  EXPECT_EQ(u->src_port(), 5555u);
  EXPECT_EQ(u->dst_port(), 6666u);
}

TEST(BufferViewTest, IPv6Icmpv6) {
  const auto total =
      sizeof(vbvx::EtherHeader) + 40 + sizeof(vbvx::ICMPv4Header);
  std::vector<uint8_t> buf_bytes(total);
  std::memset(buf_bytes.data(), 0, buf_bytes.size());

  EtherHeader eth_tmp{};
  eth_tmp.type_be = autoswap(std::to_underlying(EtherType::IPv6));
  std::memcpy(buf_bytes.data(), &eth_tmp, sizeof(eth_tmp));

  const auto ip_off = sizeof(EtherHeader);
  const uint32_t ver_be = autoswap(static_cast<uint32_t>(6u << 28));
  std::memcpy(buf_bytes.data() + ip_off, &ver_be, sizeof(ver_be));
  // next_header field is at offset 6 within the IPv6 header
  buf_bytes[ip_off + 6] = static_cast<uint8_t>(IpProtocol::ICMPv6);

  ICMPv4Header icmp{};
  icmp.type = static_cast<uint8_t>(ICMPv4Type::EchoRequest);
  icmp.code = 0;
  icmp.set_checksum(0x1234);
  std::memcpy(buf_bytes.data() + ip_off + 40, &icmp, sizeof(icmp));

  BufferView buf(buf_bytes.data(), static_cast<uint16_t>(buf_bytes.size()));
  EXPECT_EQ(buf.ip_protocol().value(), IpProtocol::ICMPv6);
  auto ic = buf.icmp6_header();
  ASSERT_TRUE(ic);
  EXPECT_EQ(ic->type_u8(), static_cast<uint8_t>(ICMPv4Type::EchoRequest));
  EXPECT_EQ(ic->checksum(), 0x1234u);
}
