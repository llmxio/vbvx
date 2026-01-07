#include <gtest/gtest.h>
#include "vbvx/udp_header.hxx"
#include "buffer_view.hxx"
#include "auto_swap.hxx"
#include "vbvx/ether.hxx"
#include "vbvx/ip4_header.hxx"

#include <array>
#include <vector>

using namespace vbvx;

TEST(UDPHeader, SizeAndAlignment) {
  // Compile-time checks exist, ensure runtime view as well
  EXPECT_EQ(sizeof(UDPHeader), 8u);
  EXPECT_EQ(alignof(UDPHeader), 1u);
}

TEST(UDPHeader, DefaultsAndSettersGetters) {
  UDPHeader h{};

  // Default fields should be zero
  EXPECT_EQ(h.src_port(), 0u);
  EXPECT_EQ(h.dst_port(), 0u);
  EXPECT_EQ(h.length(), 0u);
  EXPECT_EQ(h.checksum(), 0u);

  // Set simple fields and read them back
  h.set_src_port(12345);
  h.set_dst_port(53);
  h.set_length(8u); // header-only
  h.set_checksum(0xabba);

  EXPECT_EQ(h.src_port(), 12345u);
  EXPECT_EQ(h.dst_port(), 53u);
  EXPECT_EQ(h.length(), 8u);
  EXPECT_EQ(h.checksum(), 0xabbau);
}

TEST(UDPHeader, EndiannessOnWire) {
  // Use set_* helpers which write host-order values but store byteswapped
  UDPHeader wire{};

  wire.set_src_port(0x1234);
  wire.set_dst_port(0x80);
  wire.set_length(0x0100);
  wire.set_checksum(0x5566);

  // Validate getters (host-order)
  EXPECT_EQ(wire.src_port(), 0x1234u);
  EXPECT_EQ(wire.dst_port(), 0x80u);
  EXPECT_EQ(wire.length(), 0x0100u);
  EXPECT_EQ(wire.checksum(), 0x5566u);

  // Inspect on-the-wire stored fields directly (big-endian encoded)
  EXPECT_EQ(wire.src_port_be, autoswap(static_cast<uint16_t>(0x1234)));
  EXPECT_EQ(wire.dst_port_be, autoswap(static_cast<uint16_t>(0x80)));
  EXPECT_EQ(wire.length_be, autoswap(static_cast<uint16_t>(0x0100)));
  EXPECT_EQ(wire.checksum_be, autoswap(static_cast<uint16_t>(0x5566)));
}

TEST(UDPHeader, RawOnWireBytesRoundtrip) {
  // Construct raw bytes representing an on-the-wire UDP header and
  // reinterpret_cast as UDPHeader to validate accessors convert correctly.
  std::array<uint8_t, sizeof(UDPHeader)> raw{};

  // Fill the on-the-wire values (network byte order) by using autoswap
  auto p = reinterpret_cast<UDPHeader*>(raw.data());
  p->src_port_be = autoswap(static_cast<uint16_t>(0x2222));
  p->dst_port_be = autoswap(static_cast<uint16_t>(0x3333));
  p->length_be = autoswap(static_cast<uint16_t>(0x0040));
  p->checksum_be = autoswap(static_cast<uint16_t>(0xdead));

  // Now view via accessors
  UDPHeader const& h = *reinterpret_cast<const UDPHeader*>(raw.data());
  EXPECT_EQ(h.src_port(), 0x2222u);
  EXPECT_EQ(h.dst_port(), 0x3333u);
  EXPECT_EQ(h.length(), 0x0040u);
  EXPECT_EQ(h.checksum(), 0xdeadu);
}

TEST(UDPHeader, BufferViewIntegration) {
  // Verify BufferView resolves UDP header when IPv4 + UDP are present
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(IPv4Header) + sizeof(UDPHeader);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->protocol = static_cast<uint8_t>(IpProtocol::UDP);
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip->total_length_be =
      autoswap(static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(UDPHeader)));

  auto uh = reinterpret_cast<UDPHeader*>(raw.data() + sizeof(EtherHeader) +
                                         sizeof(IPv4Header));
  uh->set_src_port(1234);
  uh->set_dst_port(4321);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ipv4_header());
  ASSERT_TRUE(buf.ip_protocol().has_value());
  EXPECT_EQ(buf.ip_protocol().value(), IpProtocol::UDP);

  auto view = buf.udp_header();
  ASSERT_TRUE(view);
  EXPECT_EQ(view->src_port(), 1234u);
  EXPECT_EQ(view->dst_port(), 4321u);
}
