#include <gtest/gtest.h>
#include "buffer_view.hxx"
#include "auto_swap.hxx"
#include "vbvx/ether.hxx"
#include "vbvx/ip4_header.hxx"
#include "vbvx/tcp_header.hxx"

#include <bit>
#include <vector>

using namespace vbvx;

TEST(TCPHeader, SizeAndAlignment) {
  // Compile-time checks exist, ensure runtime view as well
  EXPECT_EQ(sizeof(TCPHeader), 20u);
  EXPECT_EQ(alignof(TCPHeader), 1u);
}

TEST(TCPHeader, DefaultsAndSettersGetters) {
  TCPHeader h{};

  // Default fields should be zero
  EXPECT_EQ(h.src_port(), 0u);
  EXPECT_EQ(h.dst_port(), 0u);
  EXPECT_EQ(h.seq_num(), 0u);
  EXPECT_EQ(h.ack_num(), 0u);
  EXPECT_EQ(h.header_words(), 0u);
  EXPECT_EQ(h.header_bytes(), 0u);
  EXPECT_EQ(static_cast<uint8_t>(h.flags()), 0u);
  EXPECT_EQ(h.window(), 0u);
  EXPECT_EQ(h.checksum(), 0u);
  EXPECT_EQ(h.urgent_ptr(), 0u);

  // Set simple fields and read them back
  h.set_src_port(12345);
  h.set_dst_port(80);
  h.set_seq_num(0xdeadbeef);
  h.set_ack_num(0x01020304);
  h.set_flags(static_cast<uint8_t>(TCPFlags::SYN) |
              static_cast<uint8_t>(TCPFlags::ACK));
  h.set_window(0x7070);
  h.set_checksum(0xabba);
  h.set_urgent_ptr(0xfeed);

  EXPECT_EQ(h.src_port(), 12345u);
  EXPECT_EQ(h.dst_port(), 80u);
  EXPECT_EQ(h.seq_num(), 0xdeadbeefu);
  EXPECT_EQ(h.ack_num(), 0x01020304u);
  EXPECT_EQ((h.flags() & (TCPFlags::SYN | TCPFlags::ACK)),
            (TCPFlags::SYN | TCPFlags::ACK));
  EXPECT_EQ(h.window(), 0x7070u);
  EXPECT_EQ(h.checksum(), 0xabbau);
  EXPECT_EQ(h.urgent_ptr(), 0xfeedu);
}

TEST(TCPHeader, HeaderLengthFields) {
  TCPHeader h{};

  // data_offset: high 4 bits contain header words
  // Set header_words to 5 (minimum 20 bytes)
  h.data_offset = static_cast<uint8_t>((5u & 0x0Fu) << 4);
  EXPECT_EQ(h.header_words(), 5u);
  EXPECT_EQ(h.header_bytes(), 20u);
  EXPECT_TRUE(h.valid_min_size());

  // Set header_words to 6 -> 24 bytes
  h.data_offset = static_cast<uint8_t>((6u & 0x0Fu) << 4);
  EXPECT_EQ(h.header_words(), 6u);
  EXPECT_EQ(h.header_bytes(), 24u);
  EXPECT_TRUE(h.valid_min_size());

  // Zero header_words -> invalid (0 bytes)
  h.data_offset = 0;
  EXPECT_EQ(h.header_words(), 0u);
  EXPECT_EQ(h.header_bytes(), 0u);
  EXPECT_FALSE(h.valid_min_size());
}

TEST(TCPHeader, EndiannessOnWire) {
  // Construct a TCPHeader with on-wire (network byte order) values, then
  // verify the accessors return host-ordered values via autoswap.
  TCPHeader wire{};

  // Use set_* helpers which write host-order values but store byteswapped
  wire.set_src_port(0x1234);
  wire.set_dst_port(0x80);
  wire.set_seq_num(0x11223344);
  wire.set_ack_num(0xaabbccdd);
  wire.set_window(0x3344);
  wire.set_checksum(0x5566);
  wire.set_urgent_ptr(0x7788);

  // Validate getters
  EXPECT_EQ(wire.src_port(), 0x1234u);
  EXPECT_EQ(wire.dst_port(), 0x80u);
  EXPECT_EQ(wire.seq_num(), 0x11223344u);
  EXPECT_EQ(wire.ack_num(), 0xaabbccddu);
  EXPECT_EQ(wire.window(), 0x3344u);
  EXPECT_EQ(wire.checksum(), 0x5566u);
  EXPECT_EQ(wire.urgent_ptr(), 0x7788u);

  // Now inspect the on-the-wire stored fields directly (big-endian encoded)
  // by using the *_be members which should equal byteswapped values of the
  // host-order values we set above.
  EXPECT_EQ(wire.src_port_be, autoswap(static_cast<uint16_t>(0x1234)));
  EXPECT_EQ(wire.dst_port_be, autoswap(static_cast<uint16_t>(0x80)));
  EXPECT_EQ(wire.seq_num_be, autoswap(static_cast<uint32_t>(0x11223344)));
  EXPECT_EQ(wire.ack_num_be, autoswap(static_cast<uint32_t>(0xaabbccdd)));
  EXPECT_EQ(wire.window_be, autoswap(static_cast<uint16_t>(0x3344)));
  EXPECT_EQ(wire.checksum_be, autoswap(static_cast<uint16_t>(0x5566)));
  EXPECT_EQ(wire.urgent_ptr_be, autoswap(static_cast<uint16_t>(0x7788)));
}

TEST(TCPHeader, FlagsBitmaskOperators) {
  // Ensure bitmask operators work via enable_bitmask_operators
  TCPFlags f = TCPFlags::SYN;
  f = f | TCPFlags::ACK;
  EXPECT_TRUE(static_cast<uint8_t>(f) & static_cast<uint8_t>(TCPFlags::SYN));
  EXPECT_TRUE(static_cast<uint8_t>(f) & static_cast<uint8_t>(TCPFlags::ACK));

  f = f & ~TCPFlags::SYN;
  EXPECT_FALSE(static_cast<uint8_t>(f) & static_cast<uint8_t>(TCPFlags::SYN));
  EXPECT_TRUE(static_cast<uint8_t>(f) & static_cast<uint8_t>(TCPFlags::ACK));
}

TEST(TCPHeader, TcpOptionsExactlyFit) {
  // TCP header declares options length that exactly matches available transport
  // bytes
  constexpr size_t tcp_area = 24u; // 20 + 4 bytes of options
  constexpr size_t total = sizeof(EtherHeader) + sizeof(IPv4Header) + tcp_area;
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->protocol = static_cast<uint8_t>(IpProtocol::TCP);
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip->total_length_be =
      autoswap(static_cast<uint16_t>(sizeof(IPv4Header) + tcp_area));

  auto tcp = reinterpret_cast<TCPHeader*>(raw.data() + sizeof(EtherHeader) +
                                          sizeof(IPv4Header));
  tcp->data_offset =
      static_cast<uint8_t>((6u << 4) & 0xF0u); // 6 words -> 24 bytes

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  auto th = buf.tcp_header();
  ASSERT_TRUE(th);
  EXPECT_EQ(th->header_words(), 6u);
  EXPECT_EQ(th->header_bytes(), 24u);

  const auto l3 = buf.l3_offset();
  ASSERT_EQ(l3, static_cast<uint16_t>(sizeof(EtherHeader)));
  const auto ihl = buf.ip4_ihl_bytes();
  ASSERT_TRUE(ihl.has_value());
  const auto avail_transport = static_cast<uint16_t>(raw.size()) - (l3 + *ihl);
  EXPECT_EQ(avail_transport, th->header_bytes());
}

TEST(TCPHeader, TcpMaxDataOffsetTruncated) {
  // TCP header declares maximum header size but transport bytes are one short
  constexpr size_t tcp_area = 59u; // 20 + 39 -> less than declared 60
  constexpr size_t total = sizeof(EtherHeader) + sizeof(IPv4Header) + tcp_area;
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->protocol = static_cast<uint8_t>(IpProtocol::TCP);
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip->total_length_be =
      autoswap(static_cast<uint16_t>(sizeof(IPv4Header) + tcp_area));

  auto tcp = reinterpret_cast<TCPHeader*>(raw.data() + sizeof(EtherHeader) +
                                          sizeof(IPv4Header));
  tcp->data_offset =
      static_cast<uint8_t>((15u << 4) & 0xF0u); // 15 words -> 60 bytes

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  auto th = buf.tcp_header();
  ASSERT_TRUE(th);
  EXPECT_EQ(th->header_words(), 15u);
  EXPECT_EQ(th->header_bytes(), 60u);

  const auto l3 = buf.l3_offset();
  ASSERT_EQ(l3, static_cast<uint16_t>(sizeof(EtherHeader)));
  const auto ihl = buf.ip4_ihl_bytes();
  ASSERT_TRUE(ihl.has_value());
  const auto avail_transport = static_cast<uint16_t>(raw.size()) - (l3 + *ihl);
  EXPECT_LT(avail_transport, th->header_bytes());
}

TEST(TCPHeader, DataOffsetLowNibbleIgnored) {
  // Ensure low nibble doesn't affect header word calculation
  constexpr size_t tcp_area = 28u; // 20 + 8
  constexpr size_t total = sizeof(EtherHeader) + sizeof(IPv4Header) + tcp_area;
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->protocol = static_cast<uint8_t>(IpProtocol::TCP);
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip->total_length_be =
      autoswap(static_cast<uint16_t>(sizeof(IPv4Header) + tcp_area));

  auto tcp = reinterpret_cast<TCPHeader*>(raw.data() + sizeof(EtherHeader) +
                                          sizeof(IPv4Header));
  // set high nibble = 7 (28 bytes), low nibble to 0xF which should be ignored
  tcp->data_offset = static_cast<uint8_t>(((7u << 4) & 0xF0u) | 0x0Fu);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  auto th = buf.tcp_header();
  ASSERT_TRUE(th);
  EXPECT_EQ(th->header_words(), 7u);
  EXPECT_EQ(th->header_bytes(), 28u);

  EXPECT_TRUE(th->valid_min_size());
  const auto l3 = buf.l3_offset();
  ASSERT_EQ(l3, static_cast<uint16_t>(sizeof(EtherHeader)));
  const auto ihl = buf.ip4_ihl_bytes();
  ASSERT_TRUE(ihl.has_value());
  const auto avail_transport = static_cast<uint16_t>(raw.size()) - (l3 + *ihl);
  EXPECT_EQ(avail_transport, th->header_bytes());
}
