#include <gtest/gtest.h>
#include "header_view.hxx"
#include "auto_swap.hxx"
#include "vbvx/ip4_header.hxx"

#include <array>
#include <bit>
#include <cstring>
#include <type_traits>
#include <utility>

using namespace vbvx;

TEST(IPv4FragmentTest, FlagsParsedFromWire) {
  IPv4Header tmp{};
  tmp.frag_off_be = autoswap(static_cast<uint16_t>(
      std::to_underlying(IPv4Flags::DF | IPv4Flags::MF) | 0x0003u));

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->frag_flags(), (IPv4Flags::DF | IPv4Flags::MF));
  EXPECT_TRUE(hv->has_flag(IPv4Flags::DF));
  EXPECT_TRUE(hv->has_flag(IPv4Flags::MF));
  EXPECT_EQ(hv->frag_offset_units8(), 0x0003u);
  EXPECT_EQ(hv->frag_offset_bytes(), 24u);
  EXPECT_TRUE(hv->is_fragmented());
}

TEST(IPv4FragmentTest, SettersRoundTripBits) {
  IPv4Header h{};

  h.set_frag_offset_units8(9);
  h.set_df(true);
  h.set_mf(true);

  const auto raw = h.frag_off();
  const auto expected =
      static_cast<uint16_t>(std::to_underlying(IPv4Flags::DF) |
                            std::to_underlying(IPv4Flags::MF) | 0x0009u);

  EXPECT_EQ(raw, expected);
  EXPECT_TRUE(h.has_flag(IPv4Flags::DF));
  EXPECT_TRUE(h.has_flag(IPv4Flags::MF));
  EXPECT_EQ(h.frag_offset_units8(), 9u);
  EXPECT_EQ(h.frag_offset_bytes(), 72u);
}

TEST(IPv4FragmentTest, FragmentationDetection) {
  IPv4Header h{};

  EXPECT_FALSE(h.is_fragmented());

  h.set_mf(true);
  EXPECT_TRUE(h.is_fragmented());

  h.set_mf(false);
  h.set_frag_offset_bytes(24);
  EXPECT_TRUE(h.is_fragmented());

  h.set_frag_offset_units8(0);
  h.set_df(true);
  EXPECT_FALSE(h.is_fragmented());
}

TEST(IPv4HeaderTest, VersionAndIhlParsing) {
  IPv4Header tmp{};
  tmp.version_ihl = static_cast<uint8_t>((4u << 4) | 5u);

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->version(), 4u);
  EXPECT_EQ(hv->ihl_words(), 5u);
  EXPECT_EQ(hv->ihl_bytes(), 20u);
  EXPECT_TRUE(hv->valid_min_size());
}

TEST(IPv4HeaderTest, DscpAndEcnParsing) {
  IPv4Header tmp{};
  constexpr uint8_t dscp = 0x15; // 6 bits
  constexpr uint8_t ecn = 0x2;   // 2 bits
  tmp.tos = static_cast<uint8_t>((dscp << 2) | ecn);

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->dscp(), dscp);
  EXPECT_EQ(hv->ecn(), ecn);
}

TEST(IPv4HeaderTest, TotalLengthAndIdParsing) {
  IPv4Header tmp{};
  tmp.total_length_be = autoswap(static_cast<uint16_t>(0x1234u));
  tmp.id_be = autoswap(static_cast<uint16_t>(0xABCDu));

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->total_length(), 0x1234u);
  EXPECT_EQ(hv->id(), 0xABCDu);
}

TEST(IPv4HeaderTest, FragFlagsSetterAndRoundtrip) {
  IPv4Header h{};
  h.set_frag_flags(static_cast<IPv4Flags>(std::to_underlying(IPv4Flags::DF) |
                                          std::to_underlying(IPv4Flags::MF)));

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &h, sizeof(h));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->frag_flags(), (IPv4Flags::DF | IPv4Flags::MF));
  EXPECT_TRUE(hv->has_flag(IPv4Flags::DF));
  EXPECT_TRUE(hv->has_flag(IPv4Flags::MF));
}

TEST(IPv4HeaderTest, SetFragOffsetBytes) {
  IPv4Header h{};
  h.set_frag_offset_bytes(40); // should set units8 = 5

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &h, sizeof(h));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->frag_offset_units8(), 5u);
  EXPECT_EQ(hv->frag_offset_bytes(), 40u);
}

TEST(IPv4HeaderTest, L4ProtocolParsing) {
  IPv4Header tmp{};
  tmp.protocol = static_cast<uint8_t>(IpProtocol::TCP);

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &tmp, sizeof(tmp));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->l4_protocol(), IpProtocol::TCP);
}

TEST(IPv4HeaderTest, ChecksumSetAndGet) {
  IPv4Header h{};
  h.set_checksum(0xBEEFu);
  EXPECT_EQ(h.checksum(), 0xBEEFu);
}

TEST(IPv4HeaderTest, SrcAndDstSetters) {
  IPv4Header h{};
  h.set_src(0xAABBCCDDu);
  h.set_dst(0x11223344u);

  std::array<uint8_t, sizeof(IPv4Header)> raw{};
  std::memcpy(raw.data(), &h, sizeof(h));

  HeaderView<IPv4Header> hv(raw.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->src_addr(), 0xAABBCCDDu);
  EXPECT_EQ(hv->dst_addr(), 0x11223344u);
}

TEST(IPv4HeaderTest, ValidMinSizeBehavior) {
  IPv4Header h{};
  // default ihl == 0 -> invalid
  EXPECT_FALSE(h.valid_min_size());

  // ihl 4 -> 16 bytes -> invalid
  h.version_ihl = static_cast<uint8_t>((4u << 4) | 4u);
  EXPECT_FALSE(h.valid_min_size());

  // ihl 5 -> 20 bytes -> valid
  h.version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  EXPECT_TRUE(h.valid_min_size());
}

TEST(IPv4HeaderEdgeCases, IhlMaxAndVersion) {
  IPv4Header h{};
  // IHL maximum (15 words = 60 bytes)
  h.version_ihl = static_cast<uint8_t>((4u << 4) | 15u);
  EXPECT_EQ(h.ihl_words(), 15u);
  EXPECT_EQ(h.ihl_bytes(), 60u);
  EXPECT_TRUE(h.valid_min_size());

  // Non-IPv4 version should still be parsed by the header accessors
  h.version_ihl = static_cast<uint8_t>((6u << 4) | 5u);
  EXPECT_EQ(h.version(), 6u);
  EXPECT_NE(h.version(), 4u);
  EXPECT_TRUE(h.valid_min_size());
}

TEST(IPv4HeaderEdgeCases, FragOffsetMaskingAndBytes) {
  IPv4Header h{};
  // Setting a value larger than the 13-bit offset should be masked
  h.set_frag_offset_units8(0xFFFFu);
  EXPECT_EQ(h.frag_offset_units8(),
            static_cast<uint16_t>(0xFFFFu & FRAG_OFFSET_MASK));

  // Non-multiple-of-8 byte values should be truncated when setting bytes
  h.set_frag_offset_bytes(5); // not multiple of 8 -> units8 becomes 0
  EXPECT_EQ(h.frag_offset_units8(), 0u);
  EXPECT_EQ(h.frag_offset_bytes(), 0u);
}

TEST(IPv4HeaderEdgeCases, FragFlagsMaskingAndPreserveOffset) {
  IPv4Header h{};
  // Start with a non-zero offset and set a single flag; offset must be
  // preserved
  h.set_frag_offset_units8(3u);
  h.set_frag_flags(IPv4Flags::DF);
  EXPECT_TRUE(h.has_flag(IPv4Flags::DF));
  EXPECT_EQ(h.frag_offset_units8(), 3u);

  // Passing a flags value that contains low-order offset bits should have those
  // low bits masked off; only the flag mask (FRAG_FLAGS_MASK) should be
  // applied.
  h.set_frag_flags(static_cast<IPv4Flags>(0xE001u));
  EXPECT_EQ(h.frag_flags(), static_cast<IPv4Flags>(0xE000u));
  EXPECT_TRUE(h.has_flag(IPv4Flags::RFU));
  EXPECT_TRUE(h.has_flag(IPv4Flags::DF));
  EXPECT_TRUE(h.has_flag(IPv4Flags::MF));
  // Offset should remain unchanged
  EXPECT_EQ(h.frag_offset_units8(), 3u);
}

// ---------------------------------------------------------------------
// BufferView negative / malformed header tests (IPv4)
// ---------------------------------------------------------------------

#include "buffer_view.hxx"
#include "vbvx/ether.hxx"
#include "vbvx/udp_header.hxx"
#include "vbvx/tcp_header.hxx"

#include <vector>

TEST(BufferViewIPv4MalformedTest, Ipv4HeaderTooShort) {
  // Ethernet frame that claims IPv4 but is too short to contain an IPv4 header
  std::array<uint8_t, sizeof(EtherHeader) + 10> raw{};
  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_FALSE(buf.ip4_header());
  EXPECT_FALSE(buf.l4_offset());
  EXPECT_FALSE(buf.ip_protocol().has_value());
}

TEST(BufferViewIPv4MalformedTest, Ipv4HeaderPresentAndL4Offset) {
  // Enough room for IPv4 + UDP header
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

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  ASSERT_TRUE(buf.ip_protocol().has_value());
  EXPECT_EQ(buf.ip_protocol().value(), IpProtocol::UDP);
  ASSERT_TRUE(buf.l4_offset());
  EXPECT_EQ(buf.l4_offset().value(),
            static_cast<uint16_t>(sizeof(EtherHeader) + sizeof(IPv4Header)));

  auto uh = buf.udp_header();
  ASSERT_TRUE(uh);
  // default constructed UDP header fields should be zeros
  EXPECT_EQ(uh->src_port(), 0u);
  EXPECT_EQ(uh->dst_port(), 0u);
}

TEST(BufferViewIPv4MalformedTest, TcpHeaderTooShortWhenProtoIsTcp) {
  // IPv4 present but not enough bytes for a TCP header
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(IPv4Header) + 2; // too small for TCP
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->protocol = static_cast<uint8_t>(IpProtocol::TCP);
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip->total_length_be = autoswap(static_cast<uint16_t>(2u));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_FALSE(buf.tcp_header());
}

TEST(BufferViewIPv4MalformedTest, TcpOptionsTruncated) {
  // IPv4 + TCP header present but TCP data_offset (options length) extends
  // beyond available transport bytes (truncated options)
  constexpr size_t tcp_area = 30u; // only 30 bytes available for TCP (20 + 10)
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
  // indicate a large header_words (10 -> 40 bytes) but only 30 bytes available
  tcp->data_offset = static_cast<uint8_t>((10u << 4) & 0xF0u);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  auto th = buf.tcp_header();
  ASSERT_TRUE(th);
  EXPECT_EQ(th->header_words(), 10u);
  EXPECT_EQ(th->header_bytes(), 40u);

  const auto l3 = buf.l3_offset();
  ASSERT_EQ(l3, static_cast<uint16_t>(sizeof(EtherHeader)));
  const auto ihl = buf.ip4_ihl_bytes();
  ASSERT_TRUE(ihl.has_value());
  const auto avail_transport = static_cast<uint16_t>(raw.size()) - (l3 + *ihl);
  // available transport bytes are smaller than declared header_bytes ->
  // truncated
  EXPECT_LT(avail_transport, th->header_bytes());
}

TEST(BufferViewIPv4MalformedTest, TcpDataOffsetTooSmall) {
  // TCP header declares a data_offset < 5 (invalid header size)
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(IPv4Header) + sizeof(TCPHeader);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->protocol = static_cast<uint8_t>(IpProtocol::TCP);
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
  ip->total_length_be =
      autoswap(static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(TCPHeader)));

  auto tcp = reinterpret_cast<TCPHeader*>(raw.data() + sizeof(EtherHeader) +
                                          sizeof(IPv4Header));
  // data_offset nibble = 4 -> header_bytes = 16 (invalid, less than min 20)
  tcp->data_offset = static_cast<uint8_t>((4u << 4) & 0xF0u);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  auto th = buf.tcp_header();
  // header_at requires at least 20 bytes so HeaderView exists, but data_offset
  // indicates invalid header size
  ASSERT_TRUE(th);
  EXPECT_FALSE(th->valid_min_size());
}

TEST(BufferViewIPv4MalformedTest, UdpLengthTooSmallAndTooLarge) {
  // Case A: UDP length field smaller than header size (malformed)
  {
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
    uh->length_be = autoswap(static_cast<uint16_t>(4u)); // less than 8

    BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
    ASSERT_TRUE(buf.ip4_header());
    auto u = buf.udp_header();
    ASSERT_TRUE(u);
    EXPECT_LT(u->length(), static_cast<uint16_t>(sizeof(UDPHeader)));
  }

  // Case B: UDP length field larger than IP payload
  {
    constexpr size_t total =
        sizeof(EtherHeader) + sizeof(IPv4Header) + sizeof(UDPHeader);
    std::vector<uint8_t> raw(total);

    auto eth = reinterpret_cast<EtherHeader*>(raw.data());
    eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

    auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
    ip->protocol = static_cast<uint8_t>(IpProtocol::UDP);
    ip->version_ihl = static_cast<uint8_t>((4u << 4) | 5u);
    // total length only covers minimal UDP header, no payload
    ip->total_length_be =
        autoswap(static_cast<uint16_t>(sizeof(IPv4Header) + sizeof(UDPHeader)));

    auto uh = reinterpret_cast<UDPHeader*>(raw.data() + sizeof(EtherHeader) +
                                           sizeof(IPv4Header));
    uh->length_be = autoswap(
        static_cast<uint16_t>(512u)); // claims much larger than available

    BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
    ASSERT_TRUE(buf.ip4_header());
    auto u = buf.udp_header();
    ASSERT_TRUE(u);

    const auto l3 = buf.l3_offset();
    const auto ihl = buf.ip4_ihl_bytes();
    ASSERT_TRUE(ihl.has_value());
    const auto ip_payload_bytes = static_cast<uint16_t>(
        ip->total_length_be ? ip->total_length_be / 1 : 0);
    // use header fields converted: total_length() gives host-order
    const auto ip_payload = static_cast<uint16_t>(ip->total_length() - *ihl);

    EXPECT_GT(u->length(), ip_payload);
  }
}

TEST(BufferViewIPv4MalformedTest, VlanIpv4Offset) {
  // VLAN tagged frame where the inner type is IPv4
  constexpr size_t total =
      sizeof(EtherHeader) + sizeof(VlanHeader) + sizeof(IPv4Header);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::VLAN));

  auto vlan = reinterpret_cast<VlanHeader*>(raw.data() + sizeof(EtherHeader));
  vlan->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_EQ(buf.l3_offset(),
            static_cast<uint16_t>(sizeof(EtherHeader) + sizeof(VlanHeader)));
  EXPECT_TRUE(buf.ip4_header());
}

TEST(BufferViewIPv4MalformedTest, IpProtocolNullOnNonIpFrames) {
  std::array<uint8_t, sizeof(EtherHeader)> raw{};
  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::ARP));

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  EXPECT_FALSE(buf.ip4_header());
  EXPECT_FALSE(buf.ip6_header());
  EXPECT_FALSE(buf.ip_protocol().has_value());
}

TEST(BufferViewIPv4MalformedTest, Ipv4HeaderIhlTooSmall) {
  // IPv4 header present but IHL < 5 (invalid). l4 offset should be absent.
  constexpr size_t total = sizeof(EtherHeader) + sizeof(IPv4Header);
  std::vector<uint8_t> raw(total);

  auto eth = reinterpret_cast<EtherHeader*>(raw.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  auto ip = reinterpret_cast<IPv4Header*>(raw.data() + sizeof(EtherHeader));
  ip->version_ihl = static_cast<uint8_t>((4u << 4) | 4u); // ihl=4
  ip->protocol = static_cast<uint8_t>(IpProtocol::TCP);

  BufferView buf(raw.data(), static_cast<uint16_t>(raw.size()));
  ASSERT_TRUE(buf.ip4_header());
  EXPECT_FALSE(buf.ip4_ihl_bytes());
  EXPECT_FALSE(buf.l4_offset());
  // protocol is still readable from the header itself
  ASSERT_TRUE(buf.ip_protocol().has_value());
  EXPECT_EQ(buf.ip_protocol().value(), IpProtocol::TCP);
  EXPECT_FALSE(buf.tcp_header());
}
