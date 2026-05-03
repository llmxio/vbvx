#include <gtest/gtest.h>
#include <array>
#include <cstring>

#include "vbvx/srv6_header.hxx"
#include "header_view.hxx"

using namespace vbvx;

TEST(Srv6HeaderTest, BasicAccessors) {
  // Build a SRH with two segments (2 * 16 = 32 bytes) and no TLVs.
  const size_t total_size = 8 + 2 * 16;
  std::array<uint8_t, 8 + 2 * 16> data{};

  SRv6Header tmp{};
  tmp.next_header = 6; // TCP (arbitrary)
  tmp.hdr_ext_len = static_cast<uint8_t>(
      (total_size / 8) - 1); // (HdrExtLen + 1) * 8 == total_size
  tmp.routing_type = 4;      // SRH routing type
  tmp.segments_left = 1;     // 2 segments, active segment index = 1
  tmp.last_entry = 1;        // index of last segment (0-based)
  tmp.flags = 0;
  tmp.tag_be = autoswap(static_cast<uint16_t>(0));

  std::memcpy(data.data(), &tmp, sizeof(tmp));

  // Fill segment 0 and segment 1 with distinct bytes to validate accessors
  for (size_t i = 0; i < 16; ++i) {
    data[8 + i] = static_cast<uint8_t>(0x10 + i);
  }
  for (size_t i = 0; i < 16; ++i) {
    data[8 + 16 + i] = static_cast<uint8_t>(0x80 + i);
  }

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->routing_type_value(), 4u);
  EXPECT_TRUE(hv->is_valid_routing_type());
  EXPECT_EQ(hv->header_length_bytes(), static_cast<uint16_t>(total_size));
  EXPECT_EQ(hv->segments_count(), 2u);
  EXPECT_EQ(hv->tlv_bytes_len(), 0u);

  auto s0 = hv->segment_at(0);
  EXPECT_EQ(s0[0], 0x10u);
  EXPECT_EQ(s0[15], static_cast<uint8_t>(0x10 + 15));

  auto s1 = hv->segment_at(1);
  EXPECT_EQ(s1[0], 0x80u);
  EXPECT_EQ(s1[15], static_cast<uint8_t>(0x80 + 15));
}

TEST(Srv6HeaderTest, ValidateAndSafeAccessors) {
  std::array<uint8_t, 8 + 2 * 16> data{};
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((data.size() / 8) - 1);
  hdr.routing_type = 4;
  hdr.segments_left = 1;
  hdr.last_entry = 1;
  std::memcpy(data.data(), &hdr, sizeof(hdr));

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  EXPECT_TRUE(hv->validate_srh_bounds(static_cast<uint16_t>(data.size())));

  auto s0 = hv->safe_segment_at(0, static_cast<uint16_t>(data.size()));
  ASSERT_TRUE(s0.has_value());
  EXPECT_EQ(s0->size(), 16u);

  auto s2 = hv->safe_segment_at(2, static_cast<uint16_t>(data.size()));
  EXPECT_FALSE(s2.has_value());
}

TEST(Srv6HeaderTest, InvalidLastEntryRejectedByValidator) {
  std::array<uint8_t, 24> data{}; // 8-byte SRH + 16 bytes payload
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((data.size() / 8) - 1);
  hdr.routing_type = 4;
  hdr.segments_left = 0;
  hdr.last_entry = 2; // max_LE is 0 for hdr_ext_len=2
  std::memcpy(data.data(), &hdr, sizeof(hdr));

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  EXPECT_FALSE(hv->validate_srh_bounds(static_cast<uint16_t>(data.size())));
}

TEST(Srv6HeaderTest, SafeTlvRegion) {
  std::array<uint8_t, 40> data{}; // 8 + 16 segment + 16 tlv area
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((data.size() / 8) - 1);
  hdr.routing_type = 4;
  hdr.segments_left = 0;
  hdr.last_entry = 0;
  std::memcpy(data.data(), &hdr, sizeof(hdr));

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);

  auto tlv = hv->safe_tlv_region(static_cast<uint16_t>(data.size()));
  ASSERT_TRUE(tlv.has_value());
  EXPECT_EQ(tlv->size(), 16u);
  EXPECT_EQ(tlv->data(), data.data() + 24);

  // Invalid SRH metadata should make safe_tlv_region reject the header.
  hdr.last_entry = 3;
  std::memcpy(data.data(), &hdr, sizeof(hdr));
  tlv = hv->safe_tlv_region(static_cast<uint16_t>(data.size()));
  EXPECT_FALSE(tlv.has_value());
}
