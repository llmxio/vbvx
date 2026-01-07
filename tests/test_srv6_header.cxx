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
