#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <cstring>

#include "header_view.hxx"
#include "vbvx/srv6_header.hxx"

using namespace vbvx;

TEST(Srv6TlvTest, ParsePad1PadNAndHmac) {
  // Build SRH: 1 segment (16 bytes) + TLVs (Pad1, PadN(3), HMAC with 8-byte
  // HMAC) We need to size the SRH to a multiple of 8 bytes. Build the minimum
  // buffer for fixed header + one segment + TLVs, then round up to 8.
  const size_t tlv_bytes_needed =
      1 + (2 + 3) + (2 + 14); // Pad1 + PadN(3) + HMAC(14)
  const size_t min_total =
      8 + 16 + tlv_bytes_needed;                // base + one segment + TLVs
  const size_t hdr_units = (min_total + 7) / 8; // ceil(min_total / 8)
  const size_t total_size = hdr_units * 8;

  std::vector<uint8_t> data(total_size, 0u);

  // Prepare header
  SRv6Header hdr{};
  hdr.next_header = 6; // TCP arbitrary
  hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) -
                                         1); // (HdrExtLen +1)*8 == total_size
  hdr.routing_type = 4;
  hdr.segments_left = 0;
  hdr.last_entry = 0; // one segment
  hdr.flags = 0;
  hdr.tag_be = autoswap(static_cast<uint16_t>(0));

  std::memcpy(data.data(), &hdr, sizeof(hdr));
  // Fill the single segment with pattern
  for (size_t i = 0; i < 16; ++i) {
    data[8 + i] = static_cast<uint8_t>(0xAA + i);
  }

  size_t tlv_pos = 8 + 16;

  // Pad1 (type 0)
  data[tlv_pos++] = 0x00;

  // PadN (type 4, length=3)
  data[tlv_pos++] = 0x04;
  data[tlv_pos++] = 0x03;
  data[tlv_pos++] = 0x00;
  data[tlv_pos++] = 0x00;
  data[tlv_pos++] = 0x00;

  // HMAC TLV (type 5) length = 2 + 4 + 8 = 14
  data[tlv_pos++] = 0x05; // type
  data[tlv_pos++] = 14;   // length
  // D + RESERVED (16 bits) -> D = 1 in high bit
  uint16_t d_res = autoswap(static_cast<uint16_t>(0x8000u));
  std::memcpy(&data[tlv_pos], &d_res, 2);
  tlv_pos += 2;
  // HMAC Key ID (4 bytes)
  uint32_t kid = autoswap(static_cast<uint32_t>(0x11223344u));
  std::memcpy(&data[tlv_pos], &kid, 4);
  tlv_pos += 4;
  // HMAC (8 bytes)
  for (uint8_t i = 0; i < 8; ++i) {
    data[tlv_pos++] = static_cast<uint8_t>(i + 1);
  }

  ASSERT_LE(tlv_pos, data.size());
  // Any extra bytes (due to rounding to 8-octet units) must be zero padding.
  for (size_t i = tlv_pos; i < data.size(); ++i) {
    EXPECT_EQ(data[i], 0u);
  }

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->segments_count(), 1u);
  EXPECT_EQ(hv->tlv_bytes_len(), static_cast<size_t>(data.size() - (8 + 16)));

  auto tlv_ptr = hv->tlv_first_ptr();
  SRv6TlvIterator it(tlv_ptr, hv->tlv_bytes_len());
  SRv6Tlv t;

  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 0u);
  EXPECT_EQ(t.total_len, 1u);

  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 4u);
  EXPECT_EQ(t.length, 3u);
  EXPECT_EQ(t.total_len, 5u);
  for (size_t i = 0; i < 3; ++i) {
    EXPECT_EQ(t.value[i], 0u);
  }

  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 5u);
  EXPECT_EQ(t.length, 14u);
  // Interpret HMAC TLV
  SRv6HmacTlvView hvw{t.value, t.length};
  EXPECT_TRUE(hvw.valid());
  EXPECT_TRUE(hvw.d_bit());
  EXPECT_EQ(hvw.key_id(), 0x11223344u);
  auto h = hvw.hmac();
  ASSERT_EQ(h.size(), 8u);
  for (size_t i = 0; i < h.size(); ++i) {
    EXPECT_EQ(h[i], static_cast<uint8_t>(i + 1));
  }

  // Consume any trailing padding Pad1 TLVs that may exist due to 8-octet
  // rounding of the SRH length. These must be Pad1 (type 0) single bytes.
  while (it.next(t)) {
    EXPECT_EQ(t.type, 0u);
    EXPECT_EQ(t.total_len, 1u);
  }
}

TEST(Srv6TlvTest, TruncatedTlvHandled) {
  // TLV area too short for declared length
  std::array<uint8_t, 8 + 16 + 3> data{}; // only 3 bytes of TLVs

  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>(((data.size()) / 8) - 1);
  hdr.routing_type = 4;
  hdr.last_entry = 0;
  std::memcpy(data.data(), &hdr, sizeof(hdr));

  size_t tlv_pos = 8 + 16;
  data[tlv_pos++] = 0x05; // HMAC
  data[tlv_pos++] = 14;   // length says 14, but buffer is too short
  data[tlv_pos++] = 0x00; // partial content

  HeaderView<SRv6Header> hv(data.data());
  SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
  SRv6Tlv t;
  // iterator should detect truncation and return false
  EXPECT_FALSE(it.next(t));
}
