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

TEST(Srv6TlvTest, PadNZeroLength) {
  // PadN with length 0 should be parsed (length==0, total_len==2). Any
  // trailing zero bytes from 8-octet rounding are Pad1 TLVs and should be
  // returned as type 0, total_len==1.
  const size_t tlv_bytes_needed = 2; // PadN (type + length)
  const size_t min_total = 8 + 16 + tlv_bytes_needed;
  const size_t hdr_units = (min_total + 7) / 8;
  const size_t total_size = hdr_units * 8;

  std::vector<uint8_t> data(total_size, 0u);
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) - 1);
  hdr.routing_type = 4;
  hdr.last_entry = 0;
  std::memcpy(data.data(), &hdr, sizeof(hdr));
  for (size_t i = 0; i < 16; ++i) {
    data[8 + i] = static_cast<uint8_t>(0x10 + i);
  }

  size_t tlv_pos = 8 + 16;
  data[tlv_pos++] = 0x04; // PadN
  data[tlv_pos++] = 0x00; // length = 0

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
  SRv6Tlv t;

  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 4u);
  EXPECT_EQ(t.length, 0u);
  EXPECT_EQ(t.total_len, 2u);

  // Any remaining bytes should parse as Pad1 TLVs (type 0)
  while (it.next(t)) {
    EXPECT_EQ(t.type, 0u);
    EXPECT_EQ(t.total_len, 1u);
  }
}

TEST(Srv6TlvTest, HmacMinAndInvalidLengths) {
  // HMAC TLV with length == 6 is the minimal valid (2 + 4 + 0) and should
  // be accepted by SRv6HmacTlvView. A TLV with length == 5 is too short and
  // the view should report invalid.

  // Valid minimal HMAC (length=6)
  {
    const size_t tlv_bytes_needed = 2 + 6;
    const size_t min_total = 8 + 16 + tlv_bytes_needed;
    const size_t hdr_units = (min_total + 7) / 8;
    const size_t total_size = hdr_units * 8;

    std::vector<uint8_t> data(total_size, 0u);
    SRv6Header hdr{};
    hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) - 1);
    hdr.routing_type = 4;
    hdr.last_entry = 0;
    std::memcpy(data.data(), &hdr, sizeof(hdr));
    size_t tlv_pos = 8 + 16;

    data[tlv_pos++] = 0x05; // HMAC
    data[tlv_pos++] = 6;    // length
    uint16_t d_res = autoswap(static_cast<uint16_t>(0x0000u));
    std::memcpy(&data[tlv_pos], &d_res, 2);
    tlv_pos += 2;
    uint32_t kid = autoswap(static_cast<uint32_t>(0xAABBCCDDu));
    std::memcpy(&data[tlv_pos], &kid, 4);
    tlv_pos += 4;

    HeaderView<SRv6Header> hv(data.data());
    ASSERT_TRUE(hv);
    SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
    SRv6Tlv t;
    ASSERT_TRUE(it.next(t));
    EXPECT_EQ(t.type, 5u);
    EXPECT_EQ(t.length, 6u);

    SRv6HmacTlvView hvw{t.value, t.length};
    EXPECT_TRUE(hvw.valid());
    EXPECT_FALSE(hvw.d_bit());
    EXPECT_EQ(hvw.key_id(), 0xAABBCCDDu);
    auto h = hvw.hmac();
    EXPECT_EQ(h.size(), 0u);
  }

  // Invalid HMAC (length=5) -> view reports invalid
  {
    const size_t tlv_bytes_needed = 2 + 5;
    const size_t min_total = 8 + 16 + tlv_bytes_needed;
    const size_t hdr_units = (min_total + 7) / 8;
    const size_t total_size = hdr_units * 8;

    std::vector<uint8_t> data(total_size, 0u);
    SRv6Header hdr{};
    hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) - 1);
    hdr.routing_type = 4;
    hdr.last_entry = 0;
    std::memcpy(data.data(), &hdr, sizeof(hdr));
    size_t tlv_pos = 8 + 16;

    data[tlv_pos++] = 0x05; // HMAC
    data[tlv_pos++] = 5;    // length (too short)
    // provide 5 bytes of content (2 byte D/res + 3 partial bytes)
    data[tlv_pos++] = 0x00;
    data[tlv_pos++] = 0x00;
    data[tlv_pos++] = 0xAA;
    data[tlv_pos++] = 0xBB;
    data[tlv_pos++] = 0xCC;

    HeaderView<SRv6Header> hv(data.data());
    ASSERT_TRUE(hv);
    SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
    SRv6Tlv t;
    ASSERT_TRUE(it.next(t));
    EXPECT_EQ(t.type, 5u);
    EXPECT_EQ(t.length, 5u);

    SRv6HmacTlvView hvw{t.value, t.length};
    EXPECT_FALSE(hvw.valid());
  }
}

TEST(Srv6TlvTest, UnknownTlvAndIncompleteHeader) {
  // Unknown TLV type should be returned as-is. If the buffer ends with a
  // single trailing byte (type only), iterator should detect the truncated
  // header and return false on the next() call.
  const size_t tlv_bytes_needed =
      2 + 2 + 1; // unknown TLV (type+len+2) + 1 byte

  const size_t min_total = 8 + 16 + tlv_bytes_needed;
  const size_t hdr_units = (min_total + 7) / 8;
  const size_t total_size = hdr_units * 8;

  std::vector<uint8_t> data(total_size, 0u);
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) - 1);
  hdr.routing_type = 4;
  hdr.last_entry = 0;
  std::memcpy(data.data(), &hdr, sizeof(hdr));
  size_t tlv_pos = 8 + 16;

  data[tlv_pos++] = 0xFF; // unknown type
  data[tlv_pos++] = 2;    // length
  data[tlv_pos++] = 0x11;
  data[tlv_pos++] = 0x22;

  // trailing single byte (incomplete TLV header)
  data[tlv_pos++] = 0x04;

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
  SRv6Tlv t;

  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 0xFFu);
  EXPECT_EQ(t.length, 2u);
  EXPECT_EQ(t.total_len, 4u);

  // Due to 8-octet rounding, the trailing byte is followed by a zero; this
  // parses as PadN with length==0 rather than a truncated header.
  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 4u);
  EXPECT_EQ(t.length, 0u);
}

TEST(Srv6TlvTest, MultipleHmacTlvs) {
  // Two HMAC TLVs back-to-back: first minimal (len=6), second with 8-byte HMAC
  const size_t tlv_bytes_needed = (2 + 6) + (2 + 14);
  const size_t min_total = 8 + 16 + tlv_bytes_needed;
  const size_t hdr_units = (min_total + 7) / 8;
  const size_t total_size = hdr_units * 8;

  std::vector<uint8_t> data(total_size, 0u);
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) - 1);
  hdr.routing_type = 4;
  hdr.last_entry = 0;
  std::memcpy(data.data(), &hdr, sizeof(hdr));
  size_t tlv_pos = 8 + 16;

  // First HMAC TLV (minimal)
  data[tlv_pos++] = 0x05;
  data[tlv_pos++] = 6;
  uint16_t d_res0 = autoswap(static_cast<uint16_t>(0x0000u));
  std::memcpy(&data[tlv_pos], &d_res0, 2);
  tlv_pos += 2;
  uint32_t kid0 = autoswap(static_cast<uint32_t>(0xA1A2A3A4u));
  std::memcpy(&data[tlv_pos], &kid0, 4);
  tlv_pos += 4;

  // Second HMAC TLV (with D bit and 8-byte HMAC)
  data[tlv_pos++] = 0x05;
  data[tlv_pos++] = 14;
  uint16_t d_res1 = autoswap(static_cast<uint16_t>(0x8000u));
  std::memcpy(&data[tlv_pos], &d_res1, 2);
  tlv_pos += 2;
  uint32_t kid1 = autoswap(static_cast<uint32_t>(0x01020304u));
  std::memcpy(&data[tlv_pos], &kid1, 4);
  tlv_pos += 4;
  for (uint8_t i = 0; i < 8; ++i) {
    data[tlv_pos++] = static_cast<uint8_t>(0xF0 + i);
  }

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
  SRv6Tlv t;

  // First TLV
  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 5u);
  EXPECT_EQ(t.length, 6u);
  SRv6HmacTlvView h0{t.value, t.length};
  EXPECT_TRUE(h0.valid());
  EXPECT_FALSE(h0.d_bit());
  EXPECT_EQ(h0.key_id(), 0xA1A2A3A4u);
  EXPECT_EQ(h0.hmac().size(), 0u);

  // Second TLV
  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 5u);
  EXPECT_EQ(t.length, 14u);
  SRv6HmacTlvView h1{t.value, t.length};
  EXPECT_TRUE(h1.valid());
  EXPECT_TRUE(h1.d_bit());
  EXPECT_EQ(h1.key_id(), 0x01020304u);
  auto h = h1.hmac();
  ASSERT_EQ(h.size(), 8u);
  for (size_t i = 0; i < h.size(); ++i) {
    EXPECT_EQ(h[i], static_cast<uint8_t>(0xF0 + i));
  }

  // Any padding bytes should be Pad1 or PadN as handled elsewhere
  while (it.next(t)) {
    EXPECT_TRUE(t.type == 0u || t.type == 4u);
  }
}

TEST(Srv6TlvTest, MalformedChainedTlv) {
  // First TLV valid, second TLV declares a length much larger than remaining
  // bytes — iterator should parse the first TLV and then return false when
  // encountering the malformed second TLV.
  const size_t tlv_bytes_needed =
      3 + 2 + 1; // first (3 bytes), second header (2) + 1 byte content
  const size_t min_total = 8 + 16 + tlv_bytes_needed;
  const size_t hdr_units = (min_total + 7) / 8;
  const size_t total_size = hdr_units * 8;

  std::vector<uint8_t> data(total_size, 0u);
  SRv6Header hdr{};
  hdr.hdr_ext_len = static_cast<uint8_t>((total_size / 8) - 1);
  hdr.routing_type = 4;
  hdr.last_entry = 0;
  std::memcpy(data.data(), &hdr, sizeof(hdr));
  size_t tlv_pos = 8 + 16;

  // First TLV: unknown type 0x11, length=1, value=0xAA
  data[tlv_pos++] = 0x11;
  data[tlv_pos++] = 1;
  data[tlv_pos++] = 0xAA;

  // Second TLV: unknown type 0x12, length=100 -> truncated by buffer
  data[tlv_pos++] = 0x12;
  data[tlv_pos++] = 100;
  data[tlv_pos++] = 0x55; // one byte of content only

  HeaderView<SRv6Header> hv(data.data());
  ASSERT_TRUE(hv);
  SRv6TlvIterator it(hv->tlv_first_ptr(), hv->tlv_bytes_len());
  SRv6Tlv t;

  // First TLV should be returned
  ASSERT_TRUE(it.next(t));
  EXPECT_EQ(t.type, 0x11u);
  EXPECT_EQ(t.length, 1u);
  EXPECT_EQ(t.total_len, 3u);

  // Second TLV is malformed/truncated; iterator should return false
  EXPECT_FALSE(it.next(t));
}
