#include <gtest/gtest.h>
#include "header_view.hxx"
#include "auto_swap.hxx"
#include "types/arp.hxx"
#include "types/ether.hxx"

#include <array>
#include <cstring>

using namespace vbvx;

class ArpHeaderFixture : public ::testing::Test {
protected:
  ArpHeader h;
  std::array<uint8_t, 6> sha{1, 2, 3, 4, 5, 6};
  std::array<uint8_t, 6> tha{10, 11, 12, 13, 14, 15};
  std::array<uint8_t, 4> spa{192, 168, 0, 1};
  std::array<uint8_t, 4> tpa{10, 0, 0, 5};

  void SetUp() override {
    std::memcpy(h.sha, sha.data(), 6);
    std::memcpy(h.tha, tha.data(), 6);
    std::memcpy(h.spa, spa.data(), 4);
    std::memcpy(h.tpa, tpa.data(), 4);
  }
};

TEST(ArpTypeTest, LayoutAndAlignment) {
  static_assert(sizeof(ArpHeader) == 28, "Wrong ARP header size");
  EXPECT_EQ(sizeof(ArpHeader), 28u);
  EXPECT_EQ(alignof(ArpHeader), 1u);
}

TEST(ArpHeaderTest, HTypeAndProtocol) {
  ArpHeader h{};

  h.htype_be = autoswap(std::to_underlying(ArpHType::Ethernet));
  EXPECT_EQ(h.htype(), ArpHType::Ethernet);

  h.ptype_be = autoswap(std::to_underlying(EtherType::IPv4));
  EXPECT_EQ(h.ptype(), EtherType::IPv4);

  h.ptype_be = autoswap(std::to_underlying(EtherType::ARP));
  EXPECT_EQ(h.ptype(), EtherType::ARP);
}

TEST(ArpHeaderTest, OpcodeSetAndGet) {
  ArpHeader h{};

  h.oper_be = autoswap(std::to_underlying(ArpOpCode::Request));
  EXPECT_EQ(h.opcode(), ArpOpCode::Request);

  h.oper_be = autoswap(std::to_underlying(ArpOpCode::Reply));
  EXPECT_EQ(h.opcode(), ArpOpCode::Reply);
}

TEST_F(ArpHeaderFixture, SenderMacSpanReflectsStorage) {
  auto sm = h.sender_mac();
  ASSERT_EQ(sm.size(), 6u);
  for (size_t i = 0; i < 6; ++i)
    EXPECT_EQ(sm[i], sha[i]);

  // Ensure span reflects underlying storage
  h.sha[0] = 0xAA;
  EXPECT_EQ(h.sender_mac()[0], 0xAA);
}

TEST_F(ArpHeaderFixture, TargetMacFields) {
  auto tm = h.target_mac();
  for (size_t i = 0; i < 6; ++i)
    EXPECT_EQ(tm[i], tha[i]);
}

TEST_F(ArpHeaderFixture, SenderIpv4Host) {
  uint32_t expected_sender = (uint32_t(192) << 24) | (uint32_t(168) << 16) |
                             (uint32_t(0) << 8) | uint32_t(1);
  EXPECT_EQ(h.sender_ipv4_host(), expected_sender);
}

TEST_F(ArpHeaderFixture, TargetIpv4Host) {
  uint32_t expected_target = (uint32_t(10) << 24) | (uint32_t(0) << 16) |
                             (uint32_t(0) << 8) | uint32_t(5);
  EXPECT_EQ(h.target_ipv4_host(), expected_target);
}

// Fixture for tests that operate on raw bytes and HeaderView
class ArpHeaderBytesFixture : public ::testing::Test {
protected:
  ArpHeader tmp{};
  std::array<uint8_t, 6> sha{1, 2, 3, 4, 5, 6};
  std::array<uint8_t, 4> spa{192, 168, 0, 1};
  std::array<uint8_t, sizeof(ArpHeader)> raw{};

  void SetUp() override {
    tmp.htype_be = autoswap(std::to_underlying(ArpHType::Ethernet));
    tmp.ptype_be = autoswap(std::to_underlying(EtherType::IPv4));
    tmp.oper_be = autoswap(std::to_underlying(ArpOpCode::Request));
    std::memcpy(tmp.sha, sha.data(), 6);
    std::memcpy(tmp.spa, spa.data(), 4);
    std::memcpy(raw.data(), &tmp, sizeof(tmp));
  }

  HeaderView<ArpHeader> hv_view() const {
    return HeaderView<ArpHeader>(raw.data());
  }
};

TEST_F(ArpHeaderBytesFixture, HeaderFieldsParsed) {
  auto hv = hv_view();
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->htype(), ArpHType::Ethernet);
  EXPECT_EQ(hv->ptype(), EtherType::IPv4);
  EXPECT_EQ(hv->opcode(), ArpOpCode::Request);

  auto sm = hv->sender_mac();
  for (size_t i = 0; i < 6; ++i)
    EXPECT_EQ(sm[i], sha[i]);
}

TEST_F(ArpHeaderBytesFixture, ZeroCopyReflectsMutations) {
  auto hv = hv_view();
  // Mutating the underlying bytes is reflected in the view (zero-copy)
  raw[8] = 0xAA; // first byte of sender_mac
  EXPECT_EQ(hv->sender_mac()[0], 0xAA);
}

TEST_F(ArpHeaderBytesFixture, CopyReturnsValueWithSameFields) {
  auto hv = hv_view();
  auto cp = hv.copy();
  EXPECT_EQ(cp.htype(), hv->htype());
  EXPECT_EQ(cp.opcode(), hv->opcode());
}
