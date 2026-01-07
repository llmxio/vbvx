#include <gtest/gtest.h>

#include "header_view.hxx"
#include "types/icmp4.hxx"

using namespace vbvx;
using enum ICMPv4Type;

class IcmpHeaderBytesFixture : public ::testing::Test {
protected:
  ICMPHeader tmp{};
  std::array<uint8_t, sizeof(ICMPHeader)> raw{};

  void SetUp() override {
    tmp.type = static_cast<uint8_t>(EchoRequest);
    tmp.code = 0;
    tmp.set_checksum(0x1234);
    std::memcpy(raw.data(), &tmp, sizeof(tmp));
  }

  HeaderView<ICMPHeader> hv_view() const {
    return HeaderView<ICMPHeader>(raw.data());
  }
};

TEST(IcmpTypeTest, KnownTypes) {
  ICMPHeader h{};

  h.type = 0;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), EchoReply);

  h.type = 3;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), DestinationUnreachable);

  h.type = 4;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), SourceQuench);

  h.type = 6;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), AlternateHostAddress);

  h.type = 8;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), EchoRequest);

  h.type = 42;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), ExtendedEchoRequest);

  h.type = 43;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), ExtendedEchoReply);

  h.type = 253;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), Experiment1);

  h.type = 255;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), Reserved);
}

TEST(IcmpTypeTest, UnassignedReturnsNullopt) {
  ICMPHeader h{};
  h.type = 7; // unassigned
  EXPECT_FALSE(h.type_known().has_value());

  h.type = 44; // unassigned range
  EXPECT_FALSE(h.type_known().has_value());
}

TEST(IcmpHeaderTest, LayoutAndAlignment) {
  static_assert(sizeof(ICMPHeader) == 4, "Wrong ICMP header size");
  EXPECT_EQ(sizeof(ICMPHeader), 4u);
  EXPECT_EQ(alignof(ICMPHeader), 1u);
}

TEST_F(IcmpHeaderBytesFixture, HeaderFieldsParsed) {
  auto hv = hv_view();
  ASSERT_TRUE(hv);

  EXPECT_EQ(hv->type_u8(), tmp.type);
  EXPECT_EQ(hv->code_u8(), tmp.code);
  EXPECT_EQ(hv->checksum(), tmp.checksum());
  ASSERT_TRUE(hv->type_known().has_value());
  EXPECT_EQ(hv->type_known().value(), EchoRequest);
}

TEST_F(IcmpHeaderBytesFixture, ZeroCopyReflectsMutations) {
  auto hv = hv_view();
  raw[0] = 7; // change type to unassigned
  EXPECT_EQ(hv->type_u8(), 7);
  EXPECT_FALSE(hv->type_known().has_value());
}

TEST_F(IcmpHeaderBytesFixture, CopyReturnsValueWithSameFields) {
  auto hv = hv_view();
  auto cp = hv.copy();
  EXPECT_EQ(cp.type_u8(), hv->type_u8());
  EXPECT_EQ(cp.code_u8(), hv->code_u8());
  EXPECT_EQ(cp.checksum(), hv->checksum());
  // Modifying copy doesn't affect view
  cp.set_checksum(0xBEEF);
  EXPECT_NE(cp.checksum(), hv->checksum());
}
