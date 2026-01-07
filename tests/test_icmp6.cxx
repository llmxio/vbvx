#include <gtest/gtest.h>

#include "types/icmp6.hxx"

using namespace vbvx;
using enum ICMPv6Type;

TEST(Icmpv6TypeTest, KnownTypes) {
  ICMPv6Header h{};

  h.type = 1;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), DestinationUnreachable);

  h.type = 2;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), PacketTooBig);

  h.type = 3;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), TimeExceeded);

  h.type = 4;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), ParameterProblem);

  h.type = 128;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), EchoRequest);

  h.type = 129;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), EchoReply);

  h.type = 133;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), RouterSolicitation);

  h.type = 134;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), RouterAdvertisement);

  h.type = 160;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), ExtendedEchoRequest);

  h.type = 161;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), ExtendedEchoReply);

  h.type = 255;
  ASSERT_TRUE(h.type_known().has_value());
  EXPECT_EQ(h.type_known().value(), Reserved);
}

TEST(Icmpv6TypeTest, UnassignedReturnsNullopt) {
  ICMPv6Header h{};
  h.type = 5; // unassigned
  EXPECT_FALSE(h.type_known().has_value());

  h.type = 102; // unassigned range
  EXPECT_FALSE(h.type_known().has_value());
}
