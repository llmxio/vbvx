#include <gtest/gtest.h>
#include "header_view.hxx"
#include "auto_swap.hxx"

#include "vbvx/ether.hxx"
#include "vbvx/arp.hxx"

#include <array>
#include <bit>
#include <cstring>
#include <string>

using namespace vbvx;

static_assert(WireHeader<EtherHeader>);
static_assert(WireHeader<ArpHeader>);
static_assert(!WireHeader<std::string>);

TEST(HeaderViewTest, DefaultConstructedReturnsFalseAndCopyZeroed) {
  HeaderView<EtherHeader> hv;
  EXPECT_FALSE(hv);
  EXPECT_EQ(hv.get(), nullptr);

  auto copy = hv.copy();
  EXPECT_EQ(copy.type(), 0u);
  for (auto b : copy.dst_mac()) {
    EXPECT_EQ(b, 0u);
  }
}

TEST(HeaderViewTest, ConstructFromTypedPointerAndAccessors) {
  EtherHeader eth{};
  eth.type_be = autoswap(std::to_underlying(EtherType::ARP));
  const uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
  std::memcpy(eth.dst, mac, 6);

  HeaderView<EtherHeader> hv(&eth);
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->type(), std::to_underlying(EtherType::ARP));
  EXPECT_EQ(hv.get(), &eth);

  auto ref = *hv;
  EXPECT_EQ(ref.type(), eth.type());
  auto d = hv->dst_mac();
  EXPECT_EQ(d[0], 1u);
  EXPECT_EQ(d[5], 6u);
}

TEST(HeaderViewTest, ConstructFromUint8Pointer) {
  std::array<uint8_t, sizeof(EtherHeader)> data{};
  auto eth = reinterpret_cast<EtherHeader*>(data.data());
  eth->type_be = autoswap(std::to_underlying(EtherType::IPv4));

  HeaderView<EtherHeader> hv(data.data());
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->type(), std::to_underlying(EtherType::IPv4));
}

TEST(HeaderViewTest, CopyReflectsUnderlyingMemoryAtTimeOfCall) {
  std::array<uint8_t, sizeof(EtherHeader)> data{};

  EtherHeader tmp{};
  tmp.type_be = autoswap(std::to_underlying(EtherType::IPv6));
  std::memcpy(data.data(), &tmp, sizeof(tmp));

  HeaderView<EtherHeader> hv(data.data());
  auto c1 = hv.copy();
  EXPECT_EQ(c1.type(), std::to_underlying(EtherType::IPv6));

  EtherHeader tmp2{};
  tmp2.type_be = autoswap(std::to_underlying(EtherType::ARP));
  std::memcpy(data.data(), &tmp2, sizeof(tmp2));

  auto c2 = hv.copy();
  EXPECT_EQ(c2.type(), std::to_underlying(EtherType::ARP));
}

TEST(HeaderViewTest, WorksWithArpHeaderAndFieldAccessors) {
  std::array<uint8_t, sizeof(ArpHeader)> data{};
  ArpHeader tmp{};
  tmp.htype_be = autoswap(std::to_underlying(ArpHType::Ethernet));
  tmp.ptype_be = autoswap(std::to_underlying(EtherType::IPv4));
  tmp.set_opcode(ArpOpCode::Request);
  uint8_t sha[6] = {10, 11, 12, 13, 14, 15};
  std::memcpy(tmp.sha, sha, 6);
  std::memcpy(data.data(), &tmp, sizeof(tmp));

  HeaderView<ArpHeader> hv(data.data());
  ASSERT_TRUE(hv);
  EXPECT_EQ(hv->htype(), ArpHType::Ethernet);
  EXPECT_EQ(hv->ptype(), EtherType::IPv4);
  EXPECT_EQ(hv->opcode(), ArpOpCode::Request);
  auto mac = hv->sender_mac();
  EXPECT_EQ(mac[0], 10u);
  EXPECT_EQ(mac[5], 15u);

  auto cp = hv.copy();
  EXPECT_EQ(cp.htype(), ArpHType::Ethernet);
}
