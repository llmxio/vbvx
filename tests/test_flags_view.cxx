#include "gtest/gtest.h"
#include <type_traits>

#include "flags_view.hxx"

namespace some {

enum class TestFlags : uint8_t {
  None = 0,
  A = 1 << 0,
  B = 1 << 1,
  C = 1 << 2,
  D = 1 << 3,
};

} // namespace some

template <>
struct vbvx::enable_bitmask_operators<some::TestFlags> : std::true_type {};

static_assert(vbvx::enable_bitmask_operators_v<some::TestFlags>,
              "TestFlags should enable bitmask operators");

namespace {

using namespace some;
using namespace vbvx;

TEST(FlagsView, BasicSetClearToggleReset) {
  TestFlags flags = static_cast<TestFlags>(0);
  vbvx::FlagsView<TestFlags> fv(flags);

  // chainable set
  fv.set(TestFlags::A).set(TestFlags::C);
  EXPECT_TRUE(fv.has(TestFlags::A));
  EXPECT_TRUE(fv.has(TestFlags::C));
  EXPECT_FALSE(fv.has(TestFlags::B));
  EXPECT_TRUE(
      fv.has_all(static_cast<TestFlags>(static_cast<uint8_t>(TestFlags::A) |
                                        static_cast<uint8_t>(TestFlags::C))));

  // clear
  fv.clear(TestFlags::A);
  EXPECT_FALSE(fv.has(TestFlags::A));
  EXPECT_TRUE(fv.has(TestFlags::C));

  // toggle
  fv.toggle(TestFlags::B);
  EXPECT_TRUE(fv.has(TestFlags::B));
  fv.toggle(TestFlags::B);
  EXPECT_FALSE(fv.has(TestFlags::B));

  // reset
  fv.reset();
  EXPECT_FALSE(fv.has(TestFlags::A));
  EXPECT_FALSE(fv.has(TestFlags::C));
  EXPECT_EQ(fv.value(), static_cast<TestFlags>(0));
}

TEST(FlagsView, OperatorsAndShifts) {
  // operator| and in-place |=
  TestFlags ab = TestFlags::A | TestFlags::B;
  EXPECT_TRUE((static_cast<uint8_t>(ab) & static_cast<uint8_t>(TestFlags::A)));

  // in-place
  TestFlags t = TestFlags::A;
  t |= TestFlags::B;
  EXPECT_TRUE((static_cast<uint8_t>(t) & static_cast<uint8_t>(TestFlags::B)));

  // bitwise & gives zero for disjoint flags
  auto none = static_cast<TestFlags>(static_cast<uint8_t>(TestFlags::A) &
                                     static_cast<uint8_t>(TestFlags::C));
  EXPECT_EQ(none, static_cast<TestFlags>(0));

  // shifts
  TestFlags shifted = TestFlags::A << 1;
  EXPECT_EQ(shifted, TestFlags::B);

  shifted = TestFlags::B >> 1;
  EXPECT_EQ(shifted, TestFlags::A);

  // XOR and ^=
  TestFlags x = TestFlags::A ^ TestFlags::B;
  EXPECT_TRUE((static_cast<uint8_t>(x) & static_cast<uint8_t>(TestFlags::A)));
  x ^= TestFlags::A;
  EXPECT_FALSE((static_cast<uint8_t>(x) & static_cast<uint8_t>(TestFlags::A)));
}

TEST(ConstFlagsView, ReadOnlyChecksAndConversion) {
  TestFlags f = static_cast<TestFlags>(static_cast<uint8_t>(TestFlags::A) |
                                       static_cast<uint8_t>(TestFlags::C));
  const TestFlags cf = f;
  vbvx::ConstFlagsView<TestFlags> cv(cf);

  EXPECT_TRUE(cv.has(TestFlags::A));
  EXPECT_TRUE(
      cv.has_all(static_cast<TestFlags>(static_cast<uint8_t>(TestFlags::A) |
                                        static_cast<uint8_t>(TestFlags::C))));
  EXPECT_EQ(static_cast<TestFlags>(cv), cf);

  // conversion from FlagsView
  TestFlags mutable_flags = static_cast<TestFlags>(0);
  vbvx::FlagsView<TestFlags> fv(mutable_flags);
  fv.set(TestFlags::B);
  vbvx::ConstFlagsView<TestFlags> cv2 = fv;
  EXPECT_TRUE(cv2.has(TestFlags::B));
}

} // namespace
