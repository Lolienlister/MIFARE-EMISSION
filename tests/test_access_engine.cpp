#include <gtest/gtest.h>

#include <chrono>
#include <ctime>
#include <filesystem>

#include "mifare_emission/access_engine.h"
#include "mifare_emission/crypto.h"
#include "mifare_emission/json_state.h"
#include "mifare_emission/time_policy.h"

#include "mock_rfid_reader.h"

using namespace mifare_emission;
using mifare_emission_tests::MockRfidReader;
namespace fs = std::filesystem;

namespace {

class TempDir {
public:
    TempDir() {
        path_ = fs::temp_directory_path() / ("mifare_ae_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(path_);
    }
    ~TempDir() { std::error_code ec; fs::remove_all(path_, ec); }
    fs::path path() const { return path_; }
private:
    fs::path path_;
};

std::chrono::system_clock::time_point local_tp(int hour, int minute) {
    std::tm tmv{};
    tmv.tm_year = 124;
    tmv.tm_mon = 0;
    tmv.tm_mday = 1;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_isdst = -1;
    return std::chrono::system_clock::from_time_t(std::mktime(&tmv));
}

MasterKey master(uint8_t seed = 0x42) {
    MasterKey k{};
    for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<uint8_t>(i * 7u + seed);
    }
    return k;
}

class AccessEngineFixture : public ::testing::Test {
protected:
    void SetUp() override {
        kdf = std::make_unique<BeltKdf>(master());
        store = std::make_unique<JsonStateStore>(tmp.path() / "state.json");
        store->load();
    }

    TempDir tmp;
    std::unique_ptr<BeltKdf> kdf;
    std::unique_ptr<JsonStateStore> store;
    TimePolicy policy{{8, 0}, {18, 0}};
};

}  // namespace

TEST_F(AccessEngineFixture, FirstUseUnknownUidAllows) {
    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);

    const Uid uid = {0x01, 0x02, 0x03, 0x04};
    auto r = engine.decide(uid, /*counter=*/0, local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::ALLOW);
    EXPECT_EQ(r.old_counter, 0u);
    EXPECT_EQ(r.new_counter, 1u);
    EXPECT_TRUE(r.state_mutated);

    const auto stored = store->find(uid);
    ASSERT_TRUE(stored.has_value());
    // state tracks the LAST counter the card showed (0), not the value we
    // are about to write to the card (1).
    EXPECT_EQ(stored->counter, 0u);
    EXPECT_EQ(stored->status, CardStatus::OK);
}

TEST_F(AccessEngineFixture, GreaterCounterAllowsAndUpdates) {
    const Uid uid = {0xAA};
    store->upsert(uid, {5, CardStatus::OK, std::chrono::system_clock::now()});

    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.decide(uid, 6, local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::ALLOW);
    EXPECT_EQ(r.old_counter, 6u);
    EXPECT_EQ(r.new_counter, 7u);
    // state catches up to what the card showed (6).
    EXPECT_EQ(store->find(uid)->counter, 6u);
}

TEST_F(AccessEngineFixture, EqualCounterIsReplayAndCompromises) {
    const Uid uid = {0xAA};
    store->upsert(uid, {10, CardStatus::OK, std::chrono::system_clock::now()});

    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.decide(uid, 10, local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::REPLAY);
    EXPECT_TRUE(r.state_mutated);
    EXPECT_EQ(store->find(uid)->status, CardStatus::COMPROMISED);
}

TEST_F(AccessEngineFixture, RegressedCounterIsCompromise) {
    const Uid uid = {0xBB};
    store->upsert(uid, {100, CardStatus::OK, std::chrono::system_clock::now()});

    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.decide(uid, 50, local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::COUNTER_REGRESSION);
    EXPECT_EQ(store->find(uid)->status, CardStatus::COMPROMISED);
}

TEST_F(AccessEngineFixture, CompromisedStaysCompromised) {
    const Uid uid = {0xCC};
    store->upsert(uid, {7, CardStatus::COMPROMISED, std::chrono::system_clock::now()});

    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.decide(uid, 99999, local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::COMPROMISED);
    EXPECT_FALSE(r.state_mutated);
    EXPECT_EQ(store->find(uid)->counter, 7u);
}

TEST_F(AccessEngineFixture, BlockedDeniesWithoutStateMutation) {
    const Uid uid = {0xDD};
    store->upsert(uid, {3, CardStatus::BLOCKED, std::chrono::system_clock::now()});

    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.decide(uid, 9999, local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::BLOCKED);
    EXPECT_FALSE(r.state_mutated);
}

TEST_F(AccessEngineFixture, OutsideTimeWindowDeniesEvenForUnknownUid) {
    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);

    const Uid uid = {0xEE};
    auto r = engine.decide(uid, 0, local_tp(7, 59));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::OUT_OF_TIME_WINDOW);
    EXPECT_FALSE(r.state_mutated);
    EXPECT_FALSE(store->find(uid).has_value());
}

TEST_F(AccessEngineFixture, OutsideTimeWindowDeniesEvenIfCompromised) {
    const Uid uid = {0xEE};
    store->upsert(uid, {5, CardStatus::COMPROMISED, std::chrono::system_clock::now()});

    MockRfidReader reader;
    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.decide(uid, 5, local_tp(7, 59));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::OUT_OF_TIME_WINDOW);
    EXPECT_EQ(store->find(uid)->status, CardStatus::COMPROMISED);
}

TEST_F(AccessEngineFixture, RunOnceRotatesKeyAndIncrementsCounter) {
    MockRfidReader reader;
    const Uid uid = {0x12, 0x34, 0x56, 0x78};
    reader.setUid(uid);

    const SectorKey initial_key = kdf->deriveSectorKey(uid, 0);
    reader.setAuthorizedKey(kCounterSector, initial_key);
    reader.setBlock(kCounterBlock, encodeCounter(0));

    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.runOnce(local_tp(10, 0));

    EXPECT_EQ(r.decision, Decision::ALLOW);
    EXPECT_EQ(r.old_counter, 0u);
    EXPECT_EQ(r.new_counter, 1u);

    const auto& writes = reader.writes();
    ASSERT_GE(writes.size(), 2u);
    EXPECT_EQ(writes[0].first, kCounterBlock);
    EXPECT_EQ(decodeCounter(writes[0].second), 1u);
    EXPECT_EQ(writes[1].first, kSectorTrailerBlock);
    const SectorKey new_key = kdf->deriveSectorKey(uid, 1);
    for (std::size_t i = 0; i < kSectorKeySize; ++i) {
        EXPECT_EQ(writes[1].second[i], new_key[i]);
    }
    EXPECT_EQ(store->find(uid)->counter, 0u);
}

TEST_F(AccessEngineFixture, TwoConsecutiveTapsBothAllow) {
    // Regression: state.counter must lag card.counter by 1, otherwise the
    // second legitimate tap is rejected as REPLAY.
    MockRfidReader reader;
    const Uid uid = {0x12, 0x34};
    reader.setUid(uid);
    reader.setAuthorizedKey(kCounterSector, kdf->deriveSectorKey(uid, 0));
    reader.setBlock(kCounterBlock, encodeCounter(0));

    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r1 = engine.runOnce(local_tp(10, 0));
    EXPECT_EQ(r1.decision, Decision::ALLOW);
    EXPECT_EQ(store->find(uid)->counter, 0u);

    // After the first ALLOW, runOnce wrote counter=1 to the card and rotated
    // the sector key to KDF(uid, 1). The mock simulates that by capturing
    // both writes; we now mirror the new state onto the mock for the second
    // tap. The auth top should be stored.counter + 1 = 1 (it must succeed on
    // the very first probe; no fallback).
    reader.setAuthorizedKey(kCounterSector, kdf->deriveSectorKey(uid, 1));
    reader.setBlock(kCounterBlock, encodeCounter(1));
    reader.clearWrites();

    auto r2 = engine.runOnce(local_tp(10, 1));
    EXPECT_EQ(r2.decision, Decision::ALLOW);
    EXPECT_EQ(r2.old_counter, 1u);
    EXPECT_EQ(r2.new_counter, 2u);
    EXPECT_EQ(store->find(uid)->counter, 1u);
    ASSERT_GE(reader.writes().size(), 2u);
    EXPECT_EQ(decodeCounter(reader.writes()[0].second), 2u);
}

TEST_F(AccessEngineFixture, RunOnceDetectsClonedCard) {
    MockRfidReader reader;
    const Uid uid = {0xAB, 0xCD};
    reader.setUid(uid);

    store->upsert(uid, {5, CardStatus::OK, std::chrono::system_clock::now()});
    reader.setBlock(kCounterBlock, encodeCounter(3));
    reader.setAuthorizedKey(kCounterSector, kdf->deriveSectorKey(uid, 3));

    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.runOnce(local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::COUNTER_REGRESSION);
    EXPECT_EQ(store->find(uid)->status, CardStatus::COMPROMISED);
    EXPECT_TRUE(reader.writes().empty());
}

TEST_F(AccessEngineFixture, RunOnceFailsWhenAuthFails) {
    MockRfidReader reader;
    const Uid uid = {0x99};
    reader.setUid(uid);
    reader.setBlock(kCounterBlock, encodeCounter(0));
    reader.setAuthorizedKey(kCounterSector, {0x00, 0x00, 0x00, 0x00, 0x00, 0x01});

    AccessEngine engine(&reader, store.get(), kdf.get(), policy, nullptr);
    auto r = engine.runOnce(local_tp(10, 0));
    EXPECT_EQ(r.decision, Decision::DENY);
    EXPECT_EQ(r.reason, DenyReason::CRYPTO_ERROR);
    EXPECT_FALSE(store->find(uid).has_value());
}
