#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>

#include "mifare_emission/json_state.h"

#include <nlohmann/json.hpp>

using namespace mifare_emission;
namespace fs = std::filesystem;

namespace {

class TempDir {
public:
    TempDir() {
        path_ = fs::temp_directory_path() / ("mifare_test_" + std::to_string(::getpid()) +
                                              "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    fs::path path() const { return path_; }
private:
    fs::path path_;
};

}  // namespace

TEST(JsonState, EmptyStoreLoadsEmpty) {
    TempDir tmp;
    JsonStateStore store(tmp.path() / "state.json");
    store.load();
    EXPECT_EQ(store.size(), 0u);
}

TEST(JsonState, UpsertAndLookup) {
    TempDir tmp;
    JsonStateStore store(tmp.path() / "state.json");
    store.load();
    const Uid uid = {0xAA, 0xBB};
    CardState s{42, CardStatus::OK, std::chrono::system_clock::now()};
    store.upsert(uid, s);
    const auto loaded = store.find(uid);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->counter, 42u);
    EXPECT_EQ(loaded->status, CardStatus::OK);
}

TEST(JsonState, AtomicPersistAndReload) {
    TempDir tmp;
    const auto p = tmp.path() / "state.json";
    {
        JsonStateStore store(p);
        store.load();
        store.upsert({0xDE, 0xAD}, {7, CardStatus::OK, std::chrono::system_clock::now()});
        store.upsert({0xBE, 0xEF}, {99, CardStatus::COMPROMISED, std::chrono::system_clock::now()});
    }
    {
        JsonStateStore store(p);
        store.load();
        EXPECT_EQ(store.size(), 2u);
        const auto a = store.find({0xDE, 0xAD});
        ASSERT_TRUE(a.has_value());
        EXPECT_EQ(a->counter, 7u);
        const auto b = store.find({0xBE, 0xEF});
        ASSERT_TRUE(b.has_value());
        EXPECT_EQ(b->status, CardStatus::COMPROMISED);
    }
}

TEST(JsonState, MarkCompromisedAndBlocked) {
    TempDir tmp;
    JsonStateStore store(tmp.path() / "state.json");
    store.load();
    const Uid uid = {1, 2, 3};
    store.upsert(uid, {5, CardStatus::OK, std::chrono::system_clock::now()});
    EXPECT_TRUE(store.markCompromised(uid));
    EXPECT_EQ(store.find(uid)->status, CardStatus::COMPROMISED);
    EXPECT_TRUE(store.markBlocked(uid));
    EXPECT_EQ(store.find(uid)->status, CardStatus::BLOCKED);
}

TEST(JsonState, SchemaIsVersioned) {
    TempDir tmp;
    const auto p = tmp.path() / "state.json";
    JsonStateStore store(p);
    store.load();
    store.upsert({0x01}, {1, CardStatus::OK, std::chrono::system_clock::now()});
    std::ifstream in(p);
    nlohmann::json doc;
    in >> doc;
    EXPECT_TRUE(doc.contains("schema_version"));
    EXPECT_EQ(doc["schema_version"].get<int>(), JsonStateStore::kCurrentSchemaVersion);
    EXPECT_TRUE(doc.contains("cards"));
    EXPECT_EQ(doc["cards"]["01"]["counter"].get<int>(), 1);
    EXPECT_EQ(doc["cards"]["01"]["status"].get<std::string>(), std::string("OK"));
}

TEST(JsonState, LegacyFlatFormatLoads) {
    TempDir tmp;
    const auto p = tmp.path() / "legacy.json";
    {
        std::ofstream out(p);
        out << R"({"AABB":{"counter":3,"status":"OK","last_seen":""}})";
    }
    JsonStateStore store(p);
    store.load();
    EXPECT_EQ(store.size(), 1u);
    const auto s = store.find({0xAA, 0xBB});
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->counter, 3u);
}

TEST(JsonState, CorruptFileThrows) {
    TempDir tmp;
    const auto p = tmp.path() / "corrupt.json";
    {
        std::ofstream out(p);
        out << "{ not json";
    }
    JsonStateStore store(p);
    EXPECT_THROW(store.load(), std::exception);
}
