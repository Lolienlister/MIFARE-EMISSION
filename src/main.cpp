#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "mifare_emission/access_engine.h"
#include "mifare_emission/crypto.h"
#include "mifare_emission/json_state.h"
#include "mifare_emission/logger.h"
#include "mifare_emission/master_key_vault.h"
#include "mifare_emission/pcsc_reader.h"
#include "mifare_emission/time_policy.h"
#include "mifare_emission/types.h"

namespace fs = std::filesystem;
using namespace mifare_emission;

namespace {

struct AppConfig {
    fs::path state_path = "state.json";
    fs::path log_path = "skud.log";
    fs::path master_key_path = "master.key";
    bool dpapi = true;
    LocalTimeOfDay window_start{8, 0};
    LocalTimeOfDay window_end{18, 0};
    std::string reader_name;
    int poll_timeout_ms = 1000;
};

AppConfig load_config(const fs::path& path) {
    AppConfig cfg;
    std::ifstream in(path);
    if (!in) return cfg;
    nlohmann::json doc;
    in >> doc;
    cfg.state_path = doc.value("state_path", cfg.state_path.string());
    cfg.log_path = doc.value("log_path", cfg.log_path.string());
    cfg.master_key_path = doc.value("master_key_path", cfg.master_key_path.string());
    cfg.dpapi = doc.value("dpapi", cfg.dpapi);
    cfg.reader_name = doc.value("reader_name", cfg.reader_name);
    cfg.poll_timeout_ms = doc.value("poll_timeout_ms", cfg.poll_timeout_ms);
    if (doc.contains("window")) {
        const auto& w = doc["window"];
        cfg.window_start.hour = w.value("start_hour", static_cast<int>(cfg.window_start.hour));
        cfg.window_start.minute = w.value("start_minute", static_cast<int>(cfg.window_start.minute));
        cfg.window_end.hour = w.value("end_hour", static_cast<int>(cfg.window_end.hour));
        cfg.window_end.minute = w.value("end_minute", static_cast<int>(cfg.window_end.minute));
    }
    return cfg;
}

std::unique_ptr<IMasterKeyVault> make_vault(const AppConfig& cfg) {
#if defined(_WIN32)
    if (cfg.dpapi) {
        return std::make_unique<DpapiMasterKeyVault>(cfg.master_key_path);
    }
#endif
    return std::make_unique<FilesystemMasterKeyVault>(cfg.master_key_path);
}

}  // namespace

int main(int argc, char** argv) {
    fs::path config_path = "config.json";
    if (argc > 1) config_path = argv[1];

    const AppConfig cfg = load_config(config_path);
    Logger logger(cfg.log_path);
    logger.info("MIFARE-EMISSION SKUD starting; config=" + config_path.string());

    auto vault = make_vault(cfg);
    auto master = vault->load();
    if (!master) {
        logger.error("Failed to load MASTER_KEY from " + cfg.master_key_path.string());
        std::cerr << "MASTER_KEY not available. Provision it first." << std::endl;
        return 1;
    }

    BeltKdf kdf(*master);
    master.reset();

    JsonStateStore store(cfg.state_path);
    try {
        store.load();
    } catch (const std::exception& e) {
        logger.error(std::string("State load failure: ") + e.what());
        return 2;
    }

    PcscReader reader;
    const auto readers = reader.listReaders();
    if (readers.empty()) {
        logger.error("No PC/SC readers available");
        return 3;
    }
    const std::string chosen = cfg.reader_name.empty() ? readers.front() : cfg.reader_name;
    if (!reader.connect(chosen)) {
        logger.error("Connect failed: " + reader.lastError());
        return 4;
    }
    logger.info("Connected to reader: " + chosen);

    TimePolicy policy(cfg.window_start, cfg.window_end);
    AccessEngine engine(&reader, &store, &kdf, policy, &logger);

    logger.info("Entering main loop");
    while (true) {
        if (!reader.waitForCard(cfg.poll_timeout_ms)) {
            continue;
        }
        const auto result = engine.runOnce(std::chrono::system_clock::now());
        if (result.decision == Decision::ALLOW) {
            logger.info("ALLOW uid=" + uid_to_hex(result.uid) +
                        " counter " + std::to_string(result.old_counter) + "->" +
                        std::to_string(result.new_counter));
        } else {
            logger.warn("DENY uid=" + uid_to_hex(result.uid) +
                        " reason=" + to_string(result.reason));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return 0;
}
