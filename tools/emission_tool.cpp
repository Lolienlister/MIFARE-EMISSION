#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wincrypt.h>
#  pragma comment(lib, "advapi32.lib")
#endif

#include "mifare_emission/crypto.h"
#include "mifare_emission/json_state.h"
#include "mifare_emission/logger.h"
#include "mifare_emission/master_key_vault.h"
#include "mifare_emission/pcsc_reader.h"
#include "mifare_emission/rfid_reader.h"
#include "mifare_emission/types.h"

using namespace mifare_emission;
namespace fs = std::filesystem;

namespace {

void print_usage() {
    std::cout <<
        "Usage: mifare_emission_tool <command> [args]\n"
        "Commands:\n"
        "  gen-master <out_path>            Generate new MASTER_KEY (32B) and store via DPAPI/file\n"
        "  emit <state_path> <vault_path>   Initialize a freshly tapped MIFARE Classic 1K card\n"
        "                                   for use with the SKUD system (counter=0, derived Key_A)\n"
        "  revoke <state_path> <uid_hex>    Mark a UID as BLOCKED in the state\n";
}

bool generate_random(MasterKey& out) {
#if defined(_WIN32)
    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return false;
    }
    const BOOL ok = CryptGenRandom(prov, static_cast<DWORD>(out.size()), out.data());
    CryptReleaseContext(prov, 0);
    return ok == TRUE;
#else
    std::ifstream rnd("/dev/urandom", std::ios::binary);
    if (!rnd) return false;
    rnd.read(reinterpret_cast<char*>(out.data()), out.size());
    return static_cast<bool>(rnd);
#endif
}

int cmd_gen_master(const std::string& path) {
    MasterKey k{};
    if (!generate_random(k)) {
        std::cerr << "Random generation failed" << std::endl;
        return 1;
    }
#if defined(_WIN32)
    DpapiMasterKeyVault vault(path);
#else
    FilesystemMasterKeyVault vault(path);
#endif
    if (!vault.store(k)) {
        std::cerr << "Failed to write " << path << std::endl;
        return 2;
    }
    std::cout << "MASTER_KEY stored at " << path << std::endl;
    return 0;
}

int cmd_emit(const std::string& state_path, const std::string& vault_path) {
#if defined(_WIN32)
    DpapiMasterKeyVault vault(vault_path);
#else
    FilesystemMasterKeyVault vault(vault_path);
#endif
    auto mk = vault.load();
    if (!mk) {
        std::cerr << "Cannot load MASTER_KEY from " << vault_path << std::endl;
        return 1;
    }
    BeltKdf kdf(*mk);

    JsonStateStore store(state_path);
    store.load();

    PcscReader reader;
    const auto readers = reader.listReaders();
    if (readers.empty()) {
        std::cerr << "No PC/SC readers available" << std::endl;
        return 2;
    }
    if (!reader.connect(readers.front())) {
        std::cerr << "Connect failed: " << reader.lastError() << std::endl;
        return 3;
    }

    std::cout << "Tap card on " << readers.front() << "..." << std::endl;
    if (!reader.waitForCard(15000)) {
        std::cerr << "No card detected" << std::endl;
        return 4;
    }

    const Uid uid = reader.readUid();
    std::cout << "UID: " << uid_to_hex(uid) << std::endl;

    const SectorKey factory_a = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (!reader.authenticateSector(kCounterSector, factory_a, MifareKeyType::KEY_A)) {
        std::cerr << "Factory KEY_A auth failed; card is not in transport mode" << std::endl;
        return 5;
    }

    const auto counter_block = encodeCounter(0);
    reader.writeBlock(kCounterBlock, counter_block);

    const SectorKey new_key = kdf.deriveSectorKey(uid, 0);
    const auto trailer = buildSectorTrailer(new_key, kDefaultAccessBits, new_key);
    reader.writeBlock(kSectorTrailerBlock, trailer);

    CardState state{};
    state.counter = 0;
    state.status = CardStatus::OK;
    state.last_seen = std::chrono::system_clock::now();
    store.upsert(uid, state);

    std::cout << "Card emitted. State updated for UID " << uid_to_hex(uid) << std::endl;
    return 0;
}

int cmd_revoke(const std::string& state_path, const std::string& uid_hex) {
    const auto uid = uid_from_hex(uid_hex);
    if (!uid) {
        std::cerr << "Invalid UID hex" << std::endl;
        return 1;
    }
    JsonStateStore store(state_path);
    store.load();
    store.markBlocked(*uid);
    std::cout << "UID " << uid_to_hex(*uid) << " marked BLOCKED" << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    const std::string cmd = argv[1];
    if (cmd == "gen-master" && argc >= 3) {
        return cmd_gen_master(argv[2]);
    }
    if (cmd == "emit" && argc >= 4) {
        return cmd_emit(argv[2], argv[3]);
    }
    if (cmd == "revoke" && argc >= 4) {
        return cmd_revoke(argv[2], argv[3]);
    }
    print_usage();
    return 1;
}
