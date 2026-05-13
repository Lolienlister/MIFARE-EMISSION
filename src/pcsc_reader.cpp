#include "mifare_emission/pcsc_reader.h"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>

#if defined(_WIN32)
#  include <winscard.h>
#  pragma comment(lib, "winscard.lib")
#else
#  include <winscard.h>
#endif

namespace mifare_emission {

namespace {

constexpr uint8_t kTrailerSe = 7;

uint8_t trailer_block_of(uint8_t sector) {
    return static_cast<uint8_t>(sector * 4 + 3);
}

std::string apdu_to_string(const std::vector<uint8_t>& bytes) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 3);
    for (uint8_t b : bytes) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
        out.push_back(' ');
    }
    return out;
}

std::string pcsc_error_to_string(LONG rv) {
    std::ostringstream oss;
    oss << "PC/SC error 0x" << std::hex << static_cast<unsigned long>(rv);
    return oss.str();
}

}  // namespace

struct PcscReader::Impl {
    SCARDCONTEXT context = 0;
    SCARDHANDLE card = 0;
    DWORD active_protocol = 0;
    std::string last_error;

    ~Impl() {
        if (card) {
            SCardDisconnect(card, SCARD_LEAVE_CARD);
            card = 0;
        }
        if (context) {
            SCardReleaseContext(context);
            context = 0;
        }
    }

    bool transmit(const std::vector<uint8_t>& apdu,
                  std::vector<uint8_t>& response) {
        SCARD_IO_REQUEST send_pci{};
        send_pci.dwProtocol = active_protocol == SCARD_PROTOCOL_T1 ? SCARD_PROTOCOL_T1 : SCARD_PROTOCOL_T0;
        send_pci.cbPciLength = sizeof(SCARD_IO_REQUEST);

        response.assign(256, 0);
        DWORD recv_len = static_cast<DWORD>(response.size());
        const LONG rv = SCardTransmit(card,
                                      &send_pci,
                                      apdu.data(),
                                      static_cast<DWORD>(apdu.size()),
                                      nullptr,
                                      response.data(),
                                      &recv_len);
        if (rv != SCARD_S_SUCCESS) {
            std::ostringstream oss;
            oss << pcsc_error_to_string(rv) << " on APDU " << apdu_to_string(apdu);
            last_error = oss.str();
            return false;
        }
        response.resize(recv_len);
        return true;
    }
};

PcscReader::PcscReader() : impl_(std::make_unique<Impl>()) {}
PcscReader::~PcscReader() = default;

std::vector<std::string> PcscReader::listReaders() {
    if (!impl_->context) {
        const LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &impl_->context);
        if (rv != SCARD_S_SUCCESS) {
            impl_->last_error = pcsc_error_to_string(rv);
            return {};
        }
    }

    DWORD readers_len = 0;
    LONG rv = SCardListReadersA(impl_->context, nullptr, nullptr, &readers_len);
    if (rv != SCARD_S_SUCCESS) {
        impl_->last_error = pcsc_error_to_string(rv);
        return {};
    }

    std::vector<char> buf(readers_len);
    rv = SCardListReadersA(impl_->context, nullptr, buf.data(), &readers_len);
    if (rv != SCARD_S_SUCCESS) {
        impl_->last_error = pcsc_error_to_string(rv);
        return {};
    }

    std::vector<std::string> readers;
    const char* p = buf.data();
    while (*p) {
        readers.emplace_back(p);
        p += std::strlen(p) + 1;
    }
    return readers;
}

bool PcscReader::connect(const std::string& reader_name) {
    if (!impl_->context) {
        const LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &impl_->context);
        if (rv != SCARD_S_SUCCESS) {
            impl_->last_error = pcsc_error_to_string(rv);
            return false;
        }
    }
    const LONG rv = SCardConnectA(impl_->context,
                                  reader_name.c_str(),
                                  SCARD_SHARE_SHARED,
                                  SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                  &impl_->card,
                                  &impl_->active_protocol);
    if (rv != SCARD_S_SUCCESS) {
        impl_->last_error = pcsc_error_to_string(rv);
        return false;
    }
    return true;
}

bool PcscReader::waitForCard(int timeout_ms) {
    if (!impl_->context) {
        const LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &impl_->context);
        if (rv != SCARD_S_SUCCESS) {
            impl_->last_error = pcsc_error_to_string(rv);
            return false;
        }
    }
    const auto readers = listReaders();
    if (readers.empty()) return false;

    SCARD_READERSTATEA state{};
    state.szReader = readers.front().c_str();
    state.dwCurrentState = SCARD_STATE_UNAWARE;
    const LONG rv = SCardGetStatusChangeA(impl_->context,
                                          static_cast<DWORD>(timeout_ms),
                                          &state,
                                          1);
    if (rv != SCARD_S_SUCCESS) {
        impl_->last_error = pcsc_error_to_string(rv);
        return false;
    }
    return (state.dwEventState & SCARD_STATE_PRESENT) != 0;
}

Uid PcscReader::readUid() {
    const std::vector<uint8_t> apdu = {0xFF, 0xCA, 0x00, 0x00, 0x00};
    std::vector<uint8_t> resp;
    if (!impl_->transmit(apdu, resp) || resp.size() < 2) {
        throw std::runtime_error("readUid failed: " + impl_->last_error);
    }
    const uint8_t sw1 = resp[resp.size() - 2];
    const uint8_t sw2 = resp[resp.size() - 1];
    if (sw1 != 0x90 || sw2 != 0x00) {
        std::ostringstream oss;
        oss << "readUid SW="
            << std::hex << static_cast<int>(sw1) << static_cast<int>(sw2);
        throw std::runtime_error(oss.str());
    }
    return Uid(resp.begin(), resp.end() - 2);
}

bool PcscReader::authenticateSector(uint8_t sector,
                                    const SectorKey& key,
                                    MifareKeyType type) {
    {
        std::vector<uint8_t> apdu = {0xFF, 0x82, 0x00, 0x00, 0x06};
        apdu.insert(apdu.end(), key.begin(), key.end());
        std::vector<uint8_t> resp;
        if (!impl_->transmit(apdu, resp) || resp.size() < 2) return false;
        if (resp[resp.size() - 2] != 0x90 || resp[resp.size() - 1] != 0x00) {
            return false;
        }
    }
    const uint8_t key_type_byte = (type == MifareKeyType::KEY_A) ? 0x60 : 0x61;
    const uint8_t block = trailer_block_of(sector);
    const std::vector<uint8_t> auth_apdu = {
        0xFF, 0x86, 0x00, 0x00, 0x05,
        0x01,
        0x00,
        block,
        key_type_byte,
        0x00,
    };
    std::vector<uint8_t> resp;
    if (!impl_->transmit(auth_apdu, resp) || resp.size() < 2) return false;
    return resp[resp.size() - 2] == 0x90 && resp[resp.size() - 1] == 0x00;
}

std::array<uint8_t, kMifareBlockSize> PcscReader::readBlock(uint8_t block) {
    const std::vector<uint8_t> apdu = {
        0xFF, 0xB0, 0x00, block, static_cast<uint8_t>(kMifareBlockSize)
    };
    std::vector<uint8_t> resp;
    if (!impl_->transmit(apdu, resp) || resp.size() < 2 + kMifareBlockSize) {
        throw std::runtime_error("readBlock failed: " + impl_->last_error);
    }
    if (resp[resp.size() - 2] != 0x90 || resp[resp.size() - 1] != 0x00) {
        throw std::runtime_error("readBlock bad SW");
    }
    std::array<uint8_t, kMifareBlockSize> out{};
    for (std::size_t i = 0; i < kMifareBlockSize; ++i) out[i] = resp[i];
    return out;
}

void PcscReader::writeBlock(uint8_t block,
                            const std::array<uint8_t, kMifareBlockSize>& data) {
    std::vector<uint8_t> apdu = {
        0xFF, 0xD6, 0x00, block, static_cast<uint8_t>(kMifareBlockSize)
    };
    apdu.insert(apdu.end(), data.begin(), data.end());
    std::vector<uint8_t> resp;
    if (!impl_->transmit(apdu, resp) || resp.size() < 2) {
        throw std::runtime_error("writeBlock failed: " + impl_->last_error);
    }
    if (resp[resp.size() - 2] != 0x90 || resp[resp.size() - 1] != 0x00) {
        throw std::runtime_error("writeBlock bad SW");
    }
}

void PcscReader::disconnect() {
    if (impl_->card) {
        SCardDisconnect(impl_->card, SCARD_LEAVE_CARD);
        impl_->card = 0;
    }
}

std::string PcscReader::lastError() const {
    return impl_->last_error;
}

}  // namespace mifare_emission
