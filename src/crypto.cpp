#include "mifare_emission/crypto.h"

#include <stdexcept>
#include <utility>

#include "belt.h"

namespace mifare_emission {

struct BeltKdf::Impl {
    BeltCipher cipher;
};

BeltKdf::BeltKdf(const MasterKey& master_key)
    : impl_(new Impl{BeltCipher(master_key.data())}) {}

BeltKdf::~BeltKdf() {
    delete impl_;
}

BeltKdf::BeltKdf(BeltKdf&& other) noexcept : impl_(other.impl_) {
    other.impl_ = nullptr;
}

BeltKdf& BeltKdf::operator=(BeltKdf&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

std::vector<uint8_t> BeltKdf::buildKdfInput(const Uid& uid, Counter counter) {
    std::vector<uint8_t> buf;
    buf.reserve(uid.size() + sizeof(Counter));
    buf.insert(buf.end(), uid.begin(), uid.end());
    buf.push_back(static_cast<uint8_t>((counter >> 0) & 0xFF));
    buf.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((counter >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((counter >> 24) & 0xFF));
    return buf;
}

std::array<uint8_t, kBeltMacSize> BeltKdf::deriveMac(const Uid& uid, Counter counter) const {
    if (!impl_) {
        throw std::runtime_error("BeltKdf used after move");
    }
    const auto input = buildKdfInput(uid, counter);
    std::array<uint8_t, kBeltMacSize> mac{};
    const int rc = impl_->cipher.computeMAC(input.data(), input.size(), mac.data());
    if (rc != 0) {
        throw std::runtime_error("BELT MAC computation failed");
    }
    return mac;
}

SectorKey BeltKdf::deriveSectorKey(const Uid& uid, Counter counter) const {
    const auto mac = deriveMac(uid, counter);
    SectorKey key{};
    for (std::size_t i = 0; i < kSectorKeySize; ++i) {
        key[i] = mac[i];
    }
    return key;
}

}  // namespace mifare_emission
