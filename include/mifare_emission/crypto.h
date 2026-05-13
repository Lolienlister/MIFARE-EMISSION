#ifndef MIFARE_EMISSION_CRYPTO_H
#define MIFARE_EMISSION_CRYPTO_H

#include <array>
#include <cstdint>
#include <vector>

#include "mifare_emission/types.h"

namespace mifare_emission {

class BeltKdf {
public:
    explicit BeltKdf(const MasterKey& master_key);
    ~BeltKdf();

    BeltKdf(const BeltKdf&) = delete;
    BeltKdf& operator=(const BeltKdf&) = delete;
    BeltKdf(BeltKdf&&) noexcept;
    BeltKdf& operator=(BeltKdf&&) noexcept;

    std::array<uint8_t, kBeltMacSize> deriveMac(const Uid& uid, Counter counter) const;

    SectorKey deriveSectorKey(const Uid& uid, Counter counter) const;

    static std::vector<uint8_t> buildKdfInput(const Uid& uid, Counter counter);

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace mifare_emission

#endif  // MIFARE_EMISSION_CRYPTO_H
