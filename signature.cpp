#include <iostream>
#include <vector>
#include <memory>
#include <arpa/inet.h>
#include <cmath>
#include <limits>
#include <cassert>
#include "signature.h"
#include "emit.h"

namespace SigTool {

CodeDirectory::CodeDirectory() noexcept {
    data.magic = CSMAGIC_CODEDIRECTORY;
    data.version = 0x020400;
    data.flags = CS_ADHOC;
    data.hashSize = Hash::hashSize;
    data.hashType = Hash::hashType;
}

size_t CodeDirectory::length() {
    size_t length = sizeof(data);
    length += identifier.length() + 1;
    length += sizeof(Hash::bytes) * (data.nSpecialSlots + data.nCodeSlots);
    return length;
}

void CodeDirectory::emit(std::ostream& os)  {
    // Layout variable length components
    off_t tail = sizeof(data);

    data.identOffset = tail;
    tail += identifier.length() + 1;

    data.hashOffset = tail + sizeof(Hash::bytes) * data.nSpecialSlots;
    tail += sizeof(Hash::bytes) * (data.nSpecialSlots + data.nCodeSlots);

    data.length = tail;

    // Stream all fixed components
    EmitBE::writeUInt32(os, data.magic);
    EmitBE::writeUInt32(os, data.length);
    EmitBE::writeUInt32(os, data.version);
    EmitBE::writeUInt32(os, data.flags);
    EmitBE::writeUInt32(os, data.hashOffset);
    EmitBE::writeUInt32(os, data.identOffset);
    EmitBE::writeUInt32(os, data.nSpecialSlots);
    EmitBE::writeUInt32(os, data.nCodeSlots);
    EmitBE::writeUInt32(os, data.codeLimit);
    EmitBE::writeBytes<uint8_t>(os, data.hashSize);
    EmitBE::writeBytes<uint8_t>(os, data.hashType);
    EmitBE::writeBytes<uint8_t>(os, data.platform);
    EmitBE::writeBytes<uint8_t>(os, data.pageSize);
    EmitBE::writeUInt32(os, data.spare2);
    EmitBE::writeUInt32(os, data.scatterOffset);
    EmitBE::writeUInt32(os, data.teamOffset);
    EmitBE::writeUInt32(os, data.spare3);
    EmitBE::writeUInt64(os, data.codeLimit64);
    EmitBE::writeUInt64(os, data.execSegBase);
    EmitBE::writeUInt64(os, data.execSegLimit);
    EmitBE::writeUInt64(os, data.execSegFlags);

    // Followed by variable length components
    os.write(identifier.c_str(), identifier.length());
    os.put(0);

    if (data.nSpecialSlots > 0) {
        for (int specialIndex = (int) data.nSpecialSlots - 1; specialIndex >= 0; specialIndex--) {
            os.write(specialHashes[specialIndex].bytes, sizeof(Hash::bytes));
        }
    }
    for (const Hash& hash : codeHashes) {
        os.write(hash.bytes, sizeof(Hash::bytes));
    }
}

void CodeDirectory::setSpecialHash(int index, const Hash& value) {
    // index is in the range of (1 to 5), with 1 being the first, etc
    // for convenience, map that to a regular (0..4) array
    unsigned int storage = (unsigned int)index - 1;
    data.nSpecialSlots = std::max(data.nSpecialSlots, storage + 1);
    specialHashes[storage] = value;
}

void CodeDirectory::setPageSize(uint16_t pageSize) {
    data.pageSize = log2(pageSize);
}

void CodeDirectory::setCodeLimit(uint64_t codeLimit) {
    if (codeLimit >= std::numeric_limits<uint32_t>::max()) {
        data.codeLimit = std::numeric_limits<uint32_t>::max();
        data.codeLimit64 = codeLimit;
    } else {
        data.codeLimit = codeLimit;
        data.codeLimit64 = 0;
    }
}

void CodeDirectory::addCodeHash(const Hash& value) {
    codeHashes.push_back(value);
    data.nCodeSlots = codeHashes.size();
}

void SuperBlob::emit(std::ostream& os)  {
    EmitBE::writeUInt32(os, CSMAGIC_EMBEDDED_SIGNATURE);
    EmitBE::writeUInt32(os, length());
    EmitBE::writeUInt32(os, blobs.size());

    off_t blobDataOffset =
            SuperBlob::headerSize +
            2 * sizeof(uint32_t) * blobs.size(); // blob index entry

    // blob index
    for (const auto& blob : blobs) {
        EmitBE::writeUInt32(os, blob->slotType());
        EmitBE::writeUInt32(os, blobDataOffset);
        blobDataOffset += blob->length();
    }

    for (const auto& blob : blobs) {
        // blob data
        blob->emit(os);
    }
}

size_t SuperBlob::length() {
    size_t length =
            SuperBlob::headerSize +
            2 * sizeof(uint32_t) * blobs.size();
    for (const auto& blob : blobs) {
        length += blob->length();
    }
    return length;
}

void Requirements::emit(std::ostream &os) {
    EmitBE::writeUInt32(os, CSMAGIC_REQUIREMENTS);
    EmitBE::writeUInt32(os, length());
    EmitBE::writeUInt32(os, 0); // count
}

size_t Requirements::length() {
    return 3 * sizeof(uint32_t);
}

void Signature::emit(std::ostream &os) {
    EmitBE::writeUInt32(os, CSMAGIC_BLOBWRAPPER);
    EmitBE::writeUInt32(os, length());
}

size_t Signature::length() {
    return 2 * sizeof(uint32_t);
}

void Entitlements::emit(std::ostream &os) {
    EmitBE::writeUInt32(os, CSMAGIC_EMBEDDED_ENTITLEMENTS);
    EmitBE::writeUInt32(os, length());
    os << entitlements;
}

size_t Entitlements::length() {
    return entitlements.length() + 8;
}

void EntitlementsDER::emit(std::ostream &os) {
    EmitBE::writeUInt32(os, CSMAGIC_EMBEDDED_ENTITLEMENTS_DER);
    EmitBE::writeUInt32(os, length());
    os.write(reinterpret_cast<const char *>(entitlements.data()),
             entitlements.size());
}

size_t EntitlementsDER::length() {
    return entitlements.size() + 8;
}

};
