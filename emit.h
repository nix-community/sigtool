#ifndef SIGTOOL_EMIT_H
#define SIGTOOL_EMIT_H

#include <iostream>
#include <vector>
#include <memory>
#include <arpa/inet.h>
#include <cmath>
#include <cstdint>

namespace SigTool {

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "host is little endian");

class Emit {

public:
    template<typename T> static std::ostream& writeBytes(std::ostream& os, T value) {
        return os.write(reinterpret_cast<const char *>(&value), sizeof(T));
    }
};

class EmitBE : public Emit {
public:
    static std::ostream& writeUInt32(std::ostream& os, uint32_t value) {
        return EmitBE::writeBytes(os, htonl(value));
    }

    static std::ostream& writeUInt64(std::ostream& os, uint64_t value) {
        uint64_t swapped =
                ((UINT64_C(0xff00000000000000) & value) >> 56) |
                ((UINT64_C(0x00ff000000000000) & value) >> 40) |
                ((UINT64_C(0x0000ff0000000000) & value) >> 24) |
                ((UINT64_C(0x000000ff00000000) & value) >> 8) |
                ((UINT64_C(0x00000000ff000000) & value) << 8) |
                ((UINT64_C(0x0000000000ff0000) & value) << 24) |
                ((UINT64_C(0x000000000000ff00) & value) << 40) |
                ((UINT64_C(0x00000000000000ff) & value) << 56);

        return EmitBE::writeBytes<uint64_t >(os, swapped);
    }
};

class Read {
public:
    template<typename T>
    static T readBytes(std::istream &is) {
        T value{};
        is.read(reinterpret_cast<char *>(&value), sizeof(value));
        return value;
    }
};

class ReadBE : public Read {
public:
    static uint32_t readUInt32(std::istream& is) {
        return ntohl(Read::readBytes<uint32_t>(is));
    }
};

class ReadLE : public Read {
public:
    static uint32_t readUInt32(std::istream& is) {
        return Read::readBytes<uint32_t>(is);
    }
};
};

#endif //SIGTOOL_EMIT_H

