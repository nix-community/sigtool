#include <openssl/sha.h>

#include "hash.h"

namespace SigTool {

SHA256Hash::SHA256Hash(const char *data, size_t len)
  : SHA256Hash(reinterpret_cast<const unsigned char*>(data), len)
{}

SHA256Hash::SHA256Hash(const std::string& str)
  : SHA256Hash(str.data(), str.length())
{}

SHA256Hash::SHA256Hash(const unsigned char *data, size_t len) {
    SHA256(data, len, reinterpret_cast<unsigned char *>(&this->bytes[0]));
}

SHA1Hash::SHA1Hash(const char *data, size_t len) {
    SHA1(reinterpret_cast<const unsigned char *>(data), len,
         reinterpret_cast<unsigned char *>(&this->bytes[0]));
}

SHA1Hash::SHA1Hash(const std::string &str) : SHA1Hash(str.data(), str.length()) {}

static const char *kBase64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const char *data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    auto u = reinterpret_cast<const unsigned char *>(data);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = (uint32_t(u[i]) << 16) | (uint32_t(u[i + 1]) << 8) | uint32_t(u[i + 2]);
        out.push_back(kBase64[(v >> 18) & 0x3f]);
        out.push_back(kBase64[(v >> 12) & 0x3f]);
        out.push_back(kBase64[(v >> 6) & 0x3f]);
        out.push_back(kBase64[v & 0x3f]);
    }
    if (i < len) {
        uint32_t v = uint32_t(u[i]) << 16;
        if (i + 1 < len) v |= uint32_t(u[i + 1]) << 8;
        out.push_back(kBase64[(v >> 18) & 0x3f]);
        out.push_back(kBase64[(v >> 12) & 0x3f]);
        out.push_back(i + 1 < len ? kBase64[(v >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
}
};
