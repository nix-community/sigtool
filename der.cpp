#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/asn1.h>
#include <plist/plist.h>

#include "der.h"

namespace {

using Bytes = std::vector<unsigned char>;

// Wrap one or more body parts in an ASN.1 TLV header (tag/length) using
// OpenSSL's ASN1_put_object. The parts are concatenated in order to form
// the body. xclass selects universal/application/context/private.
template <typename... Parts>
Bytes makeTLV(int constructed, int tag, int xclass, const Parts &...parts) {
    size_t bodyLenSum = 0;
    using expander = int[];
    (void)expander{0, (bodyLenSum += parts.size(), 0)...};
    int bodyLen = static_cast<int>(bodyLenSum);
    int total = ASN1_object_size(constructed, bodyLen, tag);
    if (total < 0) throw std::runtime_error{"ASN1_object_size failed"};
    Bytes out(total);
    unsigned char *p = out.data();
    ASN1_put_object(&p, constructed, bodyLen, tag, xclass);
    (void)expander{0, (std::memcpy(p, parts.data(), parts.size()), p += parts.size(), 0)...};
    return out;
}

// Run an OpenSSL i2d_* encoder over `obj`, free `obj` with `freer`, and
// return the DER bytes. Lets every primitive encoder be a three-liner.
template <typename T, typename Encoder, typename Freer>
Bytes i2dOwned(T *obj, Encoder encoder, Freer freer) {
    unsigned char *p = nullptr;
    int n = encoder(obj, &p);
    freer(obj);
    if (n < 0) throw std::runtime_error{"i2d encoder failed"};
    auto *bp = reinterpret_cast<unsigned char *>(p);
    Bytes out(bp, bp + n);
    OPENSSL_free(p);
    return out;
}

Bytes encBool(bool v) {
    ASN1_TYPE *t = ASN1_TYPE_new();
    // For V_ASN1_BOOLEAN, ASN1_TYPE_set treats the value pointer as a flag:
    // non-null -> true (encoded as 0xff in DER), null -> false (0x00).
    // (OpenSSL 3 no longer exposes a direct i2d_ASN1_BOOLEAN.)
    ASN1_TYPE_set(t, V_ASN1_BOOLEAN, v ? reinterpret_cast<void *>(1) : nullptr);
    return i2dOwned(t, i2d_ASN1_TYPE, ASN1_TYPE_free);
}

Bytes encInt(long long v) {
    ASN1_INTEGER *ai = ASN1_INTEGER_new();
    ASN1_INTEGER_set_int64(ai, v);
    return i2dOwned(ai, i2d_ASN1_INTEGER, ASN1_INTEGER_free);
}

Bytes encUTF8(const std::string &v) {
    ASN1_UTF8STRING *u = ASN1_UTF8STRING_new();
    ASN1_STRING_set(u, v.data(), static_cast<int>(v.size()));
    return i2dOwned(u, i2d_ASN1_UTF8STRING, ASN1_UTF8STRING_free);
}

template <typename... Parts>
Bytes encSequence(const Parts &...parts) {
    return makeTLV(/*constructed=*/1, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, parts...);
}

// Apple wraps the entitlements set with a context-specific [16] constructed
// tag, and the outer container with an application-class [16] constructed tag.
template <typename... Parts>
Bytes encContext16(const Parts &...parts) {
    return makeTLV(/*constructed=*/1, /*tag=*/16, V_ASN1_CONTEXT_SPECIFIC, parts...);
}

template <typename... Parts>
Bytes encApplication16(const Parts &...parts) {
    return makeTLV(/*constructed=*/1, /*tag=*/16, V_ASN1_APPLICATION, parts...);
}

Bytes encValue(plist_t v);

Bytes encDictBody(plist_t d) {
    std::vector<std::pair<std::string, plist_t>> pairs;
    pairs.reserve(plist_dict_get_size(d));

    plist_dict_iter iter = nullptr;
    plist_dict_new_iter(d, &iter);
    char *key = nullptr;
    plist_t value = nullptr;
    while (true) {
        plist_dict_next_item(d, iter, &key, &value);
        if (!key) break;
        pairs.emplace_back(std::string{key}, value);
        free(key);
    }
    free(iter);

    std::sort(pairs.begin(), pairs.end(),
              [](const std::pair<std::string, plist_t> &a,
                 const std::pair<std::string, plist_t> &b) {
                  return a.first < b.first;
              });

    Bytes body;
    for (auto &p : pairs) {
        Bytes entry = encSequence(encUTF8(p.first), encValue(p.second));
        body.insert(body.end(), entry.begin(), entry.end());
    }
    return body;
}

Bytes encValue(plist_t v) {
    switch (plist_get_node_type(v)) {
        case PLIST_BOOLEAN: {
            uint8_t b = 0;
            plist_get_bool_val(v, &b);
            return encBool(b != 0);
        }
        case PLIST_INT: {
            int64_t n = 0;
            plist_get_int_val(v, &n);
            return encInt(n);
        }
        case PLIST_STRING: {
            char *s = nullptr;
            plist_get_string_val(v, &s);
            std::string out{s ? s : ""};
            free(s);
            return encUTF8(out);
        }
        case PLIST_ARRAY: {
            uint32_t n = plist_array_get_size(v);
            Bytes body;
            for (uint32_t i = 0; i < n; i++) {
                Bytes item = encValue(plist_array_get_item(v, i));
                body.insert(body.end(), item.begin(), item.end());
            }
            return encSequence(body);
        }
        case PLIST_DICT:
            return encContext16(encDictBody(v));
        default:
            throw std::runtime_error{"unsupported entitlement value type"};
    }
}

} // namespace

std::vector<unsigned char> encodeEntitlementsDER(const std::string &plistXml) {
    plist_t plist = nullptr;
    plist_err_t err = plist_from_xml(plistXml.data(),
                                     static_cast<uint32_t>(plistXml.size()),
                                     &plist);
    if (err != PLIST_ERR_SUCCESS || !plist) {
        if (plist) plist_free(plist);
        throw std::runtime_error{"failed to parse entitlements plist"};
    }
    if (plist_get_node_type(plist) != PLIST_DICT) {
        plist_free(plist);
        throw std::runtime_error{"entitlements plist root must be a dict"};
    }

    Bytes der = encApplication16(encInt(1), encContext16(encDictBody(plist)));
    plist_free(plist);
    return der;
}
