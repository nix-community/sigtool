#ifndef SIGTOOL_RESOURCES_H
#define SIGTOOL_RESOURCES_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "bundle.h"

namespace SigTool {

// One nested-bundle entry: relative path from the bundle's contentsRoot
// (e.g. "XPCServices/Inst.xpc") plus the inner binary's cdhashes — one per
// Mach-O slice (thin = 1 entry, fat = 1 per slice). Each cdhash is the first
// 20 bytes of SHA-256 over that slice's CodeDirectory blob.
struct NestedCdHash {
    std::string relativePath;
    std::vector<std::vector<uint8_t>> cdhashes;
};

// Discover nested bundles directly under known nested-bundle directories
// (Frameworks/, SharedFrameworks/, PlugIns/, Plug-ins/, XPCServices/,
// Helpers/) under the given bundle's contentsRoot. Returns relative paths
// suitable for both signing-each-nested and emitting cdhash entries later.
std::vector<std::string> findNestedBundles(const Bundle& bundle);

// Generate a CodeResources XML plist for the given bundle. Hashes regular
// files; emits cdhash entries (in files2 only) for each nested bundle
// supplied in `nested`.
std::string generateCodeResources(const Bundle& bundle,
                                  const std::vector<NestedCdHash>& nested);

};

#endif // SIGTOOL_RESOURCES_H
