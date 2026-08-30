#ifndef SIGTOOL_BUNDLE_H
#define SIGTOOL_BUNDLE_H

#include <string>

namespace SigTool {

struct Bundle {
    enum class Type { Single, App, Framework };

    Type type = Type::Single;

    // Bundle root as the user passed it (or single-file path).
    std::string root;

    // Walk root for resource hashing:
    //   App        -> <root>/Contents
    //   Framework  -> <root>/Versions/<V>
    //   Single     -> empty
    std::string contentsRoot;

    // Inner Mach-O binary (the only path actually signed).
    std::string binaryPath;

    // Info.plist path (empty for Single, or if the bundle has none).
    std::string infoPlistPath;

    // CFBundleIdentifier from Info.plist (empty if not derivable).
    std::string identifier;
};

// Detect a bundle structure from a path. If `path` is a regular file, returns
// a Single-typed Bundle with binaryPath=path. If it's a directory recognised
// as a framework or .app, populates the bundle paths and reads the identifier
// from Info.plist. Throws std::runtime_error on unsupported directories or
// malformed bundles.
Bundle detectBundle(const std::string& path);

};

#endif // SIGTOOL_BUNDLE_H
