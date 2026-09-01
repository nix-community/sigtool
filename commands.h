#ifndef SIGTOOL_COMMANDS_H
#define SIGTOOL_COMMANDS_H

#include <string>

namespace SigTool {
namespace Commands {
    struct SignOptions {
        std::string filename;
        std::string identifier;
        std::string entitlements;
        bool generateEntitlementDER;
        bool hardenedRuntime;
        // For bundle signing: paths whose hashes seed CodeDirectory special
        // slots 1 (Info.plist) and 3 (CodeResources). Empty = unused.
        std::string infoPlistPath;
        std::string codeResourcesPath;
        // Raw entitlements XML; takes precedence over `entitlements` (path)
        // when non-empty. Used for --preserve-metadata=entitlements.
        std::string entitlementsData;
        // Runtime version emitted when hardenedRuntime is set. 0 = derive
        // from the target's LC_BUILD_VERSION / LC_VERSION_MIN sdk field.
        uint32_t runtimeVersion;
        // Additional CodeDirectory flag bits to set (CS_HARD, CS_KILL, ...).
        // CS_RUNTIME is requested via hardenedRuntime instead, since it also
        // needs the version bump and runtime field.
        uint32_t extraFlags;
    };

    struct CodesignOptions {
        std::string identifier;
        std::string entitlements;
        bool force;
        bool generateEntitlementDER;
        bool hardenedRuntime;
        // True when -o/--options was passed on the CLI. An explicit -o
        // replaces preserved flags entirely (Apple semantics).
        bool optionsSpecified;
        // --preserve-metadata categories. When set, fields not explicitly
        // overridden on the CLI are taken from the existing signature.
        bool preserveIdentifier;
        bool preserveEntitlements;
        bool preserveFlags;
    };

    int checkRequiresSignature(const std::string &file);
    int showArch(const std::string &file);
    int showSize(const SignOptions& options);
    int inject(const SignOptions& options);
    int generate(const SignOptions& options);
    int codesign(const CodesignOptions& options, const std::string& file);
};
};

#endif // SIGTOOL_COMMANDS_H
