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
    };

    struct CodesignOptions {
        std::string identifier;
        std::string entitlements;
        bool force;
        bool generateEntitlementDER;
        bool hardenedRuntime;
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
