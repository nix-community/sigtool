#include "commands.h"
#include <CLI11.hpp>

int main(int argc, char **argv) {
    CLI::App app{"codesign"};

    std::string identity, identifier, entitlements;
    bool force = false;
    bool removeSignature = false;
    std::vector<std::string> files;
    auto *signOpt = app.add_option("-s,--sign", identity, "Code signing identity");
    app.add_option("-i,--identifier", identifier, "File identifier");
    app.add_flag("-f,--force", force, "Replace any existing signatures");
    app.add_option("--entitlements", entitlements, "Entitlements plist");
    app.add_flag("--remove-signature", removeSignature,
                 "Remove any existing code signature from the target file");
    app.add_option("files", files, "Files to sign");

    CLI11_PARSE(app, argc, argv);

    if (removeSignature) {
        if (*signOpt) {
            throw std::runtime_error{"--remove-signature is mutually exclusive with --sign"};
        }
        for (const auto &f : files) {
            SigTool::Commands::removeSignature(f);
        }
        return 0;
    }

    if (!*signOpt) {
        throw std::runtime_error{"--sign is required unless --remove-signature is given"};
    }
    if (identity != std::string{"-"}) {
        throw std::runtime_error{
                std::string{"Only ad-hoc identities supported, requested: '"} + identity + "'"};
    }

    SigTool::Commands::CodesignOptions options{
            .identifier = identifier,
            .entitlements = entitlements,
            .force = force,
    };

    for (const auto &f : files) {
	SigTool::Commands::codesign(options, f);
    }

    return 0;
}
