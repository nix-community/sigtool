#include "commands.h"
#include <CLI11.hpp>
#include <cstring>
#include <iostream>

static int run(int argc, char **argv);

int main(int argc, char **argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "codesign: error: " << e.what() << std::endl;
        return 1;
    }
}

static int run(int argc, char **argv) {
    CLI::App app{"codesign"};

    std::string identity, identifier, entitlements, timestamp, optionsFlags;
    bool force = false;
    bool generateEntitlementDER = false;
    std::vector<std::string> files;
    app.add_option("-s,--sign", identity, "Code signing identity")->required();
    app.add_option("-i,--identifier", identifier, "File identifier");
    app.add_flag("-f,--force", force, "Replace any existing signatures");
    app.add_option("--entitlements", entitlements, "Entitlements plist");
    app.add_flag("--generate-entitlement-der", generateEntitlementDER,
                 "Also embed DER-encoded entitlements");
    // Apple's --timestamp takes an optional joined value only:
    //   --timestamp        request default TSA (not supported here)
    //   --timestamp=none   suppress timestamping (no-op for ad-hoc)
    //   --timestamp=URL    request a specific TSA (not supported here)
    // A string-valued flag matches that shape: it accepts a '='-joined value
    // but never consumes the following argument. A bare --timestamp yields
    // "true", which is rejected below like any value other than "none".
    app.add_flag("--timestamp", timestamp,
                 "Timestamp options; only '--timestamp=none' is supported");
    app.add_option("-o,--options", optionsFlags,
                   "Comma-separated signing options; only 'runtime' is supported");
    app.add_option("files", files, "Files to sign");

    CLI11_PARSE(app, argc, argv);

    if (!timestamp.empty() && timestamp != "none") {
        throw std::runtime_error{
                std::string{"--timestamp only supports '=none' (TSA timestamping "
                            "is not available with ad-hoc signatures)"}};
    }

    if (identity != std::string{"-"}) {
        throw std::runtime_error{
                std::string{"Only ad-hoc identities supported, requested: '"} + identity + "'"};
    }

    bool hardenedRuntime = false;
    if (!optionsFlags.empty()) {
        size_t start = 0;
        while (start <= optionsFlags.size()) {
            size_t comma = optionsFlags.find(',', start);
            if (comma == std::string::npos) comma = optionsFlags.size();
            std::string opt = optionsFlags.substr(start, comma - start);
            if (opt == "runtime") {
                hardenedRuntime = true;
            } else if (!opt.empty()) {
                throw std::runtime_error{
                        "-o option '" + opt + "' is not supported "
                        "(only 'runtime' is recognised)"};
            }
            if (comma == optionsFlags.size()) break;
            start = comma + 1;
        }
    }

    SigTool::Commands::CodesignOptions options{
            .identifier = identifier,
            .entitlements = entitlements,
            .force = force,
            .generateEntitlementDER = generateEntitlementDER,
            .hardenedRuntime = hardenedRuntime,
    };

    for (const auto &f : files) {
	SigTool::Commands::codesign(options, f);
    }

    return 0;
}
