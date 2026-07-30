#include "commands.h"
#include <CLI11.hpp>

int main(int argc, char **argv) {
    CLI::App app{"codesign"};

    std::string identity, identifier, entitlements;
    bool force = false;
    bool generateEntitlementDER = false;
    std::vector<std::string> files;
    app.add_option("-s,--sign", identity, "Code signing identity")->required();
    app.add_option("-i,--identifier", identifier, "File identifier");
    app.add_flag("-f,--force", force, "Replace any existing signatures");
    app.add_option("--entitlements", entitlements, "Entitlements plist");
    app.add_flag("--generate-entitlement-der", generateEntitlementDER,
                 "Also embed DER-encoded entitlements");
    app.add_option("files", files, "Files to sign");

    CLI11_PARSE(app, argc, argv);

    if (identity != std::string{"-"}) {
        throw std::runtime_error{
                std::string{"Only ad-hoc identities supported, requested: '"} + identity + "'"};
    }

    SigTool::Commands::CodesignOptions options{
            .identifier = identifier,
            .entitlements = entitlements,
            .force = force,
            .generateEntitlementDER = generateEntitlementDER,
    };

    for (const auto &f : files) {
	SigTool::Commands::codesign(options, f);
    }

    return 0;
}
