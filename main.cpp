#include "commands.h"
#include <CLI11.hpp>
#include <iostream>

static int run(int argc, char **argv);

int main(int argc, char **argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "sigtool: error: " << e.what() << std::endl;
        return 1;
    }
}

static int run(int argc, char **argv) {
    CLI::App app{"sigtool"};
    app.require_subcommand();

    std::string file, identifier, entitlements;
    bool generateEntitlementDER = false;
    bool hardenedRuntime = false;
    app.add_option("-f,--file", file, "Mach-O target file")
            ->required();
    app.add_option("-i,--identifier", identifier, "File identifier");
    app.add_option("-e,--entitlements", entitlements, "Entitlements plist");
    app.add_flag("--generate-entitlement-der", generateEntitlementDER,
                 "Also embed DER-encoded entitlements");
    app.add_flag("--hardened-runtime", hardenedRuntime,
                 "Enable hardened runtime (sets CS_RUNTIME flag)");

    app.add_subcommand("check-requires-signature",
                       "Determine if this is a macho file that must be signed");

    app.add_subcommand("size", "Determine size of embedded signature");
    app.add_subcommand("generate", "Generate an embedded signature and emit on stdout");
    app.add_subcommand("inject", "Generate and inject embedded signature");
    app.add_subcommand("show-arch", "Show architecture");

    app.require_subcommand();

    CLI11_PARSE(app, argc, argv);

    if (app.got_subcommand("check-requires-signature")) {
        return SigTool::Commands::checkRequiresSignature(file);
    } else if (app.got_subcommand("show-arch")) {
        return SigTool::Commands::showArch(file);
    }

    SigTool::Commands::SignOptions options{
            .filename = file,
            .identifier = identifier,
            .entitlements = entitlements,
            .generateEntitlementDER = generateEntitlementDER,
            .hardenedRuntime = hardenedRuntime,
    };

    if (app.got_subcommand("size")) {
        return SigTool::Commands::showSize(options);
    } else if (app.got_subcommand("generate")) {
        return SigTool::Commands::generate(options);
    } else if (app.got_subcommand("inject")) {
        return SigTool::Commands::inject(options);
    }

    return 0;
}
