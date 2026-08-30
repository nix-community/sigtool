#include <cstring>
#include <sstream>
#include <sys/stat.h>
#include "macho.h"

namespace SigTool {

constexpr const uint32_t MH_MAGIC_64 = 0xFEEDFACF;
constexpr const uint32_t MH_CIGAM_64 = 0xCFFAEDFE;

constexpr const uint32_t MH_FAT_MAGIC = 0xCAFEBABE;
constexpr const uint32_t MH_FAT_CIGAM = 0xBEBAFECA;

// If `path` looks like a bundle directory (e.g. Foo.framework/Versions/A or
// Foo.app), return the conventional path of the main Mach-O binary inside.
// Returns an empty string if no convention applies.
static std::string suggestBundleBinary(const std::string &path) {
    std::string p = path;
    while (p.size() > 1 && p.back() == '/') p.pop_back();

    auto basename = [](const std::string &s) {
        auto slash = s.find_last_of('/');
        return slash == std::string::npos ? s : s.substr(slash + 1);
    };
    auto endsWith = [](const std::string &s, const std::string &suffix) {
        return s.size() >= suffix.size()
               && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    };

    // Foo.framework/Versions/<V>
    auto slash = p.find_last_of('/');
    if (slash != std::string::npos) {
        std::string parent = p.substr(0, slash);
        auto slash2 = parent.find_last_of('/');
        std::string grandparent = slash2 == std::string::npos
                                  ? std::string{}
                                  : parent.substr(0, slash2);
        std::string parentBase = slash2 == std::string::npos
                                 ? parent
                                 : parent.substr(slash2 + 1);
        if (parentBase == "Versions" && endsWith(grandparent, ".framework")) {
            std::string name = basename(grandparent);
            name = name.substr(0, name.size() - sizeof(".framework") + 1);
            return p + "/" + name;
        }
    }

    // Foo.app
    if (endsWith(p, ".app")) {
        std::string name = basename(p);
        name = name.substr(0, name.size() - sizeof(".app") + 1);
        return p + "/Contents/MacOS/" + name;
    }

    return {};
}

MachOList::MachOList(const std::string &filename) {
    struct stat st{};
    if (stat(filename.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        std::ostringstream msg;
        msg << "input is a directory: '" << filename
            << "'. Bundle signing (resource manifest generation) is not "
               "supported; pass the path to the Mach-O binary inside";
        std::string suggestion = suggestBundleBinary(filename);
        if (!suggestion.empty()) {
            msg << ", e.g. '" << suggestion << "'";
        }
        throw NotAMachOFileException{msg.str()};
    }

    std::ifstream f;
    f.open(filename, std::ifstream::in | std::ifstream::binary);
    if (f.fail()) {
        throw std::runtime_error(std::string{"opening input file: "} + strerror(errno));
    }

    auto magic = Read::readBytes<uint32_t>(f);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64 && magic != MH_FAT_MAGIC && magic != MH_FAT_CIGAM) {
        std::ostringstream msg;
        msg << "not a Mach-O file: '" << filename << "' (unrecognized magic 0x"
            << std::hex << magic << ")";
        throw NotAMachOFileException{msg.str()};
    }

    if (magic == MH_FAT_CIGAM) {
        // Many files in one file
        auto count = ReadBE::readUInt32(f);
        for (int i = 0; i < count; i++) {
            FatHeader fatHeader{};

            fatHeader.cpuType = ReadBE::readUInt32(f);
            fatHeader.cpuSubType = ReadBE::readUInt32(f);
            fatHeader.offset = ReadBE::readUInt32(f);
            fatHeader.size = ReadBE::readUInt32(f);
            fatHeader.align = ReadBE::readUInt32(f);

            auto preserve = f.tellg();
            f.seekg(fatHeader.offset);
            machos.push_back(std::make_shared<MachO>(f, fatHeader.offset, fatHeader.size));
            f.seekg(preserve);
        }
    } else if (magic == MH_MAGIC_64) {
        // Single file
        f.seekg(0);
        struct stat targetFileStat{};
        if (stat(filename.c_str(), &targetFileStat) != 0) {
            throw std::runtime_error{std::string{"Stat of "} + filename + " failed: " + strerror(errno)};
        }

        machos.push_back(std::make_shared<MachO>(f, 0, targetFileStat.st_size));
    } else {
        throw std::runtime_error{
                std::string{"Unexpected magic parsing macho file: "} + std::to_string(magic)};
    }

}

MachO::MachO(std::ifstream &f, off_t offset, size_t size) : header{}, offset{offset}, size{size} {
    auto magic = Read::readBytes<uint32_t>(f);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64) {
        std::ostringstream msg;
        msg << "not a 64-bit Mach-O slice (unrecognized magic 0x"
            << std::hex << magic << ")";
        throw NotAMachOFileException{msg.str()};
    }

    f.read(reinterpret_cast<char *>(&header), sizeof(header));

    for (int cmdIdx = 0; cmdIdx < header.nCommands; cmdIdx++) {
        off_t start = f.tellg();

        uint32_t type = ReadLE::readUInt32(f);
        uint32_t cmdSize = ReadLE::readUInt32(f);

        switch (type) {
            case LC_SEGMENT_64: {
                auto lcSegment = std::make_shared<Segment64LoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcSegment->data),
                       sizeof(Segment64LoadCommand::data));
                loadCommands.push_back(lcSegment);
                break;
            }

            case LC_BUILD_VERSION: {
                auto lcBuildVersion = std::make_shared<BuildVersionLoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcBuildVersion->data),
                       sizeof(BuildVersionLoadCommand::data));
                loadCommands.push_back(lcBuildVersion);
                break;
            }

            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
            case LC_VERSION_MIN_TVOS:
            case LC_VERSION_MIN_WATCHOS: {
                auto lcVersionMin = std::make_shared<VersionMinLoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcVersionMin->data),
                       sizeof(VersionMinLoadCommand::data));
                loadCommands.push_back(lcVersionMin);
                break;
            }

            case LC_CODE_SIGNATURE: {
                auto lcCodeSignature = std::make_shared<CodeSignatureLoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcCodeSignature->data),
                       sizeof(CodeSignatureLoadCommand::data));
                loadCommands.push_back(lcCodeSignature);
                break;
            }

            default:
                auto lc = std::make_shared<LoadCommand>(type, cmdSize);
                loadCommands.push_back(lc);
        }

        size_t actualRead = f.tellg() - start;

        // Laziness: allow partial reads by skpping ahead
        // TODO: demand complete parses and make this explode instead
        if (actualRead < cmdSize) {
            f.seekg(cmdSize - actualRead, std::ifstream::cur);
        }
    }
}

std::shared_ptr<Segment64LoadCommand> MachO::getSegment64LoadCommand(const std::string &name) {
    for (const auto &lc : loadCommands) {
        if (lc->type != LC_SEGMENT_64) {
            continue;
        }

        std::shared_ptr<Segment64LoadCommand> segment64 =
                std::static_pointer_cast<Segment64LoadCommand>(lc);
        if (strncmp(segment64->data.segname, name.c_str(), sizeof(segment64->data.segname)) != 0) {
            continue;
        }

        return segment64;
    }
    return std::shared_ptr<Segment64LoadCommand>{};
}

std::shared_ptr<CodeSignatureLoadCommand> MachO::getCodeSignatureLoadCommand() {
    for (const auto &lc : loadCommands) {
        if (lc->type != LC_CODE_SIGNATURE) {
            continue;
        }

        return std::static_pointer_cast<CodeSignatureLoadCommand>(lc);
    }
    return std::shared_ptr<CodeSignatureLoadCommand>{};
}

uint32_t MachO::sdkVersion() {
    for (const auto &lc : loadCommands) {
        if (lc->type == LC_BUILD_VERSION) {
            return std::static_pointer_cast<BuildVersionLoadCommand>(lc)->data.sdk;
        }
    }

    for (const auto &lc : loadCommands) {
        switch (lc->type) {
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
            case LC_VERSION_MIN_TVOS:
            case LC_VERSION_MIN_WATCHOS:
                return std::static_pointer_cast<VersionMinLoadCommand>(lc)->data.sdk;
        }
    }

    return 0;
}

bool MachO::requiresSignature() {
    return (
            header.filetype == MH_EXECUTE || header.filetype == MH_DYLIB ||
            header.filetype == MH_DYLINKER || header.filetype == MH_BUNDLE ||
            header.filetype == MH_KEXT_BUNDLE || header.filetype == MH_PRELOAD
    );
}

};
