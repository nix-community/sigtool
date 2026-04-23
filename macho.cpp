#include <cstring>
#include <sys/stat.h>
#include "macho.h"

namespace SigTool {

constexpr const uint32_t MH_MAGIC_64 = 0xFEEDFACF;
constexpr const uint32_t MH_CIGAM_64 = 0xCFFAEDFE;

constexpr const uint32_t MH_FAT_MAGIC = 0xCAFEBABE;
constexpr const uint32_t MH_FAT_CIGAM = 0xBEBAFECA;

MachOList::MachOList(const std::string &filename) {
    std::ifstream f;
    f.open(filename, std::ifstream::in | std::ifstream::binary);
    if (f.fail()) {
        throw std::runtime_error(std::string{"opening input file: "} + strerror(errno));
    }

    auto magic = Read::readBytes<uint32_t>(f);

    if (magic != MH_MAGIC_64 && magic != MH_CIGAM_64 && magic != MH_FAT_MAGIC && magic != MH_FAT_CIGAM) {
        throw NotAMachOFileException{magic};
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
        throw NotAMachOFileException{magic};
    }

    f.read(reinterpret_cast<char *>(&header), sizeof(header));

    for (int cmdIdx = 0; cmdIdx < header.nCommands; cmdIdx++) {
        off_t start = f.tellg();

        uint32_t type = ReadLE::readUInt32(f);
        uint32_t cmdSize = ReadLE::readUInt32(f);

        std::shared_ptr<LoadCommand> lc;
        switch (type) {
            case LC_SEGMENT_64: {
                auto lcSegment = std::make_shared<Segment64LoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcSegment->data),
                       sizeof(Segment64LoadCommand::data));
                lc = lcSegment;
                break;
            }

            case LC_CODE_SIGNATURE: {
                auto lcCodeSignature = std::make_shared<CodeSignatureLoadCommand>(type, cmdSize);
                f.read(reinterpret_cast<char *>(&lcCodeSignature->data),
                       sizeof(CodeSignatureLoadCommand::data));
                lc = lcCodeSignature;
                break;
            }

            default:
                lc = std::make_shared<LoadCommand>(type, cmdSize);
        }
        lc->fileOffset = start;
        loadCommands.push_back(lc);

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

bool MachO::requiresSignature() {
    return (
            header.filetype == MH_EXECUTE || header.filetype == MH_DYLIB ||
            header.filetype == MH_DYLINKER || header.filetype == MH_BUNDLE ||
            header.filetype == MH_KEXT_BUNDLE || header.filetype == MH_PRELOAD
    );
}

};
