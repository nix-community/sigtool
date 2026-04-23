#ifndef SIGTOOL_MACHO_H
#define SIGTOOL_MACHO_H

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <netinet/in.h>
#include <iostream>
#include "emit.h"

// This project intends to be standalone and portable, however it may
// also be compiled on platforms where these constants are already
// defined. In this case, we make sure to remove the ambient
// definitions for consistency. The only known overlapping symbols are
// CPU_SUBTYPE_ARM64E and CPU_SUBTYPE_MASK.

#ifdef CPU_SUBTYPE_ARM64E
#undef CPU_SUBTYPE_ARM64E
#endif

#ifdef CPU_SUBTYPE_MASK
#undef CPU_SUBTYPE_MASK
#endif

namespace SigTool {

enum {
    MH_EXECUTE = 0x2,
    MH_PRELOAD = 0x5,
    MH_DYLIB = 0x6,
    MH_DYLINKER = 0x7,
    MH_BUNDLE = 0x8,
    MH_KEXT_BUNDLE = 0xb,
};

enum {
    CPU_SUBTYPE_MASK = 0xff000000,
    CPU_SUBTYPE_ARM64E = 0x2,
    CPU_SUBTYPE_X86_64H = 0x8,
};

enum {
    CPUTYPE_I386 = 0x7,
    CPUTYPE_ARM = 0xc,
    CPUTYPE_64_BIT = 0x1000000,

    CPUTYPE_X86_64 = CPUTYPE_I386 | CPUTYPE_64_BIT,
    CPUTYPE_X86_64H = CPUTYPE_I386 | CPUTYPE_64_BIT | CPU_SUBTYPE_X86_64H,
    CPUTYPE_ARM64 = CPUTYPE_ARM | CPUTYPE_64_BIT,
    CPUTYPE_ARM64E = CPUTYPE_ARM | CPUTYPE_64_BIT | CPU_SUBTYPE_ARM64E,
};

enum LCType {
    LC_CODE_SIGNATURE = 0x1d,
    LC_SEGMENT_64 = 0x19,
};

struct MachOHeader {
    uint32_t cpuType;
    uint32_t cpuSubType;
    uint32_t filetype;
    uint32_t nCommands;
    uint32_t sizeOfCmds;
    uint32_t flags;
    uint32_t reserved; // only for 64-bit
} __attribute__((packed));

struct FatHeader {
    uint32_t cpuType;
    uint32_t cpuSubType;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct LoadCommand {
    uint32_t type;
    uint32_t cmdSize;
    off_t fileOffset = 0; // absolute offset in file; set by MachO ctor

    explicit LoadCommand(uint32_t type, uint32_t cmdSize) : type(type), cmdSize(cmdSize) {};
};

struct Segment64LoadCommand : public LoadCommand {
    explicit Segment64LoadCommand(uint32_t type, uint32_t cmdSize)
            : LoadCommand(type, cmdSize) {};

    struct {
        char segname[16];
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
    } __attribute__((packed)) data{};
};

struct CodeSignatureLoadCommand : public LoadCommand {
    explicit CodeSignatureLoadCommand(uint32_t type, uint32_t cmdSize)
            : LoadCommand(type, cmdSize) {};

    struct {
        uint32_t dataOff;
        uint32_t dataSize;
    } __attribute__((packed)) data{};
};

// A single architecture slice
struct MachO {
    explicit MachO(std::ifstream &f, off_t offset, size_t size);

    MachOHeader header;
    off_t offset;
    size_t size;

    std::shared_ptr<Segment64LoadCommand> getSegment64LoadCommand(const std::string &name);

    std::shared_ptr<CodeSignatureLoadCommand> getCodeSignatureLoadCommand();

    bool requiresSignature();

private:
    std::vector<std::shared_ptr<LoadCommand>> loadCommands;
};

// All the architectures contained in a file. The file itself may be either a single architecture or universal.
struct MachOList {
    explicit MachOList(const std::string &f);

    std::vector<std::shared_ptr<MachO>> machos;
};

struct NotAMachOFileException : public std::exception {
    uint32_t magic;

    explicit NotAMachOFileException(uint32_t magic) : magic{magic} {}
};
};

#endif //SIGTOOL_MACHO_H
