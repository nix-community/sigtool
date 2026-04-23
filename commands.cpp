#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <sys/stat.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "commands.h"
#include "macho.h"
#include "signature.h"

extern char **environ;

namespace SigTool {

constexpr const unsigned int pageSize = 4096;

static std::string readFile(const std::string &filename) {
    std::ifstream in{filename, std::ifstream::in | std::ifstream::binary};
    if (!in.is_open()) {
        throw std::runtime_error{"Failed opening file for read: '"
                                 + filename + "' :" + strerror(errno)};
    }

    std::string str;

    in.seekg(0, std::ifstream::end);
    str.resize(in.tellg());
    in.seekg(0, std::ifstream::beg);
    in.read(&str[0], str.size());

    return str;
}

static Hash hashBlob(const std::shared_ptr<Blob> &blob) {
    std::basic_ostringstream<char> buf;
    blob->emit(buf);
    return Hash{buf.str()};
}

std::string cpuTypeName(uint32_t cpuType, uint32_t cpuSubType) {
    switch (cpuType | cpuSubType) {
        case CPUTYPE_X86_64:
            return "x86_64";
        case CPUTYPE_X86_64H:
            return "x86_64h";
        case CPUTYPE_ARM64:
            return "arm64";
        case CPUTYPE_ARM64E:
            return "arm64e";
        default:
            throw std::runtime_error{std::string{"Unsupported cpu type"} + std::to_string(cpuType)};
    }
}

int Commands::checkRequiresSignature(const std::string &file) {
    try {
        MachOList test{file};
        bool anyRequires = std::any_of(test.machos.begin(), test.machos.end(), [](const std::shared_ptr<MachO> &h) {
            return h->requiresSignature();
        });
        return anyRequires ? 0 : 1;
    } catch (NotAMachOFileException &e) {
        // A shell script or text file, for example, does not require a signature.
        return 1;
    }
}

int Commands::showArch(const std::string &file) {
    MachOList test{file};

    for (const auto &macho : test.machos) {
        std::cout << cpuTypeName(macho->header.cpuType, macho->header.cpuSubType) << std::endl;
    }

    return 0;
}

static SuperBlob signMachO(
        const Commands::SignOptions &options,
        const std::shared_ptr<MachO> &target
) {
    SuperBlob sb{};

    // blob 1: code directory
    auto codeDirectory = std::make_shared<CodeDirectory>();

    codeDirectory->identifier = options.identifier.empty() ? options.filename : options.identifier;
    codeDirectory->setPageSize(pageSize);

    // TOOD: is this sane?
    if (target->header.filetype == MH_EXECUTE) {
        codeDirectory->data.execSegFlags |= CS_EXECSEG_MAIN_BINARY;
    }

    auto textSegment = target->getSegment64LoadCommand("__TEXT");
    if (textSegment) {
        codeDirectory->data.execSegBase = textSegment->data.fileoff;
        codeDirectory->data.execSegLimit = textSegment->data.fileoff + textSegment->data.filesize;
    }

    size_t limit = target->size;

    auto codeSignature = target->getCodeSignatureLoadCommand();
    if (codeSignature) {
        limit = codeSignature->data.dataOff;
        codeDirectory->setCodeLimit(codeSignature->data.dataOff);
    }

    std::ifstream machoFileRaw;
    machoFileRaw.open(options.filename, std::ifstream::in | std::ifstream::binary);
    machoFileRaw.seekg(target->offset);

    if (machoFileRaw.fail()) {
        throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
    }

    unsigned int totalPages = (limit + (pageSize - 1)) / pageSize;

    for (int page = 0; page < totalPages; page++) {
        char pageBytes[pageSize];

        off_t thisPageStart = page * pageSize;
        size_t thisPageSize = pageSize;

        if (thisPageStart + thisPageSize > limit) {
            thisPageSize = limit - thisPageStart;
        }

        machoFileRaw.read(&pageBytes[0], thisPageSize);
        if (machoFileRaw.fail()) {
            throw std::runtime_error(std::string{"reading page: "}
                                     + std::to_string(page) + " " + strerror(errno) + " expcted_bytes="
                                     + std::to_string(thisPageSize) + " actual_bytes" +
                                     std::to_string(machoFileRaw.gcount()));
        }

        Hash pageHash{&pageBytes[0], thisPageSize};
        codeDirectory->addCodeHash(pageHash);
    }

    machoFileRaw.close();

    sb.blobs.push_back(codeDirectory);

    // blob 2: requirements index with 0 entries
    auto requirements = std::make_shared<Requirements>();
    codeDirectory->setSpecialHash(requirements->slotType(), hashBlob(requirements));
    sb.blobs.push_back(requirements);

    // optional blob: entitlements
    if (!options.entitlements.empty()) {
        auto entitlements = std::make_shared<Entitlements>(readFile(options.entitlements));
        codeDirectory->setSpecialHash(entitlements->slotType(), hashBlob(entitlements));
        sb.blobs.push_back(entitlements);
    }

    // blob: empty signature slot
    sb.blobs.emplace_back(std::make_shared<Signature>());

    return sb;
}


int Commands::showSize(const SignOptions &options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);
        std::cout << cpuTypeName(macho->header.cpuType, macho->header.cpuSubType) << " " << sb.length() << std::endl;
    }

    return 0;
}

int Commands::generate(const SignOptions &options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);
        // TODO: packing them all together is not helpful, but this is still usable
        // for the thin case.
        sb.emit(std::cout);
    }

    return 0;
}

int Commands::inject(const SignOptions &options) {
    MachOList list{options.filename};
    for (const auto &macho : list.machos) {
        auto sb = signMachO(options, macho);

        auto codeSignature = macho->getCodeSignatureLoadCommand();

        if (!codeSignature) {
            throw std::runtime_error{"cannot inject signature without appropriate load command"};
        }

        if (sb.length() > codeSignature->data.dataSize) {
            throw std::runtime_error{
                    std::string{"allocated size too small: need "}
                    + std::to_string(sb.length())
                    + std::string{" but have "}
                    + std::to_string(codeSignature->data.dataSize)
            };
        }

        std::ofstream machoFileWrite;
        machoFileWrite.open(options.filename, std::ofstream::in | std::ofstream::out | std::ofstream::binary);
        if (machoFileWrite.fail()) {
            throw std::runtime_error(std::string{"opening macho file: "} + strerror(errno));
        }

        machoFileWrite.seekp(macho->offset + codeSignature->data.dataOff);
        sb.emit(machoFileWrite);
        machoFileWrite.close();
    }

    return 0;
}

static char **toSpawnArgs(const std::vector<std::string> &args) {
    char **spawnArgs = reinterpret_cast<char **>(
            calloc(args.size() + 1, sizeof(char *)));
    for (int i = 0; i < args.size(); i++) {
        spawnArgs[i] = strdup(args[i].c_str());
    }
    spawnArgs[args.size()] = nullptr;
    return spawnArgs;
}

static void freeArgs(char **spawnArgs, std::vector<std::string>::size_type size) {
    for (int i = 0; i < size; i++) {
        free(spawnArgs[i]);
    }
    free(spawnArgs);
}

static std::string inferIdentifier(const std::string& filename) {
    // basename / basename_r are awkward to use. We don't need the exact
    // meaning of basename.

    const auto slash = filename.find_last_of('/');
    if (slash == std::string::npos) {
        return filename;
    }
    std::string basename = filename.substr(slash + 1);
    if (basename.empty()) {
        return filename;
    }
    return basename;
}

int Commands::codesign(const CodesignOptions &options, const std::string &filename) {
    std::string identifier = options.identifier;
    if (identifier.empty()) {
        identifier = inferIdentifier(filename);
    }
    // Parse and discovery arguments
    MachOList list{filename};
    std::vector<std::string> arguments;

    arguments.emplace_back("codesign_allocate");
    arguments.emplace_back("-i");
    arguments.emplace_back(filename);


    for (const auto &macho : list.machos) {
        auto codeSignature = macho->getCodeSignatureLoadCommand();
        if (!options.force && codeSignature) {
            throw std::runtime_error{"file is already signed. pass -f to sign regardless."};
        }
        auto sb = signMachO(SignOptions{
                .filename = filename,
                .identifier = identifier,
                .entitlements = options.entitlements,
        }, macho);


        arguments.emplace_back("-A");
        arguments.emplace_back(std::to_string(macho->header.cpuType));
        arguments.emplace_back(std::to_string(macho->header.cpuSubType & ~CPU_SUBTYPE_MASK));

        size_t len = sb.length();
        len = ((len + 0xf) & ~0xf) + 1024; // align and pad
        arguments.push_back(std::to_string(len));
    }

    // Make temporary name
    std::unique_ptr<char, decltype(&std::free)> tempfileName { strdup((filename + "XXXXXX").c_str()), std::free };
    int tempfile = mkstemp(tempfileName.get());

    // Preserve mode
    struct stat sourceFileStat{};
    if (stat(filename.c_str(), &sourceFileStat) != 0) {
        throw std::runtime_error{std::string{"stat of "} + filename + " failed: " + strerror(errno)};
    }

    if (fchmod(tempfile, sourceFileStat.st_mode) != 0) {
        throw std::runtime_error{"chmod temporary file"};
    }

    arguments.emplace_back("-o");
    arguments.emplace_back(std::string(tempfileName.get()));

    // codesign_allocate
    pid_t pid;
    char **spawnArgs = toSpawnArgs(arguments);

    const char *codesign_allocate = getenv("CODESIGN_ALLOCATE");
    if (!codesign_allocate) {
        codesign_allocate = "codesign_allocate";
    }

    int spawn_result;
    if ((spawn_result = posix_spawnp(&pid, codesign_allocate, nullptr, nullptr, spawnArgs, environ)) != 0) {
        throw std::runtime_error{std::string{"Failed to spawn codesign_allocate: "} + strerror(spawn_result)};
    };

    int codesign_status;
    pid_t waitpid_result;
    do {
        waitpid_result = waitpid(pid, &codesign_status, 0);
    } while (waitpid_result == -1 && errno == EINTR);
    if (waitpid_result == -1) {
        throw std::runtime_error{
                std::string{"codesign waitpid failed: "} + strerror(errno)
        };
    }

    freeArgs(spawnArgs, arguments.size());

    if (!WIFEXITED(codesign_status) || WEXITSTATUS(codesign_status) != 0) {
        throw std::runtime_error{std::string{"codesign_failed: "} + std::to_string(WEXITSTATUS(codesign_status))};
    }

    if (close(tempfile) != 0) {
        throw std::runtime_error{std::string{"close: "} + strerror(tempfile)};
    }

    // inject
    Commands::inject(SignOptions{
            .filename = std::string(tempfileName.get()),
            .identifier = identifier,
            .entitlements = options.entitlements,
    });

    // rename temp file to output
    if (rename(tempfileName.get(), filename.c_str()) != 0) {
        throw std::runtime_error{"rename failed"};
    }

    return 0;
}

// Highest file offset referenced by tables living inside __LINKEDIT.
// Needed because codesign_allocate rejects files where __LINKEDIT extends
// past the actual linker data, so we must shrink filesize to the end of
// the tables rather than to where the signature started (which includes
// alignment padding).
static uint64_t computeLinkeditEnd(const std::string &filename,
                                   off_t lcAreaStart,
                                   uint32_t nCommands,
                                   uint64_t linkeditStart,
                                   uint64_t linkeditEnd) {
    enum : uint32_t {
        LC_SYMTAB_T = 0x02,
        LC_DYSYMTAB_T = 0x0b,
        LC_FUNCTION_STARTS_T = 0x26,
        LC_DATA_IN_CODE_T = 0x29,
        LC_DYLIB_CODE_SIGN_DRS_T = 0x2b,
        LC_LINKER_OPT_HINT_T = 0x2e,
        LC_DYLD_EXPORTS_TRIE_T = 0x80000033u,
        LC_DYLD_CHAINED_FIXUPS_T = 0x80000034u,
        LC_DYLD_INFO_T = 0x22,
        LC_DYLD_INFO_ONLY_T = 0x80000022u,
    };

    std::ifstream f{filename, std::ifstream::in | std::ifstream::binary};
    if (!f) {
        throw std::runtime_error{std::string{"re-opening macho: "} + strerror(errno)};
    }

    uint64_t end = 0;
    auto consider = [&](uint64_t off, uint64_t size) {
        if (size == 0) return;
        if (off < linkeditStart || off >= linkeditEnd) return;
        if (off + size > end) end = off + size;
    };

    f.seekg(lcAreaStart);
    for (uint32_t i = 0; i < nCommands; i++) {
        off_t start = f.tellg();
        uint32_t type = ReadLE::readUInt32(f);
        uint32_t cmdSize = ReadLE::readUInt32(f);

        auto u32 = [&](off_t rel) {
            f.seekg(start + rel);
            return ReadLE::readUInt32(f);
        };

        switch (type) {
            case LC_SYMTAB_T: {
                uint32_t symoff = u32(8), nsyms = u32(12);
                uint32_t stroff = u32(16), strsize = u32(20);
                consider(symoff, uint64_t(nsyms) * 16); // nlist_64
                consider(stroff, strsize);
                break;
            }
            case LC_DYSYMTAB_T: {
                uint32_t tocoff = u32(8 + 32), ntoc = u32(8 + 36);
                uint32_t modtaboff = u32(8 + 40), nmodtab = u32(8 + 44);
                uint32_t extrefoff = u32(8 + 48), nextref = u32(8 + 52);
                uint32_t indsymoff = u32(8 + 56), nindsym = u32(8 + 60);
                uint32_t extreloff = u32(8 + 64), nextrel = u32(8 + 68);
                uint32_t locreloff = u32(8 + 72), nlocrel = u32(8 + 76);
                consider(tocoff, uint64_t(ntoc) * 8);
                consider(modtaboff, uint64_t(nmodtab) * 56);
                consider(extrefoff, uint64_t(nextref) * 8);
                consider(indsymoff, uint64_t(nindsym) * 4);
                consider(extreloff, uint64_t(nextrel) * 8);
                consider(locreloff, uint64_t(nlocrel) * 8);
                break;
            }
            case LC_DYLD_INFO_T:
            case LC_DYLD_INFO_ONLY_T: {
                for (int k = 0; k < 5; k++) {
                    uint32_t off = u32(8 + k * 8);
                    uint32_t size = u32(8 + k * 8 + 4);
                    consider(off, size);
                }
                break;
            }
            case LC_FUNCTION_STARTS_T:
            case LC_DATA_IN_CODE_T:
            case LC_DYLIB_CODE_SIGN_DRS_T:
            case LC_LINKER_OPT_HINT_T:
            case LC_DYLD_EXPORTS_TRIE_T:
            case LC_DYLD_CHAINED_FIXUPS_T: {
                uint32_t off = u32(8), size = u32(12);
                consider(off, size);
                break;
            }
            default:
                break;
        }

        f.seekg(start + cmdSize);
    }
    return end;
}

int Commands::removeSignature(const std::string &filename) {
    MachOList list{filename};
    if (list.machos.size() != 1) {
        // Fat would need FatHeader rewriting + slice re-alignment.
        throw std::runtime_error{
                "--remove-signature is only supported on thin Mach-O files"};
    }
    auto macho = list.machos.front();
    auto cs = macho->getCodeSignatureLoadCommand();
    if (!cs) return 0; // matches Apple: exit 0 when already unsigned
    auto linkedit = macho->getSegment64LoadCommand("__LINKEDIT");
    if (!linkedit) {
        throw std::runtime_error{"signed Mach-O has no __LINKEDIT segment"};
    }

    const off_t lcAreaStart = macho->offset + 4 /*magic*/ + sizeof(MachOHeader);
    const uint64_t linkeditEnd =
            linkedit->data.fileoff + linkedit->data.filesize;
    uint64_t linkerDataEnd = computeLinkeditEnd(
            filename, lcAreaStart, macho->header.nCommands,
            linkedit->data.fileoff, linkeditEnd);
    if (linkerDataEnd == 0) linkerDataEnd = linkedit->data.fileoff;

    std::fstream f{filename, std::ios::in | std::ios::out | std::ios::binary};
    if (!f) {
        throw std::runtime_error{std::string{"opening macho file: "} + strerror(errno)};
    }

    // Drop LC_CODE_SIGNATURE: shift the tail up, zero the freed bytes.
    const off_t lcAreaEnd = lcAreaStart + macho->header.sizeOfCmds;
    const off_t csStart = cs->fileOffset;
    const off_t csEnd = csStart + cs->cmdSize;
    if (csEnd > lcAreaEnd) {
        throw std::runtime_error{
                "malformed Mach-O: LC_CODE_SIGNATURE extends past load command area"};
    }
    std::vector<char> tail(static_cast<size_t>(lcAreaEnd - csEnd));
    if (!tail.empty()) {
        f.seekg(csEnd);
        f.read(tail.data(), tail.size());
        if (f.fail()) {
            throw std::runtime_error{"reading load command tail"};
        }
    }
    f.clear();
    f.seekp(csStart);
    if (!tail.empty()) {
        f.write(tail.data(), tail.size());
    }
    std::vector<char> zeros(cs->cmdSize, 0);
    f.write(zeros.data(), zeros.size());


    uint32_t newNCommands = macho->header.nCommands - 1;
    uint32_t newSizeOfCmds = macho->header.sizeOfCmds - cs->cmdSize;
    f.seekp(macho->offset + 4 /*magic*/ + offsetof(MachOHeader, nCommands));
    f.write(reinterpret_cast<const char *>(&newNCommands), 4);
    f.write(reinterpret_cast<const char *>(&newSizeOfCmds), 4);

    // Shrink __LINKEDIT.filesize; leave vmsize alone (page size varies).
    // Segment64 layout after 8-byte LC header: segname[16] vmaddr vmsize
    // fileoff filesize (all u64) -> filesize at +8+40.
    uint64_t newFilesize = linkerDataEnd - linkedit->data.fileoff;
    f.seekp(linkedit->fileOffset + 8 + 40);
    f.write(reinterpret_cast<const char *>(&newFilesize), 8);

    f.flush();
    f.close();

    if (truncate(filename.c_str(), linkerDataEnd) != 0) {
        throw std::runtime_error{std::string{"truncate: "} + strerror(errno)};
    }

    return 0;
}
};
