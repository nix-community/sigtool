#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "bundle.h"
#include "commands.h"
#include "macho.h"
#include "resources.h"
#include "signature.h"
#include "der.h"

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

    if (options.extraFlags) {
        codeDirectory->data.flags |= options.extraFlags;
    }

    if (options.hardenedRuntime) {
        codeDirectory->setHardenedRuntime(
                options.runtimeVersion ? options.runtimeVersion : target->sdkVersion());
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

    // bundle special hashes: slot 1 = Info.plist, slot 3 = CodeResources
    if (!options.infoPlistPath.empty()) {
        std::string infoData = readFile(options.infoPlistPath);
        Hash infoHash{infoData.data(), infoData.size()};
        codeDirectory->setSpecialHash(1 /* CSSLOT_INFOSLOT */, infoHash);
    }
    if (!options.codeResourcesPath.empty()) {
        std::string crData = readFile(options.codeResourcesPath);
        Hash crHash{crData.data(), crData.size()};
        codeDirectory->setSpecialHash(3 /* CSSLOT_RESOURCEDIR */, crHash);
    }

    // optional blob: entitlements (raw data takes precedence over file path)
    std::string plistXml;
    if (!options.entitlementsData.empty()) {
        plistXml = options.entitlementsData;
    } else if (!options.entitlements.empty()) {
        plistXml = readFile(options.entitlements);
    }
    if (!plistXml.empty()) {
        auto entitlements = std::make_shared<Entitlements>(plistXml);
        codeDirectory->setSpecialHash(entitlements->slotType(), hashBlob(entitlements));
        sb.blobs.push_back(entitlements);

        if (options.generateEntitlementDER) {
            auto entitlementsDer = std::make_shared<EntitlementsDER>(encodeEntitlementsDER(plistXml));
            codeDirectory->setSpecialHash(entitlementsDer->slotType(), hashBlob(entitlementsDer));
            sb.blobs.push_back(entitlementsDer);
        }
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

// Compute the cdhash of every signed Mach-O slice in `filename` — the first
// 20 bytes of SHA-256 over each slice's CodeDirectory blob. Throws if the
// binary has no signature.
static std::vector<std::vector<uint8_t>> computeCDHashes(const std::string& filename);

static uint32_t readBE32(const char *p) {
    auto u = reinterpret_cast<const unsigned char *>(p);
    return (uint32_t(u[0]) << 24) | (uint32_t(u[1]) << 16)
           | (uint32_t(u[2]) << 8) | uint32_t(u[3]);
}

static std::vector<std::vector<uint8_t>> computeCDHashes(const std::string& filename) {
    std::vector<std::vector<uint8_t>> out;
    MachOList list{filename};
    for (const auto &macho : list.machos) {
        auto cs = macho->getCodeSignatureLoadCommand();
        if (!cs) continue;

        std::ifstream in(filename, std::ifstream::binary);
        if (!in.is_open()) continue;
        in.seekg(macho->offset + cs->data.dataOff);
        std::vector<char> buf(cs->data.dataSize);
        in.read(buf.data(), buf.size());
        if (static_cast<size_t>(in.gcount()) != buf.size()) continue;

        if (buf.size() < 12) continue;
        if (readBE32(buf.data()) != CSMAGIC_EMBEDDED_SIGNATURE) continue;
        uint32_t count = readBE32(buf.data() + 8);
        for (uint32_t i = 0; i < count; i++) {
            size_t indexEntry = 12 + size_t{i} * 8;
            if (indexEntry + 8 > buf.size()) break;
            uint32_t blobOff = readBE32(buf.data() + indexEntry + 4);
            if (blobOff + 8 > buf.size()) continue;
            uint32_t blobMagic = readBE32(buf.data() + blobOff);
            uint32_t blobLen = readBE32(buf.data() + blobOff + 4);
            if (blobOff + blobLen > buf.size()) continue;
            if (blobMagic == CSMAGIC_CODEDIRECTORY) {
                SHA256Hash h{buf.data() + blobOff, blobLen};
                std::vector<uint8_t> cdhash(20);
                for (int b = 0; b < 20; b++) {
                    cdhash[b] = static_cast<uint8_t>(h.bytes[b]);
                }
                out.push_back(std::move(cdhash));
                break; // Each slice has one CodeDirectory.
            }
        }
    }
    if (out.empty()) {
        throw std::runtime_error{
                "computeCDHashes: no signed CodeDirectory found in '"
                + filename + "'"};
    }
    return out;
}

// Snapshot of metadata pulled from an existing signature, used to honour
// --preserve-metadata when re-signing.
struct ExistingSignature {
    bool present = false;
    std::string identifier;
    std::string entitlementsXml;
    uint32_t flags = 0;
    uint32_t runtime = 0;
};

// Read identifier / entitlements XML / flags / runtime from the first
// architecture slice that has an embedded SuperBlob. Returns present=false if
// the binary isn't signed at all.
static ExistingSignature readExistingSignature(const std::string &filename) {
    ExistingSignature out{};
    MachOList list{filename};
    for (const auto &macho : list.machos) {
        auto cs = macho->getCodeSignatureLoadCommand();
        if (!cs) continue;

        std::ifstream in(filename, std::ifstream::binary);
        if (!in.is_open()) continue;
        in.seekg(macho->offset + cs->data.dataOff);
        std::vector<char> buf(cs->data.dataSize);
        in.read(buf.data(), buf.size());
        if (static_cast<size_t>(in.gcount()) != buf.size()) continue;

        if (buf.size() < 12) continue;
        if (readBE32(buf.data()) != CSMAGIC_EMBEDDED_SIGNATURE) continue;
        uint32_t count = readBE32(buf.data() + 8);

        for (uint32_t i = 0; i < count; i++) {
            size_t indexEntry = 12 + size_t{i} * 8;
            if (indexEntry + 8 > buf.size()) break;
            uint32_t blobOff = readBE32(buf.data() + indexEntry + 4);
            if (blobOff + 8 > buf.size()) continue;
            uint32_t blobMagic = readBE32(buf.data() + blobOff);
            uint32_t blobLen = readBE32(buf.data() + blobOff + 4);
            if (blobOff + blobLen > buf.size()) continue;

            if (blobMagic == CSMAGIC_CODEDIRECTORY) {
                if (blobLen < 44) continue;
                uint32_t version = readBE32(buf.data() + blobOff + 8);
                out.flags = readBE32(buf.data() + blobOff + 12);
                uint32_t identOffset = readBE32(buf.data() + blobOff + 20);
                if (identOffset < blobLen) {
                    const char *id = buf.data() + blobOff + identOffset;
                    size_t maxLen = blobLen - identOffset;
                    size_t idLen = ::strnlen(id, maxLen);
                    out.identifier.assign(id, idLen);
                }
                if (version >= 0x20500 && blobLen >= 92) {
                    out.runtime = readBE32(buf.data() + blobOff + 88);
                }
            } else if (blobMagic == CSMAGIC_EMBEDDED_ENTITLEMENTS) {
                if (blobLen >= 8) {
                    out.entitlementsXml.assign(
                            buf.data() + blobOff + 8, blobLen - 8);
                }
            }
        }
        out.present = true;
        return out;
    }
    return out;
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

// Sign a single Mach-O file in place (handles allocation via codesign_allocate
// and injection of the new signature). `signTemplate` carries everything the
// CodeDirectory needs; `binaryFile` and `force` are flow control.
static void signOneMachO(const Commands::SignOptions &signTemplate,
                         const std::string &binaryFile,
                         bool force) {
    MachOList list{binaryFile};
    std::vector<std::string> arguments;

    arguments.emplace_back("codesign_allocate");
    arguments.emplace_back("-i");
    arguments.emplace_back(binaryFile);

    Commands::SignOptions perFile = signTemplate;
    perFile.filename = binaryFile;

    for (const auto &macho : list.machos) {
        auto codeSignature = macho->getCodeSignatureLoadCommand();
        if (!force && codeSignature) {
            throw std::runtime_error{"file is already signed. pass -f to sign regardless."};
        }
        auto sb = signMachO(perFile, macho);

        arguments.emplace_back("-A");
        arguments.emplace_back(std::to_string(macho->header.cpuType));
        arguments.emplace_back(std::to_string(macho->header.cpuSubType & ~CPU_SUBTYPE_MASK));

        size_t len = sb.length();
        len = ((len + 0xf) & ~0xf) + 1024; // align and pad
        arguments.push_back(std::to_string(len));
    }

    std::unique_ptr<char, decltype(&std::free)> tempfileName{
            strdup((binaryFile + "XXXXXX").c_str()), std::free};
    int tempfile = mkstemp(tempfileName.get());

    struct stat sourceFileStat{};
    if (stat(binaryFile.c_str(), &sourceFileStat) != 0) {
        throw std::runtime_error{std::string{"stat of "} + binaryFile + " failed: " + strerror(errno)};
    }
    if (fchmod(tempfile, sourceFileStat.st_mode) != 0) {
        throw std::runtime_error{"chmod temporary file"};
    }

    arguments.emplace_back("-o");
    arguments.emplace_back(std::string(tempfileName.get()));

    pid_t pid;
    char **spawnArgs = toSpawnArgs(arguments);
    const char *codesign_allocate = getenv("CODESIGN_ALLOCATE");
    if (!codesign_allocate) {
        codesign_allocate = "codesign_allocate";
    }

    int spawn_result;
    if ((spawn_result = posix_spawnp(&pid, codesign_allocate, nullptr, nullptr, spawnArgs, environ)) != 0) {
        throw std::runtime_error{std::string{"Failed to spawn codesign_allocate: "} + strerror(spawn_result)};
    }

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

    Commands::SignOptions injectOpts = signTemplate;
    injectOpts.filename = std::string(tempfileName.get());
    Commands::inject(injectOpts);

    if (rename(tempfileName.get(), binaryFile.c_str()) != 0) {
        throw std::runtime_error{"rename failed"};
    }
}

static void writeFileBytes(const std::string &path, const std::string &bytes) {
    std::ofstream out(path, std::ofstream::binary | std::ofstream::trunc);
    if (!out.is_open()) {
        throw std::runtime_error{"opening '" + path + "' for write failed"};
    }
    out.write(bytes.data(), bytes.size());
    if (!out) {
        throw std::runtime_error{"writing to '" + path + "' failed"};
    }
}

int Commands::codesign(const CodesignOptions &options, const std::string &filename) {
    Bundle bundle = detectBundle(filename);

    // Read existing signature only when at least one --preserve-metadata
    // category was requested, to avoid an extra parse pass on every call.
    ExistingSignature preserved{};
    bool needPreserve = options.preserveIdentifier
                        || options.preserveEntitlements
                        || options.preserveFlags;
    if (needPreserve) {
        preserved = readExistingSignature(bundle.binaryPath);
        if (!preserved.present) {
            throw std::runtime_error{
                    "--preserve-metadata: '" + bundle.binaryPath
                    + "' has no existing signature to preserve from"};
        }
    }

    std::string identifier = options.identifier;
    if (identifier.empty() && options.preserveIdentifier) {
        identifier = preserved.identifier;
    }
    if (identifier.empty()) identifier = bundle.identifier;
    if (identifier.empty()) identifier = inferIdentifier(bundle.binaryPath);

    SignOptions signTemplate{};
    signTemplate.identifier = identifier;
    signTemplate.entitlements = options.entitlements;
    signTemplate.generateEntitlementDER = options.generateEntitlementDER;
    signTemplate.hardenedRuntime = options.hardenedRuntime;
    // An explicit --entitlements always wins over preserved ones (Apple
    // semantics: preserve unless overridden on the command line).
    if (options.preserveEntitlements && options.entitlements.empty()) {
        signTemplate.entitlementsData = preserved.entitlementsXml;
    }
    // Apple semantics: an explicit -o/--options replaces the preserved flags
    // entirely; otherwise every option flag bit is carried over verbatim.
    if (options.preserveFlags && !options.optionsSpecified) {
        signTemplate.extraFlags =
                preserved.flags & (CS_PRESERVABLE_FLAGS & ~uint32_t{CS_RUNTIME});
        if (preserved.flags & CS_RUNTIME) {
            signTemplate.hardenedRuntime = true;
            signTemplate.runtimeVersion = preserved.runtime;
        }
    }

    if (bundle.type == Bundle::Type::Single) {
        signOneMachO(signTemplate, bundle.binaryPath, options.force);
        return 0;
    }

    // Bundle: sign nested bundles deepest-first so we can capture their
    // cdhashes for the outer CodeResources, then sign this bundle's binary
    // with slot 1 (Info.plist) and slot 3 (CodeResources) populated.
    std::vector<NestedCdHash> nestedHashes;
    auto nestedRels = findNestedBundles(bundle);
    for (const auto& rel : nestedRels) {
        std::string nestedPath = bundle.contentsRoot + "/" + rel;
        // Recurse with force=true (we're orchestrating a fresh sign of the
        // whole bundle) and identifier cleared so the nested bundle uses its
        // own CFBundleIdentifier rather than inheriting the outer's.
        CodesignOptions nestedOpts = options;
        nestedOpts.identifier.clear();
        nestedOpts.force = true;
        Commands::codesign(nestedOpts, nestedPath);

        Bundle nestedBundle = detectBundle(nestedPath);
        nestedHashes.push_back(
                NestedCdHash{rel, computeCDHashes(nestedBundle.binaryPath)});
    }

    std::string codeResources = generateCodeResources(bundle, nestedHashes);
    std::string sigDir = bundle.contentsRoot + "/_CodeSignature";
    if (mkdir(sigDir.c_str(), 0755) != 0 && errno != EEXIST) {
        throw std::runtime_error{
                std::string{"mkdir '" + sigDir + "': "} + strerror(errno)};
    }
    std::string crPath = sigDir + "/CodeResources";
    writeFileBytes(crPath, codeResources);

    signTemplate.infoPlistPath = bundle.infoPlistPath;
    signTemplate.codeResourcesPath = crPath;
    signOneMachO(signTemplate, bundle.binaryPath, options.force);
    return 0;
}
};
