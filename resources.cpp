#include "resources.h"

#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

#include "hash.h"

namespace SigTool {

namespace {

bool isFile(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string slurpFile(const std::string& path) {
    std::ifstream in(path, std::ifstream::binary);
    if (!in.is_open()) {
        throw std::runtime_error{"opening '" + path + "': read failed"};
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool isNestedBundleDirEntry(const std::string& relDir) {
    static const char* nestedRoots[] = {
            "Frameworks", "SharedFrameworks", "PlugIns", "Plug-ins",
            "XPCServices", "Helpers"};
    for (auto* r : nestedRoots) {
        if (relDir == r) return true;
    }
    return false;
}

// Walk `dir` recursively, emitting every regular file's path RELATIVE to
// `walkRoot` into `out`, and every symlink (path + readlink target) into
// `links`. Skips directories, _CodeSignature/, and the immediate children of
// nested-bundle directories (those are signed separately and recorded as
// cdhash entries).
struct SymlinkEntry {
    std::string relativePath;
    std::string target;
};

std::string readLinkTarget(const std::string& path) {
    std::vector<char> buf(1024);
    while (true) {
        ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size());
        if (n < 0) {
            throw std::runtime_error{"readlink '" + path + "': " + strerror(errno)};
        }
        if (static_cast<size_t>(n) < buf.size()) {
            return std::string{buf.data(), static_cast<size_t>(n)};
        }
        buf.resize(buf.size() * 2);
    }
}

void walk(const std::string& walkRoot, const std::string& subdir,
          std::vector<std::string>& out, std::vector<SymlinkEntry>& links) {
    std::string fullDir = subdir.empty() ? walkRoot : (walkRoot + "/" + subdir);
    DIR* d = opendir(fullDir.c_str());
    if (!d) return;
    std::vector<std::string> entries;
    while (auto* ent = readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        entries.push_back(n);
    }
    closedir(d);
    std::sort(entries.begin(), entries.end());

    for (const auto& n : entries) {
        std::string rel = subdir.empty() ? n : (subdir + "/" + n);
        std::string full = walkRoot + "/" + rel;
        struct stat st{};
        if (lstat(full.c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            links.push_back(SymlinkEntry{rel, readLinkTarget(full)});
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (rel == "_CodeSignature") continue;
            // Nested-bundle dirs are skipped here; their immediate children
            // are returned by findNestedBundles() and emitted as cdhash
            // entries instead of file hashes.
            if (subdir.empty() && isNestedBundleDirEntry(rel)) continue;
            walk(walkRoot, rel, out, links);
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            out.push_back(rel);
        }
    }
}

bool looksLikeBundleSuffix(const std::string& name) {
    static const char* suffixes[] = {".framework", ".app", ".xpc", ".bundle"};
    for (auto* s : suffixes) {
        size_t sl = std::string{s}.size();
        if (name.size() > sl
            && name.compare(name.size() - sl, sl, s) == 0) return true;
    }
    return false;
}

bool isOmitted(const std::string& rel, const std::string& binaryRel,
               bool omitRootInfoPlist) {
    if (rel == binaryRel) return true;
    // Anywhere
    if (rel == ".DS_Store") return true;
    auto slash = rel.find_last_of('/');
    if (slash != std::string::npos && rel.substr(slash + 1) == ".DS_Store") return true;
    // Root-only files for app bundles
    if (omitRootInfoPlist) {
        if (rel == "Info.plist") return true;
        if (rel == "PkgInfo") return true;
    }
    // locversion.plist inside .lproj is omitted by Apple
    static const std::string locversion = "/locversion.plist";
    if (rel.size() > locversion.size()
        && rel.compare(rel.size() - locversion.size(), locversion.size(),
                       locversion) == 0) {
        // confirm a .lproj segment precedes it
        if (rel.find(".lproj/") != std::string::npos) return true;
    }
    return false;
}

void appendXmlEscaped(std::string& out, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            default: out += c;
        }
    }
}

// rules / rules2 sections, baked in to match Apple's defaults verbatim.
const char* kRulesSection =
        "\t<key>rules</key>\n"
        "\t<dict>\n"
        "\t\t<key>^Resources/</key>\n"
        "\t\t<true/>\n"
        "\t\t<key>^Resources/.*\\.lproj/</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>optional</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>1000</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^Resources/.*\\.lproj/locversion.plist$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>omit</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>1100</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^Resources/Base\\.lproj/</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>1010</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^version.plist$</key>\n"
        "\t\t<true/>\n"
        "\t</dict>\n"
        "\t<key>rules2</key>\n"
        "\t<dict>\n"
        "\t\t<key>.*\\.dSYM($|/)</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>11</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^(.*/)?\\.DS_Store$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>omit</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>2000</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>nested</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>10</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^.*</key>\n"
        "\t\t<true/>\n"
        "\t\t<key>^Info\\.plist$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>omit</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>20</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^PkgInfo$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>omit</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>20</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^Resources/</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>20</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^Resources/.*\\.lproj/</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>optional</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>1000</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^Resources/.*\\.lproj/locversion.plist$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>omit</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>1100</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^Resources/Base\\.lproj/</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>1010</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^[^/]+$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>nested</key>\n"
        "\t\t\t<true/>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>10</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^embedded\\.provisionprofile$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>20</real>\n"
        "\t\t</dict>\n"
        "\t\t<key>^version\\.plist$</key>\n"
        "\t\t<dict>\n"
        "\t\t\t<key>weight</key>\n"
        "\t\t\t<real>20</real>\n"
        "\t\t</dict>\n"
        "\t</dict>\n";

bool isMachOFile(const std::string& path) {
    std::ifstream in(path, std::ifstream::binary);
    if (!in.is_open()) return false;
    unsigned char b[4];
    in.read(reinterpret_cast<char*>(b), 4);
    if (in.gcount() != 4) return false;
    uint32_t magic = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16)
                     | (uint32_t(b[2]) << 8) | uint32_t(b[3]);
    return magic == 0xfeedfacf || magic == 0xcffaedfe   // MH_MAGIC_64 both orders
           || magic == 0xcafebabe || magic == 0xbebafeca; // FAT both orders
}

// The main binary's path relative to contentsRoot (empty if not below it).
std::string binaryRelativePath(const Bundle& bundle) {
    if (bundle.binaryPath.size() > bundle.contentsRoot.size() + 1
        && bundle.binaryPath.compare(0, bundle.contentsRoot.size(),
                                     bundle.contentsRoot) == 0
        && bundle.binaryPath[bundle.contentsRoot.size()] == '/') {
        return bundle.binaryPath.substr(bundle.contentsRoot.size() + 1);
    }
    return {};
}

std::vector<std::string> sortedDirEntries(const std::string& dirPath) {
    std::vector<std::string> entries;
    DIR* d = opendir(dirPath.c_str());
    if (!d) return entries;
    while (auto* ent = readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        entries.push_back(n);
    }
    closedir(d);
    std::sort(entries.begin(), entries.end());
    return entries;
}

// Collect Mach-O regular files under `subdir` (recursively; "" = the
// contentsRoot itself, non-recursive) into `out`, excluding `binaryRel`.
// Apple's rules2 mark MacOS/ (any depth) and top-level files as nested code
// (weight 10), so extra executables there must be signed and recorded as
// cdhash entries rather than sealed by hash.
void collectMachOFiles(const std::string& contentsRoot,
                       const std::string& subdir,
                       const std::string& binaryRel,
                       std::vector<std::string>& out) {
    std::string dirPath =
            subdir.empty() ? contentsRoot : (contentsRoot + "/" + subdir);
    for (const auto& n : sortedDirEntries(dirPath)) {
        std::string rel = subdir.empty() ? n : (subdir + "/" + n);
        std::string full = contentsRoot + "/" + rel;
        struct stat st{};
        if (lstat(full.c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (!subdir.empty()) collectMachOFiles(contentsRoot, rel, binaryRel, out);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        if (rel == binaryRel) continue;
        if (isMachOFile(full)) out.push_back(rel);
    }
}

} // namespace

std::vector<std::string> findNestedBundles(const Bundle& bundle) {
    std::vector<std::string> out;
    if (bundle.contentsRoot.empty()) return out;

    static const char* nestedRoots[] = {
            "Frameworks", "SharedFrameworks", "PlugIns", "Plug-ins",
            "XPCServices", "Helpers"};
    for (auto* root : nestedRoots) {
        std::string dirPath = bundle.contentsRoot + "/" + root;
        DIR* d = opendir(dirPath.c_str());
        if (!d) continue;
        std::vector<std::string> children;
        while (auto* ent = readdir(d)) {
            std::string n = ent->d_name;
            if (n == "." || n == "..") continue;
            children.push_back(n);
        }
        closedir(d);
        std::sort(children.begin(), children.end());

        for (const auto& n : children) {
            std::string full = dirPath + "/" + n;
            struct stat st{};
            if (lstat(full.c_str(), &st) != 0) continue;
            if (S_ISLNK(st.st_mode)) continue;
            // Bundle directories (recursively signed) and regular files
            // (signed as a single Mach-O) are both treated as nested entries
            // — they'll appear in CodeResources as cdhash entries.
            if (S_ISDIR(st.st_mode)) {
                if (!looksLikeBundleSuffix(n)) {
                    throw std::runtime_error{
                            "non-bundle directory '" + std::string{root} + "/"
                            + n + "' under " + bundle.contentsRoot
                            + " is not supported (expected *.framework, "
                              "*.app, *.xpc, or *.bundle)"};
                }
                out.push_back(std::string{root} + "/" + n);
            } else if (S_ISREG(st.st_mode)) {
                out.push_back(std::string{root} + "/" + n);
            }
        }
    }

    // Extra Mach-O binaries next to the main one (MacOS/, or the top level
    // for frameworks) are nested code under Apple's rules and must carry
    // their own signature. Non-Mach-O files there (scripts etc.) stay
    // sealed by hash, which Apple's verifier accepts.
    std::string binaryRel = binaryRelativePath(bundle);
    collectMachOFiles(bundle.contentsRoot, "MacOS", binaryRel, out);
    collectMachOFiles(bundle.contentsRoot, "", binaryRel, out);

    return out;
}

std::string generateCodeResources(const Bundle& bundle,
                                  const std::vector<NestedCdHash>& nested) {
    if (bundle.type == Bundle::Type::Single) {
        throw std::runtime_error{"generateCodeResources called on Single bundle"};
    }
    if (bundle.contentsRoot.empty()) {
        throw std::runtime_error{"bundle has no contentsRoot"};
    }

    // Compute the binary's path RELATIVE to contentsRoot.
    std::string binaryRel = binaryRelativePath(bundle);

    bool omitRootInfoPlist = (bundle.type == Bundle::Type::App);

    std::vector<std::string> files;
    std::vector<SymlinkEntry> links;
    walk(bundle.contentsRoot, "", files, links);

    // Filter and sort.
    std::vector<std::string> kept;
    kept.reserve(files.size());
    std::set<std::string> nestedPaths;
    for (const auto& n : nested) nestedPaths.insert(n.relativePath);
    for (const auto& rel : files) {
        if (isOmitted(rel, binaryRel, omitRootInfoPlist)) continue;
        // Files signed as nested code are recorded as cdhash entries only.
        if (nestedPaths.count(rel)) continue;
        kept.push_back(rel);
    }
    std::sort(kept.begin(), kept.end());

    // Symlinks are sealed only in files2 (Apple omits them from `files`).
    std::vector<SymlinkEntry> linksSorted;
    for (const auto& l : links) {
        if (isOmitted(l.relativePath, binaryRel, omitRootInfoPlist)) continue;
        linksSorted.push_back(l);
    }
    std::sort(linksSorted.begin(), linksSorted.end(),
              [](const SymlinkEntry& a, const SymlinkEntry& b) {
                  return a.relativePath < b.relativePath;
              });

    // Sort nested entries by relativePath for stable output.
    std::vector<NestedCdHash> nestedSorted = nested;
    std::sort(nestedSorted.begin(), nestedSorted.end(),
              [](const NestedCdHash& a, const NestedCdHash& b) {
                  return a.relativePath < b.relativePath;
              });

    std::string out;
    out += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n"
           "<dict>\n";

    // SHA-1 dict — regular files only; nested bundles are NOT listed here.
    out += "\t<key>files</key>\n\t<dict>\n";
    for (const auto& rel : kept) {
        std::string contents = slurpFile(bundle.contentsRoot + "/" + rel);
        SHA1Hash h{contents.data(), contents.size()};
        out += "\t\t<key>";
        appendXmlEscaped(out, rel);
        out += "</key>\n\t\t<data>\n\t\t";
        out += base64Encode(h.bytes, sizeof(h.bytes));
        out += "\n\t\t</data>\n";
    }
    out += "\t</dict>\n";

    // SHA-256 dict — regular files (hash2) plus nested bundles (cdhash).
    // Apple sorts entries lexicographically by key; we interleave by merge.
    out += "\t<key>files2</key>\n\t<dict>\n";
    size_t ki = 0, ni = 0, li = 0;
    while (ki < kept.size() || ni < nestedSorted.size() || li < linksSorted.size()) {
        // Pick whichever of the three sorted streams has the smallest key.
        enum { Regular, Nested, Symlink } take = Regular;
        const std::string* best = ki < kept.size() ? &kept[ki] : nullptr;
        if (ni < nestedSorted.size()
            && (!best || nestedSorted[ni].relativePath < *best)) {
            best = &nestedSorted[ni].relativePath; take = Nested;
        }
        if (li < linksSorted.size()
            && (!best || linksSorted[li].relativePath < *best)) {
            take = Symlink;
        }

        if (take == Symlink) {
            const auto& l = linksSorted[li++];
            out += "\t\t<key>";
            appendXmlEscaped(out, l.relativePath);
            out += "</key>\n\t\t<dict>\n\t\t\t<key>symlink</key>\n\t\t\t<string>";
            appendXmlEscaped(out, l.target);
            out += "</string>\n\t\t</dict>\n";
        } else if (take == Nested) {
            const auto& n = nestedSorted[ni++];
            if (n.cdhashes.empty()) {
                throw std::runtime_error{
                        "nested bundle '" + n.relativePath + "' has no cdhash"};
            }
            out += "\t\t<key>";
            appendXmlEscaped(out, n.relativePath);
            out += "</key>\n\t\t<dict>\n\t\t\t<key>cdhash</key>\n"
                   "\t\t\t<data>\n\t\t\t";
            out += base64Encode(reinterpret_cast<const char*>(n.cdhashes[0].data()),
                                n.cdhashes[0].size());
            out += "\n\t\t\t</data>\n";
            // `requirement` is authoritative for verify, and lets fat binaries
            // be validated regardless of which slice the host loads. Emit one
            // OR'd requirement covering every slice's cdhash.
            out += "\t\t\t<key>requirement</key>\n\t\t\t<string>";
            for (size_t i = 0; i < n.cdhashes.size(); i++) {
                if (i > 0) out += " or ";
                out += "cdhash H\"";
                static const char* hex = "0123456789abcdef";
                for (auto b : n.cdhashes[i]) {
                    out += hex[(b >> 4) & 0xf];
                    out += hex[b & 0xf];
                }
                out += "\"";
            }
            out += "</string>\n\t\t</dict>\n";
        } else {
            const auto& rel = kept[ki++];
            std::string contents = slurpFile(bundle.contentsRoot + "/" + rel);
            SHA256Hash h{contents.data(), contents.size()};
            out += "\t\t<key>";
            appendXmlEscaped(out, rel);
            out += "</key>\n\t\t<dict>\n\t\t\t<key>hash2</key>\n\t\t\t<data>\n\t\t\t";
            out += base64Encode(h.bytes, sizeof(h.bytes));
            out += "\n\t\t\t</data>\n\t\t</dict>\n";
        }
    }
    out += "\t</dict>\n";

    out += kRulesSection;
    out += "</dict>\n</plist>\n";

    return out;
}

};
