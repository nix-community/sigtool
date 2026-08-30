#include "resources.h"

#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>

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
// `walkRoot`. Skips symlinks, directories, _CodeSignature/, and the immediate
// children of nested-bundle directories (those are signed separately and
// recorded as cdhash entries).
void walk(const std::string& walkRoot, const std::string& subdir,
          std::vector<std::string>& out) {
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
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (rel == "_CodeSignature") continue;
            // Nested-bundle dirs are skipped here; their immediate children
            // are returned by findNestedBundles() and emitted as cdhash
            // entries instead of file hashes.
            if (subdir.empty() && isNestedBundleDirEntry(rel)) continue;
            walk(walkRoot, rel, out);
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
    if (rel.size() > 18
        && rel.compare(rel.size() - 18, 18, "/locversion.plist") == 0) {
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
    std::string binaryRel;
    if (bundle.binaryPath.size() > bundle.contentsRoot.size() + 1
        && bundle.binaryPath.compare(0, bundle.contentsRoot.size(), bundle.contentsRoot) == 0
        && bundle.binaryPath[bundle.contentsRoot.size()] == '/') {
        binaryRel = bundle.binaryPath.substr(bundle.contentsRoot.size() + 1);
    }

    bool omitRootInfoPlist = (bundle.type == Bundle::Type::App);

    std::vector<std::string> files;
    walk(bundle.contentsRoot, "", files);

    // Filter and sort.
    std::vector<std::string> kept;
    kept.reserve(files.size());
    for (const auto& rel : files) {
        if (isOmitted(rel, binaryRel, omitRootInfoPlist)) continue;
        kept.push_back(rel);
    }
    std::sort(kept.begin(), kept.end());

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
    size_t ki = 0, ni = 0;
    while (ki < kept.size() || ni < nestedSorted.size()) {
        bool takeNested;
        if (ki >= kept.size()) takeNested = true;
        else if (ni >= nestedSorted.size()) takeNested = false;
        else takeNested = (nestedSorted[ni].relativePath < kept[ki]);

        if (takeNested) {
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
