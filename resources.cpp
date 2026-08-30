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
// `walkRoot`. Skips symlinks, directories, _CodeSignature/, and per-relative
// path filters provided by the caller.
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
            if (isNestedBundleDirEntry(rel)) {
                throw std::runtime_error{
                        "nested bundle directory '" + rel + "' under "
                        + walkRoot + " is not supported. Sign nested bundles "
                                     "first, then sign the outer bundle."};
            }
            walk(walkRoot, rel, out);
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            out.push_back(rel);
        }
    }
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

std::string generateCodeResources(const Bundle& bundle) {
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

    std::string out;
    out += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
           "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
           "<plist version=\"1.0\">\n"
           "<dict>\n";

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

    out += "\t<key>files2</key>\n\t<dict>\n";
    for (const auto& rel : kept) {
        std::string contents = slurpFile(bundle.contentsRoot + "/" + rel);
        SHA256Hash h{contents.data(), contents.size()};
        out += "\t\t<key>";
        appendXmlEscaped(out, rel);
        out += "</key>\n\t\t<dict>\n\t\t\t<key>hash2</key>\n\t\t\t<data>\n\t\t\t";
        out += base64Encode(h.bytes, sizeof(h.bytes));
        out += "\n\t\t\t</data>\n\t\t</dict>\n";
    }
    out += "\t</dict>\n";

    out += kRulesSection;
    out += "</dict>\n</plist>\n";

    return out;
}

};
