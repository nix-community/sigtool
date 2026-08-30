#ifndef SIGTOOL_RESOURCES_H
#define SIGTOOL_RESOURCES_H

#include <string>

#include "bundle.h"

namespace SigTool {

// Generate a CodeResources XML plist for the given bundle. Walks `contentsRoot`
// recursively, hashes regular files (skipping the executable, _CodeSignature/,
// Info.plist at the bundle's contentsRoot, .DS_Store, etc.), and emits the
// `files`, `files2`, `rules`, and `rules2` sections matching Apple's defaults.
//
// Throws std::runtime_error if the bundle is Single (not a bundle), if the
// contentsRoot is missing, or if a nested bundle is found at a known nested
// location (Frameworks/, PlugIns/, ...) since this implementation does not
// recurse into nested bundles.
std::string generateCodeResources(const Bundle& bundle);

};

#endif // SIGTOOL_RESOURCES_H
