#ifndef SIGTOOL_DER_HPP
#define SIGTOOL_DER_HPP

#include <cstddef>
#include <string>
#include <vector>

// Encode an XML plist (as text) into Apple's DER entitlements form,
// matching the output of `codesign --generate-entitlement-der`.
std::vector<unsigned char> encodeEntitlementsDER(const std::string &plistXml);

#endif // SIGTOOL_DER_HPP
