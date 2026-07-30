# sigtool

`sigtool` is minimal multicall binary providing helpers for working
with embedded signatures in Mach-O files. Currently only supports
embedded ad-hoc signatures for universal and thin 64-bit Mach-O files.

A `codesign` interface is also provided, and is intended to be a
drop-in replacement for upstream `codesign`.

## Signing a binary or library

This tool can generate and inject ad-hoc signatures, but uses
`codesign_allocate` to make space for the signature. `codesign_allocate` is
available in Apple's open source `cctools` project.

## Usage

### sigtool

```
sigtool
Usage: sigtool [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit
  -f,--file TEXT REQUIRED     Mach-O target file
  -i,--identifier TEXT        File identifier
  -e,--entitlements TEXT      Entitlements plist
  --generate-entitlement-der  Also embed DER-encoded entitlements

Subcommands:
  check-requires-signature    Determine if this is a macho file that must be signed
  size                        Determine size of embedded signature
  generate                    Generate an embedded signature and emit on stdout
  inject                      Generate and inject embedded signature
  show-arch                   Show architecture
```

### codesign

```
codesign
Usage: codesign [OPTIONS] [files...]

Positionals:
  files TEXT ...              Files to sign

Options:
  -h,--help                   Print this help message and exit
  -s TEXT REQUIRED            Code signing identity
  -i,--identifier TEXT        File identifier
  -f,--force                  Replace any existing signatures
  --entitlements TEXT         Entitlements plist
  --generate-entitlement-der  Also embed DER-encoded entitlements
  --timestamp[=none]          Accepted for compatibility; only =none is supported
```

`--timestamp=none` is accepted as a no-op so build tools that pass it can call
this `codesign` unmodified. Real TSA timestamping is not supported because
ad-hoc signatures contain no CMS signature for a timestamp authority to
countersign.

## Example signature

At a high level the embedded ad-hoc signature consists of three blobs in a superblob:

  1. A CodeDirectory, which consists of
     - metadata: page size, hash type and size, signature type, etc.
     - `codeLimit` defining the byte range of the signed prefix. This is set to
       the data offset of the `LC_CODE_SIGNATURE` load command.
     - a list of hashes of the pages of file up to `codeLimit`
     - a hash of the following requirements list (the second `specialHash`)
  2. A list of requirements containing 0 items
  3. A signature blob of 0 bytes

An example generated signature follows:

```
Container: 
    pointer = 0
    magic = (enum) CSMAGIC_EMBEDDED_SIGNATURE 4208856256
    length = 668
    count = 3
    index = ListContainer: 
        Container: 
            type = (enum) CSSLOT_CODEDIRECTORY 0
            offset = 36
            blob = Container: 
                cs_magic = (enum) CSMAGIC_CODEDIRECTORY 4208856066
                length = 612
            parsed = Container: 
                start = 36
                magic = (enum) CSMAGIC_CODEDIRECTORY 4208856066
                length = 612
                version = 0x00020400
                flags = Container: 
                    CS_ADHOC = True
                hashOffset = 164
                identOffset = 88
                nSpecialSlots = 2
                nCodeSlots = 14
                codeLimit = 55632
                hashSize = 32
                hashType = (enum) CS_HASHTYPE_SHA256 2
                platform = 0
                pageSize = 0x1000
                spare2 = 0
                specialHashes = ListContainer: 
                    unhexlify('987920904eab650e75788c054aa0b0524e6a80bfc71aa32df8d237a61743f986')
                    unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
                codeHashes = ListContainer: 
                    unhexlify('c7a50cbe13b795377b183e4ed604962ff7ffefd4d4f95484b5527f49d8359fef')
                    unhexlify('ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7')
                    unhexlify('ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7')
                    unhexlify('ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7')
                    unhexlify('f879ab6e20f587ed187e93378fc3f25220655d7cee92842b778ec80d6874be4e')
                    unhexlify('33e9b066051a30b33d1d6ee649df1b7d07f240fb3789269663a8117d165f5022')
                    unhexlify('020768e17db0b2489350cc37535342245d20186c211ac1e8f4622a8ad75e0a36')
                    unhexlify('d3667173d43e90c4d426735d74619055c2c0107ad06e6de885abe1824cd7a4fa')
                    unhexlify('22b02fd680f0aad8947a7a7092d1b56d442b8b73935a8c2eb70f71249687f67a')
                    unhexlify('ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7')
                    unhexlify('ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7')
                    unhexlify('ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7')
                    unhexlify('42b9a1e666211b86f482e0a6a97fd22bc3ee204441ba7f210cffdd5194a1c9fa')
                    unhexlify('9ab2636686fc30efea6a0f3fb8e5c899b1544d49c6b52146c1b6304a85733467')
                identifier = u'hello-there' (total 11)
                scatterOffset = 0
                teamOffset = 0
                spare3 = 0
                codeLimit64 = 0
                execSegBase = 0
                execSegLimit = 32768
                execSegFlags = Container: 
                    CS_EXECSEG_MAIN_BINARY = True
        Container: 
            type = (enum) CSSLOT_REQUIREMENTS 2
            offset = 648
            blob = Container: 
                cs_magic = (enum) CSMAGIC_REQUIREMENTS 4208856065
                length = 12
            parsed = Container: 
                start = 648
                cs_magic = (enum) CSMAGIC_REQUIREMENTS 4208856065
                length = 12
                count = 0
                raw = unhexlify('fade0c010000000c00000000')
                items = ListContainer: 
        Container: 
            type = (enum) CSSLOT_SIGNATURESLOT 65536
            offset = 660
            blob = Container: 
                cs_magic = (enum) CSMAGIC_BLOBWRAPPER 4208855809
                length = 8
            parsed = Container: 
                cs_magic = (enum) CSMAGIC_BLOBWRAPPER 4208855809
                length = 8
```
