# 4.0.0

- TCP queries now also use EDNS, since the DO bit and other options
  may be relevant, even when the UDP buffer size is not.  Therefore,
  TCP now also does a non-EDNS fallback.
- The resolvEDNS field is subsumed in resolvQueryControls and
  removed.  The encodeQuestion function changes to no longer take
  an explicit "EDNSheader" argument, instead the EDNS record is
  built based on the supplied options.  Also the encodeQuestions
  function has been removed, since we're deprecating it, but the
  legacy interface can no longer be maintained.
- New API: doFlag, ednsEnable, ednsSetVersion, ednsSetSize and
  ednsSetOptions makes it possible for 'QueryControls' to adjust
  EDNS settings.
- New API: lookupRawCtl
- Breaking change: the decoded EDNS record no longer contains
  an error field.  Instead the header of decoded messages is
  updated hold the extended error code when valid EDNS OPT records
  (EDNS pseudo-headers) are found.  The remaining EDNS record
  fields have been renamed:

        udpSize  -> ednsBufferSize
        dnssecOk -> ednsDnssecOk
        options  -> ednsOptions

  The reverse process happens on output with the 12-bit header
  RCODE split across the wire-form DNS header and the OPT record.
  When EDNS is not enabled, and the RCODE > 15, it is mapped to
  FormatErr instead.
- Breaking change: The fromRCODEforHeader and toRCODEforHeader
  functions have been removed.
- Breaking change: DNSFormat and fromDNSFormat
  have been removed.
- The fromDNSMessage function now distinguishes between FormatErr
  responses without an OPT record (which signal no EDNS support),
  and FormatErr with an OPT record, which signal problems
  (malformed or unsupported version) with the OPT record received
  in the request.  For the latter the 'BadOptRecord' error is
  returned.
- Added more RCODEs, including a BadRCODE that is generated
  locally, rather than parsed from the message.  The value
  lies just above the EDNS 12-bit range, with the bottom
  12-bits matching FormatErr.
- Breaking change: The DNSMessage structure now has an
  "ednsHeader" field, initialized to "EDNSheader defaultEDNS"
  in "defaultQuery" and to "NoEDNS" in "defaultResponse".
  The former enables EDNS(0) with default options, the latter
  leaves EDNS unconfigured.
- The BadOpt RCODE is renamed to BadVers to better resemble
  the term used in RFCs.
- Added EDNS OPTIONS: NSID, DAU, DHU, N3U
- Decoding of the ClientSubnet option is now a total function,
  provided the RDATA is structurally sound.  Unexpected values
  just yield OD_ECSgeneric results.
- Breaking change: New OD_ECSgeneric EDNS constructor, represents
  ClientSubnet values whose address family is not IP or that violate
  the specification.  The "family" field distinguishes the two cases.
- The ClientSubnet EDNS option is now encoded correctly even when the
  source bits match some trailing all-zero bytes.
- Breaking change: EDNS0 is renamed to EDNS.
- Breaking change: lookupRawAD, composeQuery, composeQueryAD are removed.
- New OP codes: OP_NOTIFY and OP_UPDATE.
  [#113](https://github.com/kazu-yamamoto/dns/pull/113)

# 3.0.4

- Drop unexpected UDP answers [#112](https://github.com/kazu-yamamoto/dns/pull/112)

# 3.0.3

- Implementing NSEC3PARAM [#109](https://github.com/kazu-yamamoto/dns/pull/109)
- Fixing an example of DNS server.
- Improving DNS decoder [#111](https://github.com/kazu-yamamoto/dns/pull/111)

# 3.0.2

- Supporting conduit 1.3 [#105](https://github.com/kazu-yamamoto/dns/pull/105)
- Supporting GHC 8.4 with semigroup hack.

# 3.0.1

- Supporting GHC 7.8 again.

# 3.0.0

- The version introduces some breaking changes internally. But upper layer APIs in the `Lookup` module remain the same.
- Breaking change: `Network.DNS.Types` is redesigned. `ResourceRecord` is not a sum type anymore. It holds only normal RRs. For EDNS0, a new scheme is implemented. [#63](https://github.com/kazu-yamamoto/dns/issues/63)
- Breaking change: the `Encode` and `Decode` modules use strict ByteString instead of lazy one. [#59](https://github.com/kazu-yamamoto/dns/issues/59)
- Default DNS servers are detected automatically on Windows if `RCFilePath` is used. Use vanilla `defaultResolvConf` on Windows! [#83](https://github.com/kazu-yamamoto/dns/pull/83)
- Multiple DNS servers can be used. You can choose either sequential lookup or concurrent lookup. See `resolvConcurrent`. [#81](https://github.com/kazu-yamamoto/dns/pull/81)
- EDNS0 queries are used by default. [#95](https://github.com/kazu-yamamoto/dns/pull/95)
- `lookupSOA` is defined. [#93](https://github.com/kazu-yamamoto/dns/pull/93)
- Cache mechanism is provided. See `resolvCache`.
- Some constructors such as ANY are added in the `Types` module.
- Some bug fixes and code clean-up.

# 2.0.13
- Testing with AppVeyor.
- Detecting a default DNS server on Windows.
- Fixing sendAll on Windows [#72](https://github.com/kazu-yamamoto/dns/pull/72)

# 2.0.12
- Fixing Windows build again

# 2.0.11
- Fixing the StateBinary.get32 parser [#57](https://github.com/kazu-yamamoto/dns/pull/57)
- Removing bytestring-builder dependency [#61](https://github.com/kazu-yamamoto/dns/pull/61)
- Fixing Windows build [#62](https://github.com/kazu-yamamoto/dns/pull/62)

# 2.0.10
- Cleaning up the code. [#47](https://github.com/kazu-yamamoto/dns/pull/47)

# 2.0.9
- Implemented TCP fallback after a truncated UDP response. [#46](https://github.com/kazu-yamamoto/dns/pull/46)

# 2.0.8
- Better handling of encoding and decoding the "root" domain ".". [#45](https://github.com/kazu-yamamoto/dns/pull/45)

# 2.0.7
- Add length checks for A and AAAA records. [#43](https://github.com/kazu-yamamoto/dns/pull/43)

# 2.0.6
- Adding Ord instance. [#41](https://github.com/kazu-yamamoto/dns/pull/41)
- Adding DNSSEC-related RRTYPEs [#40](https://github.com/kazu-yamamoto/dns/pull/40)

# 2.0.5
- Supporting DNS-SEC AD (authenticated data). [#38](https://github.com/kazu-yamamoto/dns/pull/38)
- Removing the dependency to blaze-builder.

# 2.0.4
- Renaming a variable to fix preprocessor conflicts [#37](https://github.com/kazu-yamamoto/dns/pull/37)

# 2.0.3
- Handle invalid opcodes gracefully. [#36](https://github.com/kazu-yamamoto/dns/pull/36)

# 2.0.2
- Providing a new API: decodeMany.

# 2.0.1
- Updating document.

# 2.0.0
- DNSMessage is now monomorphic
- RDATA is now monomorphic
- Removed traversal instance for DNSMessage
- EDNS0 encoding/decoding is now supported
- Removed dnsMapWithType and dnsTraverseWithType functions
- responseA and responseAAAA now take lists of IP addresses as their arguments
- DNSHeader type no longer has qdCount, anCount, nsCount, and arCount fields
