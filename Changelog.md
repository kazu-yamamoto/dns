# ChangeLog

## 4.1.1

- Adding encoder/decoder for CAA RR.

## 4.1.0

- Breaking change: GHC 7.x and earlier no longer supported.
  We now require support for PatternSynonyms, available since
  GHC 8.0.
- Feature: relaxed lookup-raw interface
  [#167](https://github.com/kazu-yamamoto/dns/pull/167)
- Using "53" instead of "domain".
  [#166](ttps://github.com/kazu-yamamoto/dns/pull/166)
- UDP ReceiveFrom, sendTo with SockAddr
  [#165](https://github.com/kazu-yamamoto/dns/pull/165)
- Feature: Support for RP resource record type
  [#161](https://github.com/kazu-yamamoto/dns/pull/161)
- Feature: New `splitDomain` function splits a domain name
  at the first label break, unescaping the first label to
  a raw ByteString.
- Feature: New `splitMailbox` function splits a domain name
  at the first label break, unescaping the first label to
  a raw ByteString.
  [#155](https://github.com/kazu-yamamoto/dns/pull/155)
- Bugfix: Encoding of large packets could produce invalid
  compression pointers.
  [#156](https://github.com/kazu-yamamoto/dns/pull/156)
- Bugfix: SRV record presentation form (RD_SRV show instance)
  was missing a space between the port and the target.

## 4.0.1

- Bugfix: Retry without EDNS on empty FormatErr responses. Non-EDNS resolvers
  may return a FormErr response with an empty question section. Such a response
  must be accepted as a valid signal to switch to non-EDNS queries, even though
  the response does not contain a matching question.
- Feature: New RData constructors RD_CDS and RD_CDNSKEY
- Usability: More friendly network errors, instead of reporting the error
  location as an overly verbose "addrinfo" it is now just the essential
  "tcp@address" or "udp@address".
- BCP: The EDNS UDP buffer size has been changed to the RIPE recommended
  default of 1232 bytes.  Note that this recomendation is for a default value,
  to be used when better information is not available.  Users can still
  configure larger values if their networks support larger data frames and they
  are certain there is no risk of IP fragmentation.
- CI: Linux tests now pass with GHC 8.0.2, 8.2.2, 8.4.4, 8.6.5 and 8.8.1.
  Windows tests now build and run, but pass only intermittently.  The Windows
  doctests hang most of the time, perhaps a bug or portability issue in the
  doctest code, rather than the DNS library?
- Build: Internal modules are no longer exposed outside the build, this uses
  Cabal 2.0 or later features to expose internal modules only to the test
  executables.

## 4.0.0

- Breaking change: when `Domain` name ByteStrings are
  parsed as a sequence of DNS labels, backslashed escapes
  (single-character and 3-digit decimal) are decoded to
  the corresponding character or byte. Therefore, `encode`
  is not a total function, it may raise a `DecodeError`
  when a `ResourceRecord` contains a malformed `Domain`.
- Breaking change: when wire-form DNS names are converted
  to `Domain` ByteStrings, special characters in DNS labels
  are now encoded as `\c` (single-character backslash escapes)
  and non-printing characters as `\DDD` (3-digit decimal escapes).
- Output format change: `show` for TXT RDATA now includes
  enclosing double quotes, and escapes special characters.
  This is consistent with the format of TXT records in zone
  files and, e.g., dig(1) output. The DNS string quoting
  syntax is similar to a proper subset of the Haskell string
  quoting syntax, but its decimal escapes require exactly
  three digits, while Haskell accepts 1 or more, and uses
  `'\&'` as a null. Therefore, `read @String` does not
  reliably decode the DNS text string presentation form.
- Breaking change: the DNSMessage __component__ encoding
  functions are now internal.  They're still exported from
  the new 'Nework.DNS.Encode.Internal' module, but this
  is only to make them available for the test-suite.
- Added the TYPE definition, but not yet RData, for CAA.
- Added decode, encode and show for NSEC3 RRs.
- Added base16-bytestring as a new dependency.
- Added decode, encode and show for NSEC RRs.
- New RData constructor RD\_NSEC.
- Correct presentation form of unknown RR types.
- Corrected encoding of long TXT records
- RD\_NULL now has an opaque data payload.
- Safety: Both 'decode' and 'decodeAt' must now consume exactly
  the complete input buffer or a DecodeError is returned.
  * The same applies to each complete message with 'decodeMany'
    and 'decodeManyAt'.  Any final encoded message segment at the
    end of the input buffer is still returned as the second
    element of the result pair.
- Bugfix: fixed incorrect decoding of TXT records, and corrected
  the associated test.
- Cleanup: More precise control over decoder error messages via
  'failSGet', which avoids the unhelpful Attoparsec "Failure
  reading: " error prefix.
- Cleanup: Simplified loop detection in name decompression, making
  use of a monotone strictly decreasing limit on valid "pointer"
  targets.
- Breaking change: In the "Decode" module, expose only the
  decode{,Many}{,At} functions.  The rest of the "Decode" module's
  functions are now internal, exposed only for testing.  These
  include:
  * decodeDNSHeader
  * decodeDNSFlags
  * decodeResourceRecord
  * decodeDomain
  * decodeMailbox
- Cleanup: Reworked Decode module structure:
    * Moved Decode.Internal to Decode.Parsers
    * Created a new Decode.Internal which is now exposed, and
      moved some functions there from Decode which are only
      exposed for testing, since they could not reliably be used
      except as part of decoding a full message.
- Feature: RRSIG support, we can now encode, decode and show RRSIG
  records.  This uses the new 'decodeAt' and 'decodeManyAt' API.
- New API: 'decodeAt' and 'decodeManyAt' make it possible for
  the decoder to get the current time, in order to decode some
  RR types (like RRSIG) whose full meaning is time-dependent.
- Re-export 'sendAll' and export 'encodeVC' for use with TCP.
- No longer using sendAll with UDP, UDP datagrams must not be sent
  piece-by-piece
- Removed socket I/O work-around for no longer supported GHC versions
  on Windows.
- TCP queries now also use EDNS, since the DO bit and other options
  may be relevant, even when the UDP buffer size is not.  Therefore,
  TCP now also does a non-EDNS fallback.
- The resolvEDNS field is subsumed in resolvQueryControls and
  removed.  The encodeQuestion function changes to no longer take
  an explicit "EDNSheader" argument, instead the EDNS record is
  built based on the supplied options.  Also the encodeQuestions
  function has been removed, since we're deprecating it, but the
  legacy interface can no longer be maintained.
- New API: lookupRawCtl
- New API: ODataOp, doFlag, ednsEnable, ednsSetVersion, ednsSetSize
  and ednsSetOptions make it possible for 'QueryControls' to adjust
  EDNS settings.
- New API: FlagOp, rdFlag, adFlag and cdFlag make it possible to
  override the default settings of the query-related DNS header
  flags.
- Breaking change: the decoded EDNS record no longer contains
  an error field.  Instead the header of decoded messages is
  updated hold the extended error code when valid EDNS OPT records
  (EDNS pseudo-headers) are found.  The remaining EDNS record
  fields have been renamed:
      * udpSize  -> ednsBufferSize
      * dnssecOk -> ednsDnssecOk
      * options  -> ednsOptions
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
  just yield OD\_ECSgeneric results.
- Breaking change: New OD\_ECSgeneric EDNS constructor, represents
  ClientSubnet values whose address family is not IP or that violate
  the specification.  The "family" field distinguishes the two cases.
- The ClientSubnet EDNS option is now encoded correctly even when the
  source bits match some trailing all-zero bytes.
- Breaking change: EDNS0 is renamed to EDNS.
- Breaking change: lookupRawAD, composeQuery, composeQueryAD are removed.
- New OP codes: OP\_NOTIFY and OP\_UPDATE.
  [#113](https://github.com/kazu-yamamoto/dns/pull/113)

## 3.0.4

- Drop unexpected UDP answers [#112](https://github.com/kazu-yamamoto/dns/pull/112)

## 3.0.3

- Implementing NSEC3PARAM [#109](https://github.com/kazu-yamamoto/dns/pull/109)
- Fixing an example of DNS server.
- Improving DNS decoder [#111](https://github.com/kazu-yamamoto/dns/pull/111)

## 3.0.2

- Supporting conduit 1.3 [#105](https://github.com/kazu-yamamoto/dns/pull/105)
- Supporting GHC 8.4 with semigroup hack.

## 3.0.1

- Supporting GHC 7.8 again.

## 3.0.0

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

## 2.0.13
- Testing with AppVeyor.
- Detecting a default DNS server on Windows.
- Fixing sendAll on Windows [#72](https://github.com/kazu-yamamoto/dns/pull/72)

## 2.0.12
- Fixing Windows build again

## 2.0.11
- Fixing the StateBinary.get32 parser [#57](https://github.com/kazu-yamamoto/dns/pull/57)
- Removing bytestring-builder dependency [#61](https://github.com/kazu-yamamoto/dns/pull/61)
- Fixing Windows build [#62](https://github.com/kazu-yamamoto/dns/pull/62)

## 2.0.10
- Cleaning up the code. [#47](https://github.com/kazu-yamamoto/dns/pull/47)

## 2.0.9
- Implemented TCP fallback after a truncated UDP response. [#46](https://github.com/kazu-yamamoto/dns/pull/46)

## 2.0.8
- Better handling of encoding and decoding the "root" domain ".". [#45](https://github.com/kazu-yamamoto/dns/pull/45)

## 2.0.7
- Add length checks for A and AAAA records. [#43](https://github.com/kazu-yamamoto/dns/pull/43)

## 2.0.6
- Adding Ord instance. [#41](https://github.com/kazu-yamamoto/dns/pull/41)
- Adding DNSSEC-related RRTYPEs [#40](https://github.com/kazu-yamamoto/dns/pull/40)

## 2.0.5
- Supporting DNS-SEC AD (authenticated data). [#38](https://github.com/kazu-yamamoto/dns/pull/38)
- Removing the dependency to blaze-builder.

## 2.0.4
- Renaming a variable to fix preprocessor conflicts [#37](https://github.com/kazu-yamamoto/dns/pull/37)

## 2.0.3
- Handle invalid opcodes gracefully. [#36](https://github.com/kazu-yamamoto/dns/pull/36)

## 2.0.2
- Providing a new API: decodeMany.

## 2.0.1
- Updating document.

## 2.0.0
- DNSMessage is now monomorphic
- RDATA is now monomorphic
- Removed traversal instance for DNSMessage
- EDNS0 encoding/decoding is now supported
- Removed dnsMapWithType and dnsTraverseWithType functions
- responseA and responseAAAA now take lists of IP addresses as their arguments
- DNSHeader type no longer has qdCount, anCount, nsCount, and arCount fields
