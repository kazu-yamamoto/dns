# Highly concurrent DNS library purely in Haskell

## Features

- This library supports both IPv4 and IPv6 for resolving (`A` and `AAAA`) and transport (using `getaddrinfo`).
- This library can be used for both clients and servers on Unix, Mac and Windows.

## Related packages

- [Concurrent DNS cache in Haskell](https://hackage.haskell.org/package/concurrent-dns-cache)

## Experience reports:

- [Network Protocol Programming in Haskell](http://conferences.sigcomm.org/sigcomm/2017/workshop-netpl.html)
- [RSS reader written in Haskell and Ur/Web](https://www.reddit.com/r/haskell/comments/1ha5dd/rss_reader_written_in_haskell_and_urweb/)

## Todo

- EDNS0
- DNSSEC
- Default DNS server detection on Windows (now included in the `master` branch).
