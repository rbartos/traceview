# Traceview

A dependency-free, browser-based PCAP and PCAPNG viewer. It decodes Ethernet, IPv4,
IPv6, ICMP, UDP, TCP, ARP, DNS, and HTTP packet details locally in your browser.

The goal of this project is to provide a simple, fast, and privacy-respecting way to
inspect packet captures without requiring any server-side processing or third-party
services. It is intended for use as a teaching tool in an introductory networking 
course.

## Run

Serve this directory with any static HTTP server, then open its URL. For
example, with Python installed:

```sh
python3 -m http.server 8000
```

Open <http://localhost:8000/> and choose a `.pcap` or `.pcapng` file, drag a capture onto
the page, or select a bundled sample. To host the app under a website subfolder,
deploy the entire directory (including `samples/`) at that subfolder and open its
directory URL, such as `https://example.com/tools/traceviewer/`. The app's assets
use relative URLs, and sample requests resolve relative to `app.mjs`, so no
root-level URL mapping is needed. Sample captures are stored in `samples/` and
listed in `samples/index.json`; add each new `.pcap` or `.pcapng` filename to that
list to make it available in the sample menu. Sample loading requires serving the
directory over HTTP; the file picker also works with local captures.
To open a particular bundled sample directly, add its filename as the `cap` query
parameter, for example `https://example.com/tools/traceviewer/?cap=cs725-f26-a3.pcapng`.
The filename must be listed in `samples/index.json`.

Use the display filter or protocol chips to narrow packets. Select a row to
inspect decoded protocol fields and the raw packet bytes. Capture contents are
processed entirely on-device and are not uploaded.

ICMP and ICMPv6 echo, unreachable, time-exceeded, redirect, and related common
messages include decoded type-specific fields. DNS queries and responses over UDP
or TCP include decoded headers, questions, and common resource records (A, AAAA,
CNAME, NS, PTR, MX, TXT, SRV, and SOA).
