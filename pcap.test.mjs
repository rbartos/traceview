import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseCapture, parsePcapng } from "./pcap.mjs";

const sample = await readFile(new URL("./samples/cs725-f26-a3.pcapng", import.meta.url));
const sampleFiles = JSON.parse(await readFile(new URL("./samples/index.json", import.meta.url), "utf8"));

function makeBlock(type, body, littleEndian = true) {
  const length = body.length + 12;
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, type, littleEndian);
  view.setUint32(4, length, littleEndian);
  bytes.set(body, 8);
  view.setUint32(length - 4, length, littleEndian);
  return bytes;
}

function makeCapture(frames, { littleEndian = true, linkType = 1 } = {}) {
  const sectionBody = new Uint8Array(16);
  const sectionView = new DataView(sectionBody.buffer);
  sectionView.setUint32(0, 0x1a2b3c4d, littleEndian);
  sectionView.setUint16(4, 1, littleEndian);
  sectionView.setUint16(6, 0, littleEndian);
  sectionView.setBigInt64(8, -1n, littleEndian);
  const section = makeBlock(0x0a0d0d0a, sectionBody, littleEndian);

  const interfaceBody = new Uint8Array(8);
  const interfaceView = new DataView(interfaceBody.buffer);
  interfaceView.setUint16(0, linkType, littleEndian);
  const interfaceBlock = makeBlock(1, interfaceBody, littleEndian);

  const packetBlocks = frames.map((frame, index) => {
    const body = new Uint8Array(20 + ((frame.length + 3) & ~3));
    const view = new DataView(body.buffer);
    view.setUint32(0, 0, littleEndian);
    view.setUint32(4, 0, littleEndian);
    view.setUint32(8, index + 1, littleEndian);
    view.setUint32(12, frame.length, littleEndian);
    view.setUint32(16, frame.length, littleEndian);
    body.set(frame, 20);
    return makeBlock(6, body, littleEndian);
  });
  const all = [section, interfaceBlock, ...packetBlocks];
  const output = new Uint8Array(all.reduce((sum, block) => sum + block.length, 0));
  let offset = 0;
  for (const block of all) {
    output.set(block, offset);
    offset += block.length;
  }
  return output;
}

function makeClassicCapture(frames, { littleEndian = true, nanoseconds = false } = {}) {
  const bytes = new Uint8Array(24 + frames.reduce((sum, frame) => sum + 16 + frame.length, 0));
  const view = new DataView(bytes.buffer);
  bytes.set(nanoseconds
    ? (littleEndian ? [0x4d, 0x3c, 0xb2, 0xa1] : [0xa1, 0xb2, 0x3c, 0x4d])
    : (littleEndian ? [0xd4, 0xc3, 0xb2, 0xa1] : [0xa1, 0xb2, 0xc3, 0xd4]));
  view.setUint16(4, 2, littleEndian);
  view.setUint16(6, 4, littleEndian);
  view.setUint32(16, 65535, littleEndian);
  view.setUint32(20, 1, littleEndian);
  let offset = 24;
  for (const [index, frame] of frames.entries()) {
    view.setUint32(offset, 100 + index, littleEndian);
    view.setUint32(offset + 4, nanoseconds ? 123_456_789 : 123_456, littleEndian);
    view.setUint32(offset + 8, frame.length, littleEndian);
    view.setUint32(offset + 12, frame.length, littleEndian);
    bytes.set(frame, offset + 16);
    offset += 16 + frame.length;
  }
  return bytes;
}

function ethernet(type, payload) {
  const frame = new Uint8Array(14 + payload.length);
  frame.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  new DataView(frame.buffer).setUint16(12, type);
  frame.set(payload, 14);
  return frame;
}

function ipv4(protocol, payload) {
  const packet = new Uint8Array(20 + payload.length);
  packet[0] = 0x45;
  new DataView(packet.buffer).setUint16(2, packet.length);
  packet[8] = 64;
  packet[9] = protocol;
  packet.set([192, 0, 2, 1, 198, 51, 100, 2], 12);
  packet.set(payload, 20);
  return ethernet(0x0800, packet);
}

function ipv6(nextHeader, payload) {
  const packet = new Uint8Array(40 + payload.length);
  packet[0] = 0x60;
  new DataView(packet.buffer).setUint16(4, payload.length);
  packet[6] = nextHeader;
  packet[7] = 64;
  packet.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8);
  packet.set([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 24);
  packet.set(payload, 40);
  return ethernet(0x86dd, packet);
}

function icmp(type, code, rest = [0, 1, 0, 2]) {
  return new Uint8Array([type, code, 0x12, 0x34, ...rest]);
}

function udp(sourcePort, destinationPort, payload) {
  const segment = new Uint8Array(8 + payload.length);
  const view = new DataView(segment.buffer);
  view.setUint16(0, sourcePort);
  view.setUint16(2, destinationPort);
  view.setUint16(4, segment.length);
  segment.set(payload, 8);
  return segment;
}

function dnsQuery() {
  return new Uint8Array([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
  ]);
}

function dnsResponse() {
  return new Uint8Array([
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
    0xc0, 0x00, 0x02, 0x2a,
  ]);
}

function tcp(sourcePort, destinationPort, payload) {
  const segment = new Uint8Array(20 + payload.length);
  const view = new DataView(segment.buffer);
  view.setUint16(0, sourcePort);
  view.setUint16(2, destinationPort);
  view.setUint32(4, 1);
  segment[12] = 0x50;
  segment[13] = 0x18;
  segment.set(payload, 20);
  return segment;
}

test("decodes the supplied capture including IPv6 and HTTP", () => {
  const parsed = parsePcapng(sample);
  assert.equal(parsed.packets.length, 10);
  assert.equal(parsed.packets[0].protocol, "TCP");
  assert.equal(parsed.packets[0].layers[1].name, "Internet Protocol Version 6");
  assert.equal(parsed.packets[3].protocol, "HTTP");
  assert.match(parsed.packets[3].info, /GET \//);
  assert.equal(parsed.packets[5].protocol, "HTTP");
  assert.match(parsed.packets[5].info, /302 Found/);
});

test("sample manifest lists capture files that can be decoded", async () => {
  assert.ok(Array.isArray(sampleFiles));
  assert.ok(sampleFiles.length > 0);
  for (const file of sampleFiles) {
    const bytes = await readFile(new URL(`./samples/${file}`, import.meta.url));
    assert.ok(parseCapture(bytes).packets.length > 0, `${file} should contain supported packets`);
  }
});

test("decodes Ethernet, IPv4 and UDP fields", () => {
  const udp = new Uint8Array(8);
  const view = new DataView(udp.buffer);
  view.setUint16(0, 53000);
  view.setUint16(2, 53);
  view.setUint16(4, 8);
  const packet = parsePcapng(makeCapture([ipv4(17, udp)])).packets[0];
  assert.equal(packet.protocol, "UDP");
  assert.equal(packet.source, "192.0.2.1");
  assert.equal(packet.destination, "198.51.100.2");
  assert.equal(packet.layers[0].name, "Ethernet II");
  assert.equal(packet.layers[2].name, "UDP (53000 → 53)");
});

test("decodes common ICMPv4 echo and destination-unreachable messages", () => {
  const echo = parsePcapng(makeCapture([ipv4(1, icmp(8, 0))])).packets[0];
  assert.equal(echo.protocol, "ICMP");
  assert.equal(echo.info, "Echo Request (id=1, seq=2)");
  assert.ok(echo.filterTokens.includes("icmp"));
  assert.equal(echo.layers[2].name, "ICMP");
  assert.match(JSON.stringify(echo.layers[2].fields), /Identifier.*1/);

  const unreachable = parsePcapng(makeCapture([ipv4(1, icmp(3, 3))])).packets[0];
  assert.equal(unreachable.protocol, "ICMP");
  assert.equal(unreachable.info, "Destination Unreachable (Port unreachable)");
  assert.match(JSON.stringify(unreachable.layers[2].fields), /Port unreachable/);

  const fragmentation = parsePcapng(makeCapture([ipv4(1, icmp(3, 4, [0, 0, 5, 220]))])).packets[0];
  assert.equal(fragmentation.info, "Destination Unreachable (MTU 1500)");
  assert.match(JSON.stringify(fragmentation.layers[2].fields), /1500 bytes/);
});

test("decodes common ICMPv6 echo, packet-too-big, and neighbor messages", () => {
  const echo = parsePcapng(makeCapture([ipv6(58, icmp(128, 0))])).packets[0];
  assert.equal(echo.protocol, "ICMPv6");
  assert.equal(echo.info, "Echo Request (id=1, seq=2)");
  assert.ok(echo.filterTokens.includes("icmpv6"));
  assert.ok(echo.filterTokens.includes("icmp"));
  assert.equal(echo.layers[2].name, "ICMPv6");

  const tooBig = parsePcapng(makeCapture([ipv6(58, icmp(2, 0, [0, 0, 5, 220]))])).packets[0];
  assert.equal(tooBig.info, "Packet Too Big (MTU 1500)");
  const jumboTooBig = parsePcapng(makeCapture([ipv6(58, icmp(2, 0, [0, 1, 0, 0]))])).packets[0];
  assert.equal(jumboTooBig.info, "Packet Too Big (MTU 65536)");

  const target = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
  const neighbor = parsePcapng(makeCapture([ipv6(58, icmp(135, 0, [0, 0, 0, 0, ...target]))])).packets[0];
  assert.equal(neighbor.protocol, "ICMPv6");
  assert.match(neighbor.info, /Neighbor Solicitation/);
  assert.match(JSON.stringify(neighbor.layers[2].fields), /2001:db8::9/);
});

test("decodes DNS queries and compressed A-record responses over UDP", () => {
  const query = parsePcapng(makeCapture([ipv4(17, udp(53000, 53, dnsQuery()))])).packets[0];
  assert.equal(query.protocol, "DNS");
  assert.match(query.info, /Standard query 0x1234 A example\.com/);
  assert.equal(query.filterTokens.includes("dns"), true);
  assert.equal(query.layers[3].name, "Domain Name System");
  assert.match(JSON.stringify(query.layers[3].fields), /example\.com/);

  const response = parsePcapng(makeCapture([ipv4(17, udp(53, 53000, dnsResponse()))])).packets[0];
  assert.equal(response.protocol, "DNS");
  assert.match(response.info, /Standard query response 0x1234 A example\.com A 192\.0\.2\.42/);
  assert.match(JSON.stringify(response.layers[3].fields), /Time to live.*60 seconds/);
});

test("decodes length-prefixed DNS queries over TCP", () => {
  const query = dnsQuery();
  const framedQuery = new Uint8Array(query.length + 2);
  new DataView(framedQuery.buffer).setUint16(0, query.length);
  framedQuery.set(query, 2);
  const packet = parsePcapng(makeCapture([ipv4(6, tcp(53000, 53, framedQuery))])).packets[0];
  assert.equal(packet.protocol, "DNS");
  assert.match(packet.info, /Standard query 0x1234 A example\.com/);
  assert.equal(packet.layers[3].name, "Domain Name System");
});

test("decodes ARP requests", () => {
  const arp = new Uint8Array(28);
  const view = new DataView(arp.buffer);
  view.setUint16(0, 1);
  view.setUint16(2, 0x0800);
  arp[4] = 6;
  arp[5] = 4;
  view.setUint16(6, 1);
  arp.set([0, 1, 2, 3, 4, 5, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2], 8);
  const packet = parsePcapng(makeCapture([ethernet(0x0806, arp)])).packets[0];
  assert.equal(packet.protocol, "ARP");
  assert.equal(packet.source, "192.0.2.1");
  assert.match(packet.info, /Request: 192\.0\.2\.1 → 192\.0\.2\.2/);
  assert.equal(packet.layers[0].name, "Ethernet II");
  assert.equal(packet.layers[1].name, "Address Resolution Protocol");
});

test("reads big-endian PCAPNG sections and handles non-Ethernet link types", () => {
  const frame = new Uint8Array([1, 2, 3, 4]);
  const packet = parsePcapng(makeCapture([frame], { littleEndian: false, linkType: 147 })).packets[0];
  assert.equal(packet.protocol, "Unknown");
  assert.equal(packet.info, "Unsupported link type 147");
  assert.equal(packet.capturedLength, 4);
});

test("loads little-endian microsecond and big-endian nanosecond PCAP captures", () => {
  const frame = ipv4(17, udp(53000, 53, new Uint8Array()));
  const microsecondCapture = parseCapture(makeClassicCapture([frame]));
  assert.equal(microsecondCapture.interfaceCount, 1);
  assert.equal(microsecondCapture.packets[0].protocol, "UDP");
  assert.equal(microsecondCapture.packets[0].time, 100.123456);
  assert.equal(microsecondCapture.packets[0].relativeTime, 0);

  const nanosecondCapture = parseCapture(makeClassicCapture([frame], { littleEndian: false, nanoseconds: true }));
  assert.equal(nanosecondCapture.packets[0].protocol, "UDP");
  assert.equal(nanosecondCapture.packets[0].time, 100.123456789);
});

test("rejects truncated classic PCAP records and invalid timestamps", () => {
  const capture = makeClassicCapture([new Uint8Array([1, 2, 3, 4])]);
  assert.throws(() => parseCapture(capture.subarray(0, 42)), /truncated packet data/);
  new DataView(capture.buffer).setUint32(28, 1_000_000, true);
  assert.throws(() => parseCapture(capture), /invalid packet timestamp/);
});

test("rejects invalid and truncated captures with a useful error", () => {
  assert.throws(() => parsePcapng(new Uint8Array()), /empty or is not a valid PCAPNG/);
  assert.throws(() => parsePcapng(sample.subarray(0, sample.length - 2)), /truncated PCAPNG block/);
});
