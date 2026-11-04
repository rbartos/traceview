const BLOCK = {
  SECTION_HEADER: 0x0a0d0d0a,
  INTERFACE_DESCRIPTION: 1,
  SIMPLE_PACKET: 3,
  ENHANCED_PACKET: 6,
  PACKET: 2,
};

const PCAP_FORMATS = {
  "212,195,178,161": { littleEndian: true, timestampScale: 1e-6 },
  "161,178,195,212": { littleEndian: false, timestampScale: 1e-6 },
  "77,60,178,161": { littleEndian: true, timestampScale: 1e-9 },
  "161,178,60,77": { littleEndian: false, timestampScale: 1e-9 },
};

const protocolNames = {
  1: "ICMP",
  6: "TCP",
  17: "UDP",
  41: "IPv6",
  47: "GRE",
  58: "ICMPv6",
};

function assertRange(offset, length, limit, label) {
  if (!Number.isInteger(offset) || !Number.isInteger(length) || offset < 0 || length < 0 || offset + length > limit) {
    throw new Error(`The capture contains a truncated ${label}.`);
  }
}

function readOptions(view, start, end, littleEndian, onOption) {
  let offset = start;
  while (offset + 4 <= end) {
    const code = view.getUint16(offset, littleEndian);
    const length = view.getUint16(offset + 2, littleEndian);
    offset += 4;
    if (code === 0) break;
    assertRange(offset, length, end, "option");
    onOption(code, offset, length);
    offset += (length + 3) & ~3;
  }
}

function formatMac(bytes, offset) {
  return Array.from(bytes.subarray(offset, offset + 6), byte => byte.toString(16).padStart(2, "0")).join(":");
}

function formatIPv4(bytes, offset) {
  return Array.from(bytes.subarray(offset, offset + 4)).join(".");
}

function formatIPv6(bytes, offset) {
  const words = [];
  for (let i = 0; i < 8; i++) words.push((bytes[offset + i * 2] << 8) | bytes[offset + i * 2 + 1]);
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) { i++; continue; }
    let end = i;
    while (end < 8 && words[end] === 0) end++;
    if (end - i > bestLength) { bestStart = i; bestLength = end - i; }
    i = end;
  }
  if (bestStart < 0) return words.map(word => word.toString(16)).join(":");
  const before = words.slice(0, bestStart).map(word => word.toString(16)).join(":");
  const after = words.slice(bestStart + bestLength).map(word => word.toString(16)).join(":");
  return `${before}::${after}`;
}

function field(name, value, children = []) {
  return { name, value: String(value), children };
}

function readHttp(payload) {
  if (!payload.length) return null;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(payload);
  const firstLineEnd = text.indexOf("\r\n");
  if (firstLineEnd < 0) return null;
  const firstLine = text.slice(0, firstLineEnd);
  const isRequest = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+\s+HTTP\/\d\.\d$/.test(firstLine);
  const response = /^HTTP\/\d\.\d\s+\d{3}(?:\s|$)/.test(firstLine);
  if (!isRequest && !response) return null;

  const headerEnd = text.indexOf("\r\n\r\n");
  const headerLines = text.slice(firstLineEnd + 2, headerEnd < 0 ? text.length : headerEnd).split("\r\n").filter(Boolean);
  const headers = headerLines.map(line => {
    const colon = line.indexOf(":");
    return colon > 0 ? field(line.slice(0, colon).trim(), line.slice(colon + 1).trim()) : field("Header", line);
  });
  const firstParts = firstLine.split(" ");
  return {
    summary: isRequest ? `${firstParts[0]} ${firstParts[1]}` : `${firstParts[1]} ${firstParts.slice(2).join(" ")}`.trim(),
    description: isRequest ? `${firstParts[0]} request` : "Response",
    fields: [
      field("Request method", isRequest ? firstParts[0] : "—"),
      field("Request URI", isRequest ? firstParts[1] : "—"),
      field("Status code", response ? firstParts[1] : "—"),
      field("Status phrase", response ? firstParts.slice(2).join(" ") : "—"),
      field("HTTP version", (isRequest ? firstParts[2] : firstParts[0]).replace("HTTP/", "")),
      field("Headers", `${headers.length} header${headers.length === 1 ? "" : "s"}`, headers),
      ...(headerEnd >= 0 && text.length > headerEnd + 4 ? [field("Body", `${text.length - headerEnd - 4} bytes`)] : []),
    ],
  };
}

const dnsTypes = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  41: "OPT",
  43: "DS",
  46: "RRSIG",
  47: "NSEC",
  48: "DNSKEY",
  64: "SVCB",
  65: "HTTPS",
};

function readDnsName(bytes, offset, end) {
  const labels = [];
  let cursor = offset;
  let nextOffset = null;
  const visitedPointers = new Set();
  let expandedLength = 0;
  while (true) {
    assertRange(cursor, 1, end, "DNS name");
    const length = bytes[cursor];
    if (length === 0) {
      if (nextOffset === null) nextOffset = cursor + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      assertRange(cursor, 2, end, "DNS compression pointer");
      const pointer = ((length & 0x3f) << 8) | bytes[cursor + 1];
      if (pointer >= end || visitedPointers.has(pointer)) throw new Error("The capture contains an invalid DNS compression pointer.");
      visitedPointers.add(pointer);
      if (nextOffset === null) nextOffset = cursor + 2;
      cursor = pointer;
      continue;
    }
    if (length & 0xc0 || length > 63) throw new Error("The capture contains an invalid DNS label.");
    assertRange(cursor + 1, length, end, "DNS label");
    expandedLength += length + 1;
    if (expandedLength > 255) throw new Error("The capture contains an overlong DNS name.");
    labels.push(new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(cursor + 1, cursor + 1 + length)));
    cursor += length + 1;
  }
  return { name: labels.join(".") || ".", nextOffset };
}

function dnsTypeName(type) {
  return dnsTypes[type] || `TYPE${type}`;
}

function dnsClassName(value) {
  return value === 1 ? "IN (Internet)" : value === 3 ? "CH (Chaos)" : value === 4 ? "HS (Hesiod)" : `CLASS${value}`;
}

function readDnsRecord(bytes, offset, end, view) {
  const owner = readDnsName(bytes, offset, end);
  let cursor = owner.nextOffset;
  assertRange(cursor, 10, end, "DNS resource record");
  const type = view.getUint16(cursor);
  const recordClass = view.getUint16(cursor + 2);
  const ttl = view.getUint32(cursor + 4);
  const dataLength = view.getUint16(cursor + 8);
  const dataOffset = cursor + 10;
  const dataEnd = dataOffset + dataLength;
  assertRange(dataOffset, dataLength, end, "DNS record data");
  let data;
  if (type === 1 && dataLength === 4) {
    data = formatIPv4(bytes, dataOffset);
  } else if (type === 28 && dataLength === 16) {
    data = formatIPv6(bytes, dataOffset);
  } else if ([2, 5, 12].includes(type)) {
    data = readDnsName(bytes, dataOffset, end).name;
  } else if (type === 15 && dataLength >= 3) {
    data = `${view.getUint16(dataOffset)} ${readDnsName(bytes, dataOffset + 2, end).name}`;
  } else if (type === 33 && dataLength >= 7) {
    data = `${view.getUint16(dataOffset)} ${view.getUint16(dataOffset + 2)} ${view.getUint16(dataOffset + 4)} ${readDnsName(bytes, dataOffset + 6, end).name}`;
  } else if (type === 16) {
    const chunks = [];
    for (let position = dataOffset; position < dataEnd;) {
      const length = bytes[position++];
      assertRange(position, length, dataEnd, "DNS TXT string");
      chunks.push(new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(position, position + length)));
      position += length;
    }
    data = chunks.map(chunk => `"${chunk.replaceAll('"', '\\"')}"`).join(" ");
  } else if (type === 6 && dataLength >= 22) {
    const primary = readDnsName(bytes, dataOffset, end);
    const responsible = readDnsName(bytes, primary.nextOffset, end);
    assertRange(responsible.nextOffset, 20, dataEnd, "DNS SOA record");
    const values = Array.from({ length: 5 }, (_, index) => view.getUint32(responsible.nextOffset + index * 4));
    data = `${primary.name} ${responsible.name} ${values.join(" ")}`;
  } else {
    data = dataLength ? `\\# ${dataLength} ${Array.from(bytes.subarray(dataOffset, dataEnd), byte => byte.toString(16).padStart(2, "0")).join("")}` : "(empty)";
  }
  return {
    name: owner.name,
    type,
    recordClass,
    ttl,
    dataLength,
    data,
    nextOffset: dataEnd,
  };
}

function parseDns(payload, isTcp) {
  let start = 0;
  let messageLength = payload.length;
  if (isTcp) {
    if (payload.length < 2) return null;
    messageLength = (payload[0] << 8) | payload[1];
    start = 2;
    if (messageLength === 0 || messageLength > payload.length - 2) return null;
    messageLength = start + messageLength;
  }
  if (messageLength - start < 12) return null;
  const bytes = payload.subarray(start, messageLength);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const id = view.getUint16(0);
  const flags = view.getUint16(2);
  const isResponse = Boolean(flags & 0x8000);
  const opcode = (flags >> 11) & 0x0f;
  const responseCode = flags & 0x0f;
  const questionCount = view.getUint16(4);
  const answerCount = view.getUint16(6);
  const authorityCount = view.getUint16(8);
  const additionalCount = view.getUint16(10);
  const opcodeNames = ["Standard query", "Inverse query", "Status", "Notify", "Update"];
  const responseNames = ["No error", "Format error", "Server failure", "Name error", "Not implemented", "Refused"];
  const queryFields = [];
  const recordFields = [];
  let offset = 12;

  for (let index = 0; index < questionCount; index++) {
    const question = readDnsName(bytes, offset, bytes.length);
    offset = question.nextOffset;
    assertRange(offset, 4, bytes.length, "DNS question");
    const type = view.getUint16(offset);
    const recordClass = view.getUint16(offset + 2);
    offset += 4;
    queryFields.push(field(`Question ${index + 1}`, `${question.name} ${dnsTypeName(type)}`, [
      field("Name", question.name),
      field("Type", `${type} (${dnsTypeName(type)})`),
      field("Class", `${recordClass} (${dnsClassName(recordClass)})`),
    ]));
  }

  const sections = [
    ["Answer", answerCount],
    ["Authority", authorityCount],
    ["Additional", additionalCount],
  ];
  const answerSummaries = [];
  for (const [section, count] of sections) {
    const fields = [];
    for (let index = 0; index < count; index++) {
      const record = readDnsRecord(bytes, offset, bytes.length, view);
      offset = record.nextOffset;
      const summary = `${record.name} ${record.ttl} ${dnsTypeName(record.type)} ${record.data}`;
      fields.push(field(`Record ${index + 1}`, summary, [
        field("Name", record.name),
        field("Type", `${record.type} (${dnsTypeName(record.type)})`),
        field("Class", `${record.recordClass} (${dnsClassName(record.recordClass)})`),
        field("Time to live", `${record.ttl} seconds`),
        field("Data length", `${record.dataLength} bytes`),
        field("Data", record.data),
      ]));
      if (section === "Answer") answerSummaries.push(`${dnsTypeName(record.type)} ${record.data}`);
    }
    if (count) recordFields.push(field(`${section} records`, `${count} record${count === 1 ? "" : "s"}`, fields));
  }

  const questionSummary = queryFields[0]?.children[0]?.value;
  const firstQuestionType = queryFields[0]?.children[1]?.value.match(/\(([^)]+)\)$/)?.[1];
  const operation = opcodeNames[opcode] || `Opcode ${opcode}`;
  const description = `${operation}${isResponse ? " response" : ""}`;
  const parts = [description, `0x${id.toString(16).padStart(4, "0")}`];
  if (questionSummary) parts.push(firstQuestionType || "query", questionSummary);
  if (answerSummaries.length) parts.push(...answerSummaries.slice(0, 2));
  if (responseCode) parts.push(responseNames[responseCode] || `RCode ${responseCode}`);

  const headerFields = [
    field("Transaction ID", `0x${id.toString(16).padStart(4, "0")}`),
    field("Message type", isResponse ? "Response" : "Query"),
    field("Opcode", `${opcode} (${operation})`),
    field("Authoritative answer", Boolean(flags & 0x0400)),
    field("Truncated", Boolean(flags & 0x0200)),
    field("Recursion desired", Boolean(flags & 0x0100)),
    field("Recursion available", Boolean(flags & 0x0080)),
    field("Response code", `${responseCode} (${responseNames[responseCode] || "Unknown"})`),
    field("Questions", questionCount),
    field("Answer RRs", answerCount),
    field("Authority RRs", authorityCount),
    field("Additional RRs", additionalCount),
  ];

  return {
    summary: parts.join(" "),
    description,
    fields: [
      field("Header", `${description}, ID 0x${id.toString(16).padStart(4, "0")}`, headerFields),
      ...(queryFields.length ? [field("Questions", `${queryFields.length} question${queryFields.length === 1 ? "" : "s"}`, queryFields)] : []),
      ...recordFields,
    ],
  };
}

function parseArp(bytes, offset, end) {
  assertRange(offset, 8, end, "ARP header");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const hardwareType = view.getUint16(offset);
  const protocolType = view.getUint16(offset + 2);
  const hardwareLength = bytes[offset + 4];
  const protocolLength = bytes[offset + 5];
  const operation = view.getUint16(offset + 6);
  const addressBytes = 2 * (hardwareLength + protocolLength);
  assertRange(offset + 8, addressBytes, end, "ARP addresses");
  let cursor = offset + 8;
  const senderMac = hardwareLength === 6 ? formatMac(bytes, cursor) : Array.from(bytes.subarray(cursor, cursor + hardwareLength), b => b.toString(16).padStart(2, "0")).join(":");
  cursor += hardwareLength;
  const senderIP = protocolLength === 4 ? formatIPv4(bytes, cursor) : Array.from(bytes.subarray(cursor, cursor + protocolLength), b => b.toString(16).padStart(2, "0")).join(".");
  cursor += protocolLength;
  const targetMac = hardwareLength === 6 ? formatMac(bytes, cursor) : Array.from(bytes.subarray(cursor, cursor + hardwareLength), b => b.toString(16).padStart(2, "0")).join(":");
  cursor += hardwareLength;
  const targetIP = protocolLength === 4 ? formatIPv4(bytes, cursor) : Array.from(bytes.subarray(cursor, cursor + protocolLength), b => b.toString(16).padStart(2, "0")).join(".");
  const operationName = operation === 1 ? "request" : operation === 2 ? "reply" : `operation ${operation}`;
  return {
    protocol: "ARP",
    source: senderIP,
    destination: targetIP,
    info: `${operationName[0].toUpperCase()}${operationName.slice(1)}: ${senderIP} → ${targetIP}`,
    layers: [{
      name: "Address Resolution Protocol",
      summary: `${operationName} ${senderIP} → ${targetIP}`,
      fields: [
        field("Hardware type", `${hardwareType} (${hardwareType === 1 ? "Ethernet" : "unknown"})`),
        field("Protocol type", `0x${protocolType.toString(16).padStart(4, "0")}`),
        field("Hardware size", `${hardwareLength} bytes`),
        field("Protocol size", `${protocolLength} bytes`),
        field("Opcode", `${operation} (${operationName})`),
        field("Sender MAC address", senderMac),
        field("Sender IP address", senderIP),
        field("Target MAC address", targetMac),
        field("Target IP address", targetIP),
      ],
    }],
    filterTokens: ["arp"],
  };
}

function parseIcmp(bytes, offset, end, version) {
  assertRange(offset, 8, end, "ICMP header");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const type = bytes[offset];
  const code = bytes[offset + 1];
  const checksum = `0x${view.getUint16(offset + 2).toString(16).padStart(4, "0")}`;
  const isV6 = version === 6;
  const protocol = isV6 ? "ICMPv6" : "ICMP";
  const typeNames = isV6 ? {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
  } : {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
  };
  const codeNames = isV6 ? {
    1: ["No route to destination", "Communication administratively prohibited", "Beyond scope of source address", "Address unreachable", "Port unreachable", "Source address failed ingress/egress policy", "Reject route"],
    3: ["Hop limit exceeded in transit", "Fragment reassembly time exceeded"],
    4: ["Erroneous header field", "Unrecognized next header", "Unrecognized IPv6 option"],
  } : {
    3: ["Network unreachable", "Host unreachable", "Protocol unreachable", "Port unreachable", "Fragmentation needed", "Source route failed", "Destination network unknown", "Destination host unknown", "Source host isolated", "Network administratively prohibited", "Host administratively prohibited", "Network unreachable for ToS", "Host unreachable for ToS", "Communication administratively prohibited", "Host precedence violation", "Precedence cutoff"],
    5: ["Redirect for network", "Redirect for host", "Redirect for ToS and network", "Redirect for ToS and host"],
    11: ["TTL exceeded in transit", "Fragment reassembly time exceeded"],
  };
  const typeName = typeNames[type] || `Type ${type}`;
  const codeName = codeNames[type]?.[code] || `Code ${code}`;
  const fields = [
    field("Type", `${type} (${typeName})`),
    field("Code", `${code} (${codeName})`),
    field("Checksum", checksum),
  ];
  let detail = codeName;

  if ((!isV6 && [0, 8, 13, 14].includes(type)) || (isV6 && [128, 129].includes(type))) {
    const identifier = view.getUint16(offset + 4);
    const sequence = view.getUint16(offset + 6);
    fields.push(field("Identifier", identifier), field("Sequence number", sequence));
    if (!isV6 && [13, 14].includes(type)) {
      assertRange(offset, 20, end, "ICMP timestamp message");
      fields.push(
        field("Originate timestamp", `${view.getUint32(offset + 8)} ms`),
        field("Receive timestamp", `${view.getUint32(offset + 12)} ms`),
        field("Transmit timestamp", `${view.getUint32(offset + 16)} ms`),
      );
    }
    detail = `id=${identifier}, seq=${sequence}`;
  } else if ((!isV6 && type === 3 && code === 4) || (isV6 && type === 2)) {
    const mtu = isV6 ? view.getUint32(offset + 4) : view.getUint16(offset + 6);
    fields.push(field("Next-hop MTU", `${mtu} bytes`));
    detail = `MTU ${mtu}`;
  } else if ((!isV6 && type === 5) || (isV6 && type === 137)) {
    assertRange(offset, isV6 ? 40 : 8, end, "ICMP redirect message");
    const gateway = isV6 ? formatIPv6(bytes, offset + 8) : formatIPv4(bytes, offset + 4);
    fields.push(field(isV6 ? "Target address" : "Gateway address", gateway));
    if (isV6) fields.push(field("Destination address", formatIPv6(bytes, offset + 24)));
    detail = `${isV6 ? "target" : "gateway"} ${gateway}`;
  } else if ((!isV6 && type === 12) || (isV6 && type === 4)) {
    const pointer = isV6 ? view.getUint32(offset + 4) : bytes[offset + 4];
    fields.push(field("Pointer", pointer));
    detail = `pointer ${pointer}`;
  } else if (isV6 && [135, 136].includes(type)) {
    assertRange(offset, 24, end, "ICMPv6 neighbor message");
    const target = formatIPv6(bytes, offset + 8);
    fields.push(field("Target address", target));
    if (type === 136) {
      const flags = view.getUint32(offset + 4);
      fields.push(
        field("Router flag", Boolean(flags & 0x80000000)),
        field("Solicited flag", Boolean(flags & 0x40000000)),
        field("Override flag", Boolean(flags & 0x20000000)),
      );
    }
    detail = target;
  } else if (isV6 && type === 134) {
    assertRange(offset, 16, end, "ICMPv6 router advertisement");
    fields.push(
      field("Current hop limit", bytes[offset + 4]),
      field("Managed address configuration", Boolean(bytes[offset + 5] & 0x80)),
      field("Other configuration", Boolean(bytes[offset + 5] & 0x40)),
      field("Router lifetime", `${view.getUint16(offset + 6)} seconds`),
      field("Reachable time", `${view.getUint32(offset + 8)} ms`),
      field("Retransmit timer", `${view.getUint32(offset + 12)} ms`),
    );
  }

  const info = `${typeName}${detail ? ` (${detail})` : ""}`;
  return {
    protocol,
    info,
    layer: { name: protocol, summary: info, fields },
    filterTokens: [protocol.toLowerCase(), "icmp"],
  };
}

function parseTransport(bytes, offset, end, protocol, context) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  assertRange(offset, protocol === 6 ? 20 : 8, end, protocol === 6 ? "TCP header" : "UDP header");
  const sourcePort = view.getUint16(offset);
  const destinationPort = view.getUint16(offset + 2);
  const segmentLength = protocol === 6 ? ((bytes[offset + 12] >> 4) * 4) : 8;
  if (segmentLength < (protocol === 6 ? 20 : 8)) throw new Error(`The capture contains an invalid ${protocol === 6 ? "TCP" : "UDP"} header length.`);
  assertRange(offset, segmentLength, end, protocol === 6 ? "TCP options" : "UDP header");
  const payloadStart = offset + segmentLength;
  const payloadEnd = protocol === 17 ? Math.min(end, offset + view.getUint16(offset + 4)) : end;
  const payload = bytes.subarray(payloadStart, Math.max(payloadStart, payloadEnd));
  const isTcp = protocol === 6;
  const label = isTcp ? "TCP" : "UDP";
  const dns = (sourcePort === 53 || destinationPort === 53) ? parseDns(payload, isTcp) : null;
  const flags = isTcp ? bytes[offset + 13] : 0;
  const flagNames = [];
  if (isTcp) {
    for (const [mask, name] of [[0x80, "CWR"], [0x40, "ECE"], [0x20, "URG"], [0x02, "SYN"], [0x04, "RST"], [0x08, "PSH"], [0x01, "FIN"], [0x10, "ACK"]]) {
      if (flags & mask) flagNames.push(name);
    }
  }
  const http = isTcp && (sourcePort === 80 || destinationPort === 80 || sourcePort === 8080 || destinationPort === 8080 || sourcePort === 8000 || destinationPort === 8000)
    ? readHttp(payload)
    : (isTcp ? readHttp(payload) : null);
  const fields = [
    field("Source port", sourcePort),
    field("Destination port", destinationPort),
  ];
  if (isTcp) {
    fields.push(
      field("Sequence number", view.getUint32(offset + 4)),
      field("Acknowledgment number", view.getUint32(offset + 8)),
      field("Header length", `${segmentLength} bytes`),
      field("Flags", flagNames.join(", ") || "None", flagNames.map(name => field(name, "Set"))),
      field("Window size", view.getUint16(offset + 14)),
      field("Checksum", `0x${view.getUint16(offset + 16).toString(16).padStart(4, "0")}`),
      field("Urgent pointer", view.getUint16(offset + 18)),
    );
    let optionOffset = offset + 20;
    const optionFields = [];
    while (optionOffset < offset + segmentLength) {
      const kind = bytes[optionOffset];
      if (kind === 0) { optionFields.push(field("End of options", "End")); break; }
      if (kind === 1) { optionFields.push(field("No-op", "1")); optionOffset++; continue; }
      if (optionOffset + 1 >= offset + segmentLength) break;
      const length = bytes[optionOffset + 1];
      if (length < 2 || optionOffset + length > offset + segmentLength) break;
      const value = kind === 2 && length === 4 ? view.getUint16(optionOffset + 2) : `${length} bytes`;
      const name = kind === 2 ? "Maximum segment size" : kind === 3 ? "Window scale" : kind === 4 ? "SACK permitted" : kind === 8 ? "Timestamps" : `Option ${kind}`;
      optionFields.push(field(name, value));
      optionOffset += length;
    }
    if (optionFields.length) fields.push(field("Options", `${optionFields.length} option(s)`, optionFields));
    fields.push(field("Payload length", `${payload.length} bytes`));
  } else {
    fields.push(
      field("Length", `${view.getUint16(offset + 4)} bytes`),
      field("Checksum", `0x${view.getUint16(offset + 6).toString(16).padStart(4, "0")}`),
      field("Payload length", `${payload.length} bytes`),
    );
  }
  const info = dns ? dns.summary : http ? http.summary : isTcp
    ? `${sourcePort} → ${destinationPort}${flagNames.length ? ` [${flagNames.join(", ")}]` : ""}${payload.length ? ` Len=${payload.length}` : ""}`
    : `${sourcePort} → ${destinationPort} Len=${payload.length}`;
  const transport = {
    name: `${label} (${sourcePort} → ${destinationPort})`,
    summary: `${sourcePort} → ${destinationPort}${isTcp && flagNames.length ? ` [${flagNames.join(", ")}]` : ""}`,
    fields,
  };
  context.layers.push(transport);
  if (dns) context.layers.push({ name: "Domain Name System", summary: dns.summary, fields: dns.fields });
  return {
    protocol: dns ? "DNS" : http ? "HTTP" : label,
    info,
    http,
    filterTokens: [label.toLowerCase(), isTcp ? "tcp" : "udp", ...(dns ? ["dns"] : []), ...(http ? ["http"] : [])],
  };
}

function parsePacket(packetBytes, originalLength, time, number, interfaceInfo) {
  const bytes = packetBytes;
  const end = bytes.length;
  if (interfaceInfo?.linkType !== 1) {
    return {
      number,
      time,
      length: originalLength,
      capturedLength: end,
      source: "—",
      destination: "—",
      protocol: "Unknown",
      info: `Unsupported link type ${interfaceInfo.linkType}`,
      bytes,
      layers: [{ name: "Frame", summary: `${end} captured bytes`, fields: [field("Link type", interfaceInfo.linkType)] }],
      filterTokens: ["frame"],
    };
  }
  assertRange(0, 14, end, "Ethernet header");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let etherType = view.getUint16(12);
  const destinationMac = formatMac(bytes, 0);
  const sourceMac = formatMac(bytes, 6);
  const ethernetFields = [
    field("Destination", destinationMac),
    field("Source", sourceMac),
    field("Type", `0x${etherType.toString(16).padStart(4, "0")} (${etherType === 0x0800 ? "IPv4" : etherType === 0x86dd ? "IPv6" : etherType === 0x0806 ? "ARP" : "Unknown"})`),
  ];
  let networkOffset = 14;
  const vlans = [];
  while ([0x8100, 0x88a8, 0x9100].includes(etherType)) {
    assertRange(networkOffset, 4, end, "VLAN header");
    const tci = view.getUint16(networkOffset);
    const innerType = view.getUint16(networkOffset + 2);
    vlans.push(field("VLAN", `ID ${tci & 0x0fff}, priority ${tci >> 13}, type 0x${innerType.toString(16)}`));
    etherType = innerType;
    networkOffset += 4;
  }
  if (vlans.length) ethernetFields.push(...vlans);
  const layers = [{
    name: "Ethernet II",
    summary: `${sourceMac} → ${destinationMac}`,
    fields: ethernetFields,
  }];
  const result = {
    number,
    time,
    length: originalLength,
    capturedLength: end,
    source: sourceMac,
    destination: destinationMac,
    protocol: "Ethernet",
    info: "Unknown packet type",
    bytes,
    layers,
    filterTokens: ["eth", "ethernet"],
  };

  if (etherType === 0x0806) {
    const arp = parseArp(bytes, networkOffset, end);
    result.protocol = arp.protocol;
    result.source = arp.source;
    result.destination = arp.destination;
    result.info = arp.info;
    result.layers.push(...arp.layers);
    result.filterTokens.push(...arp.filterTokens);
  } else if (etherType === 0x0800) {
    assertRange(networkOffset, 20, end, "IPv4 header");
    const versionAndLength = bytes[networkOffset];
    const headerLength = (versionAndLength & 0x0f) * 4;
    if ((versionAndLength >> 4) !== 4 || headerLength < 20) throw new Error("The capture contains an invalid IPv4 header.");
    assertRange(networkOffset, headerLength, end, "IPv4 options");
    const totalLength = view.getUint16(networkOffset + 2);
    const protocolNumber = bytes[networkOffset + 9];
    const sourceIP = formatIPv4(bytes, networkOffset + 12);
    const destinationIP = formatIPv4(bytes, networkOffset + 16);
    const ipEnd = Math.min(end, networkOffset + totalLength);
    const flagsAndOffset = view.getUint16(networkOffset + 6);
    const ipFields = [
      field("Version", 4),
      field("Header length", `${headerLength} bytes`),
      field("Differentiated services", `0x${bytes[networkOffset + 1].toString(16).padStart(2, "0")}`),
      field("Total length", `${totalLength} bytes`),
      field("Identification", `0x${view.getUint16(networkOffset + 4).toString(16).padStart(4, "0")}`),
      field("Flags", `0x${(flagsAndOffset >> 13).toString(16)}`),
      field("Fragment offset", flagsAndOffset & 0x1fff),
      field("Time to live", bytes[networkOffset + 8]),
      field("Protocol", `${protocolNumber} (${protocolNames[protocolNumber] || "Unknown"})`),
      field("Header checksum", `0x${view.getUint16(networkOffset + 10).toString(16).padStart(4, "0")}`),
      field("Source address", sourceIP),
      field("Destination address", destinationIP),
    ];
    if (headerLength > 20) ipFields.push(field("Options", `${headerLength - 20} bytes`));
    layers.push({ name: "Internet Protocol Version 4", summary: `${sourceIP} → ${destinationIP}`, fields: ipFields });
    result.source = sourceIP;
    result.destination = destinationIP;
    result.info = `${sourceIP} → ${destinationIP}`;
    result.filterTokens.push("ip", "ipv4");
    const transportOffset = networkOffset + headerLength;
    if (protocolNumber === 6 || protocolNumber === 17) {
      const transport = parseTransport(bytes, transportOffset, ipEnd, protocolNumber, { layers });
      result.protocol = transport.protocol;
      result.info = transport.info;
      result.filterTokens.push(...transport.filterTokens);
      if (transport.http) layers.push({ name: "Hypertext Transfer Protocol", summary: transport.http.summary, fields: transport.http.fields });
    } else if (protocolNumber === 1) {
      const icmp = parseIcmp(bytes, transportOffset, ipEnd, 4);
      result.protocol = icmp.protocol;
      result.info = icmp.info;
      result.layers.push(icmp.layer);
      result.filterTokens.push(...icmp.filterTokens);
    } else if (protocolNames[protocolNumber]) {
      result.protocol = protocolNames[protocolNumber];
      result.info = `${result.info} ${result.protocol}`;
      result.filterTokens.push(result.protocol.toLowerCase());
    } else {
      result.info = `${result.info} Protocol ${protocolNumber}`;
    }
  } else if (etherType === 0x86dd) {
    assertRange(networkOffset, 40, end, "IPv6 header");
    if ((bytes[networkOffset] >> 4) !== 6) throw new Error("The capture contains an invalid IPv6 header.");
    const payloadLength = view.getUint16(networkOffset + 4);
    let nextHeader = bytes[networkOffset + 6];
    const sourceIP = formatIPv6(bytes, networkOffset + 8);
    const destinationIP = formatIPv6(bytes, networkOffset + 24);
    const ipEnd = Math.min(end, networkOffset + 40 + payloadLength);
    const ipFields = [
      field("Version", 6),
      field("Traffic class", ((bytes[networkOffset] & 0x0f) << 4) | (bytes[networkOffset + 1] >> 4)),
      field("Flow label", `0x${(((bytes[networkOffset + 1] & 0x0f) << 16) | (bytes[networkOffset + 2] << 8) | bytes[networkOffset + 3]).toString(16)}`),
      field("Payload length", `${payloadLength} bytes`),
      field("Next header", `${nextHeader} (${protocolNames[nextHeader] || "Unknown"})`),
      field("Hop limit", bytes[networkOffset + 7]),
      field("Source address", sourceIP),
      field("Destination address", destinationIP),
    ];
    layers.push({ name: "Internet Protocol Version 6", summary: `${sourceIP} → ${destinationIP}`, fields: ipFields });
    result.source = sourceIP;
    result.destination = destinationIP;
    result.info = `${sourceIP} → ${destinationIP}`;
    result.filterTokens.push("ipv6", "ip");
    let transportOffset = networkOffset + 40;
    while ([0, 43, 44, 51, 60].includes(nextHeader)) {
      assertRange(transportOffset, nextHeader === 44 ? 8 : 2, ipEnd, "IPv6 extension header");
      const extensionType = nextHeader;
      const following = bytes[transportOffset];
      const extensionLength = extensionType === 44 ? 8 : extensionType === 51 ? (bytes[transportOffset + 1] + 2) * 4 : (bytes[transportOffset + 1] + 1) * 8;
      assertRange(transportOffset, extensionLength, ipEnd, "IPv6 extension header");
      const name = extensionType === 0 ? "Hop-by-Hop Options" : extensionType === 43 ? "Routing" : extensionType === 44 ? "Fragment" : extensionType === 51 ? "Authentication" : "Destination Options";
      layers.push({ name: `IPv6 ${name} Header`, summary: `${extensionLength} bytes`, fields: [field("Next header", following), field("Header length", `${extensionLength} bytes`)] });
      nextHeader = following;
      transportOffset += extensionLength;
    }
    if (nextHeader === 6 || nextHeader === 17) {
      const transport = parseTransport(bytes, transportOffset, ipEnd, nextHeader, { layers });
      result.protocol = transport.protocol;
      result.info = transport.info;
      result.filterTokens.push(...transport.filterTokens);
      if (transport.http) layers.push({ name: "Hypertext Transfer Protocol", summary: transport.http.summary, fields: transport.http.fields });
    } else if (nextHeader === 58) {
      const icmp = parseIcmp(bytes, transportOffset, ipEnd, 6);
      result.protocol = icmp.protocol;
      result.info = icmp.info;
      layers.push(icmp.layer);
      result.filterTokens.push(...icmp.filterTokens);
    } else if (protocolNames[nextHeader]) {
      result.protocol = protocolNames[nextHeader];
      result.info = `${result.info} ${result.protocol}`;
      result.filterTokens.push(result.protocol.toLowerCase());
    } else {
      result.info = `${result.info} Next header ${nextHeader}`;
    }
  }
  result.filterTokens = [...new Set(result.filterTokens)];
  return result;
}

export function parsePcapng(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const packets = [];
  let offset = 0;
  let littleEndian = true;
  let interfaces = [];
  let sectionSeen = false;
  let firstTimestamp = null;

  while (offset + 12 <= bytes.length) {
    const rawType = view.getUint32(offset, true);
    let blockType;
    if (rawType === BLOCK.SECTION_HEADER) {
      assertRange(offset, 12, bytes.length, "section header");
      const bom = view.getUint32(offset + 8, false);
      if (bom === 0x1a2b3c4d) littleEndian = false;
      else if (bom === 0x4d3c2b1a) littleEndian = true;
      else throw new Error("This file has an invalid PCAPNG byte-order marker.");
      blockType = BLOCK.SECTION_HEADER;
    } else {
      if (!sectionSeen) throw new Error("This is not a valid PCAPNG file (section header not found).");
      blockType = view.getUint32(offset, littleEndian);
    }
    const blockLength = view.getUint32(offset + 4, littleEndian);
    if (blockLength < 12 || blockLength % 4 !== 0) throw new Error(`The capture contains an invalid block length at byte ${offset}.`);
    assertRange(offset, blockLength, bytes.length, "PCAPNG block");
    if (view.getUint32(offset + blockLength - 4, littleEndian) !== blockLength) throw new Error(`The capture contains a mismatched block length at byte ${offset}.`);

    if (blockType === BLOCK.SECTION_HEADER) {
      if (blockLength < 28) throw new Error("The capture contains an incomplete section header.");
      interfaces = [];
      sectionSeen = true;
    } else if (blockType === BLOCK.INTERFACE_DESCRIPTION) {
      if (blockLength < 20) throw new Error("The capture contains an incomplete interface description.");
      const linkType = view.getUint16(offset + 8, littleEndian);
      const interfaceInfo = { linkType, timestampScale: 1e-6, timestampOffset: 0 };
      readOptions(view, offset + 16, offset + blockLength - 4, littleEndian, (code, valueOffset, length) => {
        if (code === 9 && length >= 1) {
          const resolution = bytes[valueOffset];
          interfaceInfo.timestampScale = resolution & 0x80 ? 2 ** -(resolution & 0x7f) : 10 ** -resolution;
        } else if (code === 14 && length >= 8) {
          interfaceInfo.timestampOffset = Number(view.getBigInt64(valueOffset, littleEndian));
        }
      });
      interfaces.push(interfaceInfo);
    } else if (blockType === BLOCK.ENHANCED_PACKET || blockType === BLOCK.PACKET || blockType === BLOCK.SIMPLE_PACKET) {
      if (interfaces.length === 0) throw new Error("The capture contains a packet before any interface was defined.");
      let interfaceId = 0;
      let capturedLength;
      let originalLength;
      let packetOffset;
      let time = null;
      if (blockType === BLOCK.ENHANCED_PACKET) {
        if (blockLength < 32) throw new Error("The capture contains an incomplete enhanced packet block.");
        interfaceId = view.getUint32(offset + 8, littleEndian);
        const timestampHigh = view.getUint32(offset + 12, littleEndian);
        const timestampLow = view.getUint32(offset + 16, littleEndian);
        capturedLength = view.getUint32(offset + 20, littleEndian);
        originalLength = view.getUint32(offset + 24, littleEndian);
        packetOffset = offset + 28;
        const timestamp = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
        const iface = interfaces[interfaceId];
        if (!iface) throw new Error(`The capture refers to unknown interface ${interfaceId}.`);
        time = iface.timestampOffset + Number(timestamp) * iface.timestampScale;
      } else if (blockType === BLOCK.PACKET) {
        if (blockLength < 32) throw new Error("The capture contains an incomplete packet block.");
        interfaceId = view.getUint16(offset + 8, littleEndian);
        const timestampHigh = view.getUint32(offset + 12, littleEndian);
        const timestampLow = view.getUint32(offset + 16, littleEndian);
        capturedLength = view.getUint32(offset + 20, littleEndian);
        originalLength = view.getUint32(offset + 24, littleEndian);
        packetOffset = offset + 28;
        const timestamp = (BigInt(timestampHigh) << 32n) | BigInt(timestampLow);
        const iface = interfaces[interfaceId];
        if (!iface) throw new Error(`The capture refers to unknown interface ${interfaceId}.`);
        time = iface.timestampOffset + Number(timestamp) * iface.timestampScale;
      } else {
        if (blockLength < 16) throw new Error("The capture contains an incomplete simple packet block.");
        originalLength = view.getUint32(offset + 8, littleEndian);
        capturedLength = Math.min(originalLength, blockLength - 16);
        packetOffset = offset + 12;
      }
      const iface = interfaces[interfaceId];
      if (!iface) throw new Error(`The capture refers to unknown interface ${interfaceId}.`);
      const packetLimit = offset + blockLength - 4;
      assertRange(packetOffset, capturedLength, packetLimit, "packet data");
      const packetBytes = bytes.slice(packetOffset, packetOffset + capturedLength);
      const packet = parsePacket(packetBytes, originalLength, time, packets.length + 1, iface);
      packets.push(packet);
      if (time !== null && (firstTimestamp === null || time < firstTimestamp)) firstTimestamp = time;
    }
    offset += blockLength;
  }

  if (!sectionSeen) throw new Error("This file is empty or is not a valid PCAPNG capture.");
  if (offset !== bytes.length) throw new Error("The capture ends with an incomplete PCAPNG block.");
  if (firstTimestamp !== null) {
    for (const packet of packets) packet.relativeTime = packet.time - firstTimestamp;
  }
  return { packets, interfaceCount: interfaces.length };
}

export function parsePcap(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 24) throw new Error("This file is not a valid PCAP capture (global header is incomplete).");

  const magic = Array.from(bytes.subarray(0, 4)).join(",");
  const format = PCAP_FORMATS[magic];
  if (!format) throw new Error("This file has an unrecognized PCAP byte-order marker.");

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const majorVersion = view.getUint16(4, format.littleEndian);
  if (majorVersion !== 2) throw new Error(`This PCAP version (${majorVersion}) is not supported.`);
  const interfaceInfo = { linkType: view.getUint32(20, format.littleEndian) & 0xffff };
  const packets = [];
  let offset = 24;
  let firstTimestamp = null;

  while (offset < bytes.length) {
    assertRange(offset, 16, bytes.length, "PCAP packet header");
    const seconds = view.getUint32(offset, format.littleEndian);
    const fraction = view.getUint32(offset + 4, format.littleEndian);
    const capturedLength = view.getUint32(offset + 8, format.littleEndian);
    const originalLength = view.getUint32(offset + 12, format.littleEndian);
    const fractionLimit = format.timestampScale === 1e-6 ? 1_000_000 : 1_000_000_000;
    if (fraction >= fractionLimit) throw new Error("The capture contains an invalid packet timestamp.");
    const packetOffset = offset + 16;
    assertRange(packetOffset, capturedLength, bytes.length, "packet data");
    const packetBytes = bytes.slice(packetOffset, packetOffset + capturedLength);
    const time = seconds + fraction * format.timestampScale;
    packets.push(parsePacket(packetBytes, originalLength, time, packets.length + 1, interfaceInfo));
    if (firstTimestamp === null || time < firstTimestamp) firstTimestamp = time;
    offset = packetOffset + capturedLength;
  }

  if (firstTimestamp !== null) {
    for (const packet of packets) packet.relativeTime = packet.time - firstTimestamp;
  }
  return { packets, interfaceCount: 1 };
}

export function parseCapture(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const magic = Array.from(bytes.subarray(0, 4)).join(",");
  if (PCAP_FORMATS[magic]) {
    return parsePcap(bytes);
  }
  return parsePcapng(bytes);
}
