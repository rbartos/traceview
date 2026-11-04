import { parseCapture } from "./pcap.mjs";

const elements = {
  fileInput: document.querySelector("#file-input"),
  sampleSelect: document.querySelector("#sample-select"),
  aboutButton: document.querySelector("#about-button"),
  aboutDialog: document.querySelector("#about-dialog"),
  aboutContent: document.querySelector("#about-content"),
  aboutClose: document.querySelector("#about-close"),
  welcomeSample: document.querySelector("#welcome-sample"),
  welcome: document.querySelector("#welcome"),
  workspace: document.querySelector("#workspace"),
  captureName: document.querySelector("#capture-name"),
  captureMeta: document.querySelector("#capture-meta"),
  filter: document.querySelector("#display-filter"),
  clearFilter: document.querySelector("#clear-filter"),
  packetCount: document.querySelector("#packet-count"),
  packetSelection: document.querySelector("#packet-selection"),
  packetRows: document.querySelector("#packet-rows"),
  emptyFilter: document.querySelector("#empty-filter"),
  details: document.querySelector("#packet-details"),
  bytes: document.querySelector("#packet-bytes"),
  bytesLength: document.querySelector("#bytes-length"),
  error: document.querySelector("#error-message"),
};

let packets = [];
let sampleFiles = [];
let samplesReady = Promise.resolve();
let selectedNumber = null;
let errorTimer = null;
let aboutLoaded = false;

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
  window.clearTimeout(errorTimer);
  errorTimer = window.setTimeout(() => { elements.error.hidden = true; }, 7000);
}

function formatTime(seconds) {
  if (seconds === null || !Number.isFinite(seconds)) return "—";
  const date = new Date(seconds * 1000);
  return `${date.toISOString().slice(11, 23)}`;
}

function setCapture(fileName, parsed) {
  packets = parsed.packets;
  selectedNumber = packets[0]?.number ?? null;
  elements.captureName.textContent = fileName;
  const totalBytes = packets.reduce((sum, packet) => sum + packet.length, 0);
  elements.captureMeta.textContent = `${packets.length.toLocaleString()} packets · ${formatBytes(totalBytes)} · ${parsed.interfaceCount} interface${parsed.interfaceCount === 1 ? "" : "s"}`;
  elements.filter.value = "";
  document.querySelectorAll(".filter-chip").forEach(chip => chip.classList.toggle("active", chip.dataset.filter === ""));
  elements.welcome.hidden = true;
  elements.workspace.hidden = false;
  elements.error.hidden = true;
  renderPackets();
}

function formatBytes(bytes) {
  if (bytes < 1000) return `${bytes} B`;
  if (bytes < 1_000_000) return `${(bytes / 1000).toFixed(1)} kB`;
  return `${(bytes / 1_000_000).toFixed(2)} MB`;
}

function matchesFilter(packet, filter) {
  const query = filter.trim().toLowerCase();
  if (!query) return true;
  const tokens = query.split(/\s+and\s+|&&|\s+/).filter(Boolean);
  const searchable = `${packet.number} ${packet.time ?? ""} ${packet.source} ${packet.destination} ${packet.protocol} ${packet.info} ${packet.filterTokens.join(" ")}`.toLowerCase();
  return tokens.every(token => {
    const part = token.replace(/^\(|\)$/g, "").replace(/^!/, "");
    const matched = packet.filterTokens.includes(part) || searchable.includes(part);
    return token.startsWith("!") ? !matched : matched;
  });
}

function renderPackets() {
  const filter = elements.filter.value;
  const visible = packets.filter(packet => matchesFilter(packet, filter));
  elements.packetRows.replaceChildren();
  const fragment = document.createDocumentFragment();
  for (const packet of visible) {
    const row = document.createElement("tr");
    row.dataset.number = String(packet.number);
    if (packet.number === selectedNumber) row.classList.add("selected");
    const values = [
      packet.number,
      packet.relativeTime === undefined ? formatTime(packet.time) : packet.relativeTime.toFixed(6),
      packet.source,
      packet.destination,
      packet.protocol,
      packet.length,
      packet.info,
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      if (index === 4) {
        cell.classList.add("protocol");
        if (packet.protocol === "HTTP") cell.classList.add("protocol-http");
        if (packet.protocol === "ARP") cell.classList.add("protocol-arp");
        if (packet.protocol === "DNS") cell.classList.add("protocol-dns");
      }
      row.append(cell);
    });
    row.addEventListener("click", () => {
      selectedNumber = packet.number;
      renderPackets();
      renderInspectors(packet);
    });
    fragment.append(row);
  }
  elements.packetRows.append(fragment);
  elements.emptyFilter.hidden = visible.length !== 0;
  elements.packetCount.textContent = `${visible.length.toLocaleString()} / ${packets.length.toLocaleString()} packets`;
  const selected = visible.find(packet => packet.number === selectedNumber);
  if (selected) renderInspectors(selected);
  else if (visible.length) {
    selectedNumber = visible[0].number;
    renderInspectors(visible[0]);
    elements.packetRows.querySelector("tr")?.classList.add("selected");
  } else {
    elements.details.innerHTML = '<div class="inspector-empty">No packet selected.</div>';
    elements.bytes.innerHTML = '<div class="inspector-empty">No packet selected.</div>';
    elements.bytesLength.textContent = "";
  }
}

function renderField(item, parent) {
  const row = document.createElement("div");
  row.className = "field-row";
  const name = document.createElement("span");
  name.className = "field-name";
  name.textContent = item.name;
  const value = document.createElement("span");
  value.className = "field-value";
  value.textContent = item.value;
  row.append(name, value);
  parent.append(row);
  if (item.children?.length) {
    const children = document.createElement("div");
    children.className = "field-children";
    item.children.forEach(child => renderField(child, children));
    parent.append(children);
  }
}

function renderInspectors(packet) {
  elements.details.replaceChildren();
  elements.details.scrollTop = 0;
  elements.bytes.scrollTop = 0;
  elements.packetSelection.textContent = `Frame ${packet.number} · ${packet.protocol}`;
  packet.layers.forEach((layer, index) => {
    const details = document.createElement("details");
    details.className = "layer";
    details.open = index < packet.layers.length;
    const summary = document.createElement("summary");
    const label = document.createElement("span");
    label.className = "layer-label";
    label.textContent = layer.name;
    const description = document.createElement("span");
    description.className = "layer-summary";
    description.textContent = `  ${layer.summary}`;
    summary.append(label, description);
    details.append(summary);
    const fields = document.createElement("div");
    layer.fields.forEach(item => renderField(item, fields));
    details.append(fields);
    elements.details.append(details);
  });
  elements.bytes.replaceChildren();
  elements.bytesLength.textContent = `${packet.capturedLength} bytes`;
  const fragment = document.createDocumentFragment();
  for (let offset = 0; offset < packet.bytes.length; offset += 16) {
    const row = document.createElement("div");
    row.className = "bytes-row";
    const offsetText = document.createElement("span");
    offsetText.className = "bytes-offset";
    offsetText.textContent = offset.toString(16).padStart(4, "0");
    const hexText = document.createElement("span");
    hexText.className = "bytes-hex";
    hexText.textContent = Array.from(packet.bytes.subarray(offset, offset + 16), byte => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const asciiText = document.createElement("span");
    asciiText.className = "bytes-ascii";
    asciiText.textContent = Array.from(packet.bytes.subarray(offset, offset + 16), byte => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".").join("");
    row.append(offsetText, hexText, asciiText);
    fragment.append(row);
  }
  elements.bytes.append(fragment);
}

async function loadFile(file) {
  if (!file) return;
  try {
    const parsed = parseCapture(await file.arrayBuffer());
    if (!parsed.packets.length) throw new Error("No supported packet blocks were found in this PCAPNG file.");
    setCapture(file.name, parsed);
  } catch (error) {
    showError(error instanceof Error ? error.message : "Unable to read this capture file.");
  }
}

async function loadSamples() {
  try {
    const response = await fetch(new URL("./samples/index.json", import.meta.url));
    if (!response.ok) throw new Error("Could not load the sample list.");
    const files = await response.json();
    if (!Array.isArray(files) || files.some(file => typeof file !== "string" || !/^[^/\\]+\.pcap(?:ng)?$/i.test(file))) {
      throw new Error("The sample list contains an invalid capture filename.");
    }
    if (new Set(files).size !== files.length) throw new Error("The sample list contains duplicate capture filenames.");

    sampleFiles = files;
    elements.sampleSelect.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = files.length ? "Open sample…" : "No sample captures";
    elements.sampleSelect.append(placeholder);
    for (const file of files) {
      const option = document.createElement("option");
      option.value = file;
      option.textContent = file;
      elements.sampleSelect.append(option);
    }
    elements.sampleSelect.disabled = files.length === 0;
    return true;
  } catch (error) {
    elements.sampleSelect.options[0].textContent = "Samples unavailable";
    showError(error instanceof Error ? error.message : "Unable to load the sample list.");
    return false;
  }
}

async function loadSampleFromUrl() {
  const fileName = new URLSearchParams(window.location.search).get("cap");
  if (fileName === null) return;

  if (!await samplesReady) return;
  if (!sampleFiles.includes(fileName)) {
    showError(`Sample capture "${fileName}" is not available.`);
    return;
  }
  await loadSample(fileName);
}

async function loadSample(fileName = sampleFiles[0]) {
  await samplesReady;
  const selectedFile = fileName ?? sampleFiles[0];
  if (!selectedFile) {
    showError("No sample captures are available.");
    return;
  }
  try {
    const sampleUrl = new URL(`./samples/${encodeURIComponent(selectedFile)}`, import.meta.url);
    const response = await fetch(sampleUrl);
    if (!response.ok) throw new Error(`Could not load sample capture "${selectedFile}".`);
    const parsed = parseCapture(await response.arrayBuffer());
    if (!parsed.packets.length) throw new Error(`Sample capture "${selectedFile}" has no supported packet blocks.`);
    setCapture(selectedFile, parsed);
  } catch (error) {
    showError(error instanceof Error ? error.message : "Unable to load the sample capture.");
  }
}

elements.fileInput.addEventListener("change", event => {
  loadFile(event.target.files?.[0]);
  event.target.value = "";
});
elements.sampleSelect.addEventListener("change", event => {
  const fileName = event.target.value;
  event.target.value = "";
  if (fileName) loadSample(fileName);
});
elements.welcomeSample.addEventListener("click", () => loadSample());
elements.aboutButton.addEventListener("click", async () => {
  elements.aboutDialog.showModal();
  if (aboutLoaded) return;

  elements.aboutContent.textContent = "Loading README.md…";
  try {
    const response = await fetch(new URL("./README.md", import.meta.url));
    if (!response.ok) throw new Error(`Could not load README.md (HTTP ${response.status}).`);
    elements.aboutContent.textContent = await response.text();
    aboutLoaded = true;
  } catch (error) {
    elements.aboutContent.textContent = error instanceof Error
      ? `Unable to load README.md: ${error.message}`
      : "Unable to load README.md.";
  }
});
elements.aboutClose.addEventListener("click", () => elements.aboutDialog.close());
samplesReady = loadSamples();
loadSampleFromUrl();
document.querySelector("#change-capture").addEventListener("click", () => elements.fileInput.click());
elements.filter.addEventListener("input", () => {
  document.querySelectorAll(".filter-chip").forEach(chip => chip.classList.toggle("active", chip.dataset.filter === elements.filter.value.trim().toLowerCase()));
  renderPackets();
});
elements.filter.addEventListener("keydown", event => {
  if (event.key === "Enter") renderPackets();
});
elements.clearFilter.addEventListener("click", () => {
  elements.filter.value = "";
  document.querySelectorAll(".filter-chip").forEach(chip => chip.classList.toggle("active", chip.dataset.filter === ""));
  renderPackets();
});
document.querySelectorAll(".filter-chip").forEach(chip => chip.addEventListener("click", () => {
  elements.filter.value = chip.dataset.filter;
  document.querySelectorAll(".filter-chip").forEach(item => item.classList.toggle("active", item === chip));
  renderPackets();
}));

for (const eventName of ["dragenter", "dragover"]) {
  window.addEventListener(eventName, event => {
    event.preventDefault();
    document.body.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  window.addEventListener(eventName, event => {
    event.preventDefault();
    document.body.classList.remove("dragging");
    if (eventName === "drop") loadFile(event.dataTransfer?.files?.[0]);
  });
}
