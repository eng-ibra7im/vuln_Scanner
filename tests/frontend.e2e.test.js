const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { JSDOM } = require("jsdom");

const ROOT = path.resolve(__dirname, "..");
const HTML_PATH = path.join(ROOT, "web", "web_interface.html");
const JS_PATH = path.join(ROOT, "web", "main.js");

class MockEventSource {
  static instances = [];

  constructor(url) {
    this.url = url;
    this.listeners = new Map();
    MockEventSource.instances.push(this);
  }

  addEventListener(eventName, callback) {
    const list = this.listeners.get(eventName) || [];
    list.push(callback);
    this.listeners.set(eventName, list);
  }

  close() {
    this.closed = true;
  }

  emit(eventName, payload) {
    const callbacks = this.listeners.get(eventName) || [];
    for (const callback of callbacks) {
      callback({ data: JSON.stringify(payload) });
    }
  }
}

function tick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function createBaseFetchMock(overrides = {}) {
  const counters = new Map();

  return async function fetch(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const key = `${method} ${url}`;
    const counter = (counters.get(key) || 0) + 1;
    counters.set(key, counter);

    const defaultResponses = {
      "GET http://localhost:5000/api/health": { status: "healthy" },
      "GET http://localhost:5000/api/stats": {
        success: true,
        statistics: { total_scans: 0 },
      },
      "GET http://localhost:5000/api/xss/stats": {
        success: true,
        statistics: { total_scans: 0, total_findings: 0, critical_findings: 0, high_findings: 0 },
      },
      "GET http://localhost:5000/api/sqli/stats": {
        success: true,
        statistics: { total_scans: 0, total_findings: 0, critical_findings: 0, high_findings: 0 },
      },
      "GET http://localhost:5000/api/tools": { success: true, tools: [] },
      "GET http://localhost:5000/api/xss/tools": { success: true, tools: [] },
      "GET http://localhost:5000/api/sqli/tools": { success: true, tools: [] },
      "GET http://localhost:5000/api/profiles": {
        success: true,
        default: "standard",
        profiles: [
          { id: "quick", label: "Quick", description: "Fast" },
          { id: "standard", label: "Standard", description: "Balanced" },
          { id: "deep", label: "Deep", description: "Thorough" },
        ],
      },
      "GET http://localhost:5000/api/tool-health": {
        success: true,
        summary: { installed: 1, tools: 1 },
        modules: {
          subdomains: [
            {
              name: "subfinder",
              installed: true,
              version: "1.0.0",
              path: "/usr/bin/subfinder",
            },
          ],
        },
      },
      "POST http://localhost:5000/api/recommendations/summary": {
        success: false,
        error: "No completed scans available yet.",
      },
    };

    let payload = overrides[key];
    if (typeof payload === "function") {
      payload = payload(counter, options);
    }
    if (payload === undefined) {
      payload = defaultResponses[key];
    }
    if (payload === undefined) {
      throw new Error(`Unhandled fetch: ${key}`);
    }

    return {
      ok: true,
      async json() {
        return payload;
      },
    };
  };
}

async function setupDom({ fetchImpl, useEventSource = true } = {}) {
  MockEventSource.instances.length = 0;
  const html = fs.readFileSync(HTML_PATH, "utf8");
  const dom = new JSDOM(html, {
    url: "http://localhost:5000",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });

  const { window } = dom;
  const intervalCallbacks = [];

  window.fetch = fetchImpl;
  window.console = console;
  window.Chart = function Chart() {
    return {};
  };
  window.jspdf = {
    jsPDF: function jsPDF() {
      return {
        setFontSize() {},
        setTextColor() {},
        text() {},
        autoTable() {},
        save() {},
      };
    },
  };
  window.EventSource = useEventSource ? MockEventSource : undefined;
  window.setInterval = (callback) => {
    intervalCallbacks.push(callback);
    return intervalCallbacks.length - 1;
  };
  window.clearInterval = () => {};

  const script = fs.readFileSync(JS_PATH, "utf8");
  window.eval(script);
  window.document.dispatchEvent(new window.Event("DOMContentLoaded"));
  await tick();

  return { window, document: window.document, intervalCallbacks };
}

test("subdomain form uses SSE and renders results", async () => {
  const fetchImpl = createBaseFetchMock({
    "POST http://localhost:5000/api/scan": {
      success: true,
      job_id: "job-subdomains-1",
      event_url: "/api/scan/job-subdomains-1/events",
      results_url: "/api/scan/job-subdomains-1/results",
    },
    "GET http://localhost:5000/api/scan/job-subdomains-1/results": {
      success: true,
      results: {
        summary: { total_findings: 1, severity: { high: 1 } },
        subdomains: [
          {
            subdomain: "admin.example.com",
            priority: "high",
            status: "active",
            dns_records: { ip_addresses: ["127.0.0.1"] },
          },
        ],
      },
    },
  });

  const { document, window } = await setupDom({ fetchImpl, useEventSource: true });
  document.getElementById("subdomainInput").value = "example.com";
  document.getElementById("tool-subfinder").checked = true;
  document.getElementById("subdomainForm").dispatchEvent(
    new window.Event("submit", { bubbles: true, cancelable: true }),
  );
  await tick();

  const stream = MockEventSource.instances.at(-1);
  assert.ok(stream);
  stream.emit("progress", { progress: 55 });
  await tick();
  assert.match(document.getElementById("subdomain-loader").textContent, /55%/);

  stream.emit("completed", {});
  await tick();
  await tick();

  const rows = document.querySelectorAll("#subResultsTable tbody tr");
  assert.equal(rows.length, 1);
  assert.match(rows[0].textContent, /admin\.example\.com/);
});

test("path discovery falls back to polling and renders results", async () => {
  const fetchImpl = createBaseFetchMock({
    "POST http://localhost:5000/api/path/scan": {
      success: true,
      job_id: "job-path-1",
    },
    "GET http://localhost:5000/api/path/scan/job-path-1": (count) =>
      count === 1
        ? { success: true, job: { status: "running", progress: 25 } }
        : { success: true, job: { status: "completed", progress: 100 } },
    "GET http://localhost:5000/api/path/scan/job-path-1/results": {
      success: true,
      results: {
        summary: {
          total_findings: 1,
          severity: { high: 1 },
          module_metrics: {
            paths: { total: 1 },
            parameters: { total: 1 },
          },
        },
        discovered_paths: [
          {
            url: "https://example.com/admin",
            path: "/admin",
            status_code: 200,
            risk_level: "high",
            discovery_tool: "ffuf",
          },
        ],
        discovered_parameters: [
          {
            url: "https://example.com/search?q=test",
            parameter: "q",
            method: "GET",
            discovery_tool: "arjun",
            potential_vuln: ["XSS"],
          },
        ],
        interesting_findings: {},
      },
    },
  });

  const { document, window, intervalCallbacks } = await setupDom({
    fetchImpl,
    useEventSource: false,
  });

  document.getElementById("pathUrlInput").value = "https://example.com";
  document.getElementById("pt-ffuf").checked = true;
  document.getElementById("pathForm").dispatchEvent(
    new window.Event("submit", { bubbles: true, cancelable: true }),
  );
  await tick();

  assert.equal(intervalCallbacks.length, 1);
  await intervalCallbacks[0]();
  await tick();
  await intervalCallbacks[0]();
  await tick();

  const rows = document.querySelectorAll("#pathResultsTable tbody tr");
  assert.equal(rows.length, 2);
  assert.match(document.querySelector("#path-results").textContent, /admin/);
});
