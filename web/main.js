/**
 * SecOps Orchestrator Dashboard - Main JavaScript
 * Professional Web Interface for Vulnerability Scanner
 */

// =============================================
// Configuration
// =============================================
const API_BASE_URL =
  window.location.port === "5000"
    ? `${window.location.protocol}//${window.location.hostname}:5000/api`
    : "http://localhost:5000/api";

// =============================================
// State Management
// =============================================
let currentScanJobId = null;
let scanPollInterval = null;
let subdomainResults = [];
let pathResults = [];
let statsData = {
  totalScans: 0,
  highSeverity: 0,
  subdomainsFound: 0,
  xssFindings: 0,
  sqliFindings: 0,
};

// Path Discovery Pagination State
let allDiscoveredPaths = [];
let allDiscoveredParams = [];
let pathCurrentPage = 1;
let pathPageSize = 25;
let pathTotalPages = 1;

// Subdomain Pagination State
let allSubdomains = [];
let originalSubdomains = [];
let subdomainCurrentPage = 1;
let subdomainPageSize = 25;
let subdomainTotalPages = 1;

// XSS Scanner State
let xssResults = [];
let allXSSFindings = [];
let xssCurrentPage = 1;
let xssPageSize = 25;
let xssTotalPages = 1;
let currentXSSJobId = null;
let xssPollInterval = null;

// SQL Injection Scanner State
let sqliResults = [];
let allSQLiFindings = [];
let sqliCurrentPage = 1;
let sqliPageSize = 50;
let sqliTotalPages = 1;
let currentSQLiJobId = null;
let sqliPollInterval = null;

// LFI Scanner State
let lfiResults = [];
let allLFIFindings = [];
let lfiCurrentPage = 1;
let lfiPageSize = 25;
let lfiTotalPages = 1;
let currentLFIJobId = null;
let lfiPollInterval = null;
let profileOptions = [];
const liveEventStreams = {};
const PROFILE_SELECT_MODULES = {
  subdomainProfile: "subdomains",
  pathProfile: "paths",
  xssProfile: "xss",
  sqliProfile: "sqli",
  lfiProfile: "lfi",
};

// =============================================
// Initialization
// =============================================
document.addEventListener("DOMContentLoaded", () => {
  initializeApp();
});

async function initializeApp() {
  console.log("🚀 Initializing SecOps Dashboard...");

  // Check API health
  await checkAPIHealth();

  // Load initial data
  await loadStats();
  await loadToolsConfig();
  await loadProfiles();
  await loadToolHealth();
  await loadRecommendationSummary();

  // Setup form handlers
  setupFormHandlers();

  // Initialize chart
  initializeChart();

  console.log("✅ Dashboard initialized successfully");
}

function absoluteApiUrl(path) {
  if (!path) return null;
  if (/^https?:\/\//i.test(path)) {
    return path;
  }
  return `${window.location.origin}${path}`;
}

function getSelectedProfile(selectId) {
  return document.getElementById(selectId)?.value || "standard";
}

function getProfilePresetTone(profileId) {
  if (profileId === "quick") return "Fast";
  if (profileId === "deep") return "Thorough";
  return "Balanced";
}

function buildProfileChips(profile, moduleName) {
  const moduleConfig = profile?.modules?.[moduleName] || {};
  const chips = [];
  const tools = Array.isArray(moduleConfig.tools) ? moduleConfig.tools : [];

  if (tools.length) {
    chips.push({
      icon: "fa-solid fa-screwdriver-wrench",
      label: `${tools.length} tools`,
    });
  }

  if (moduleConfig.parallel === true) {
    chips.push({
      icon: "fa-solid fa-bolt",
      label: "Parallel",
    });
  }

  if (moduleConfig.validate_dns === true) {
    chips.push({
      icon: "fa-solid fa-shield-check",
      label: "DNS validation",
    });
  }

  if (typeof moduleConfig.intensity === "string") {
    chips.push({
      icon: "fa-solid fa-gauge-high",
      label:
        moduleConfig.intensity === "aggressive"
          ? "Aggressive"
          : moduleConfig.intensity.charAt(0).toUpperCase() +
            moduleConfig.intensity.slice(1),
    });
  }

  if (moduleName === "lfi" && tools.includes("custom")) {
    chips.push({
      icon: "fa-solid fa-shield-halved",
      label: "Signature checks",
    });
  }

  return chips;
}

function renderProfileMeta(selectId) {
  const select = document.getElementById(selectId);
  const meta = document.getElementById(`${selectId}Meta`);
  const moduleName = PROFILE_SELECT_MODULES[selectId];

  if (!select || !meta || !moduleName) {
    return;
  }

  const fallbackProfile = {
    id: "standard",
    label: "Standard",
    description: "Balanced coverage for regular assessments.",
    modules: {},
  };
  const profile =
    profileOptions.find((item) => item.id === select.value) ||
    profileOptions.find((item) => item.id === "standard") ||
    fallbackProfile;

  meta.replaceChildren();

  const topRow = document.createElement("div");
  topRow.className = "profile-meta-top";

  const badge = document.createElement("span");
  badge.className = `profile-pill profile-pill-${profile.id || "standard"}`;
  badge.textContent = profile.label || "Standard";

  const mode = document.createElement("span");
  mode.className = "profile-meta-mode";
  mode.textContent = getProfilePresetTone(profile.id);

  topRow.appendChild(badge);
  topRow.appendChild(mode);

  const description = document.createElement("p");
  description.textContent =
    profile.description || "Balanced coverage for regular assessments.";

  const chipsWrap = document.createElement("div");
  chipsWrap.className = "profile-meta-chips";

  const chips = buildProfileChips(profile, moduleName);
  chips.forEach((chip) => {
    const item = document.createElement("span");
    item.className = "profile-meta-chip";

    const icon = document.createElement("i");
    icon.className = chip.icon;
    icon.setAttribute("aria-hidden", "true");

    const text = document.createElement("span");
    text.textContent = chip.label;

    item.appendChild(icon);
    item.appendChild(text);
    chipsWrap.appendChild(item);
  });

  meta.appendChild(topRow);
  meta.appendChild(description);
  meta.appendChild(chipsWrap);
}

function bindProfileSelectors() {
  Object.keys(PROFILE_SELECT_MODULES).forEach((selectId) => {
    const select = document.getElementById(selectId);
    if (!select || select.dataset.profileBound === "true") {
      return;
    }

    select.addEventListener("change", () => renderProfileMeta(selectId));
    select.dataset.profileBound = "true";
  });
}

function refreshProfileMeta() {
  Object.keys(PROFILE_SELECT_MODULES).forEach((selectId) => {
    renderProfileMeta(selectId);
  });
}

function updateLoaderProgress(loaderId, progress, message = "") {
  const loader = document.getElementById(loaderId);
  if (!loader) return;

  const textNode = loader.querySelector("p");
  if (textNode) {
    textNode.textContent = message
      ? `${message} (${progress}%)`
      : `${progress}%`;
  }
}

function closeLiveStream(streamKey) {
  const stream = liveEventStreams[streamKey];
  if (stream) {
    stream.close();
    delete liveEventStreams[streamKey];
  }
}

function monitorJobLive({
  streamKey,
  eventUrl,
  resultsUrl,
  onProgress,
  onComplete,
  onFailed,
  fallbackPoll,
}) {
  closeLiveStream(streamKey);

  if (!window.EventSource || !eventUrl) {
    if (typeof fallbackPoll === "function") {
      fallbackPoll();
    }
    return;
  }

  const source = new EventSource(absoluteApiUrl(eventUrl));
  liveEventStreams[streamKey] = source;

  source.addEventListener("progress", (event) => {
    const payload = JSON.parse(event.data || "{}");
    if (typeof onProgress === "function") {
      onProgress(payload);
    }
  });

  source.addEventListener("completed", async () => {
    closeLiveStream(streamKey);
    try {
      const response = await fetch(absoluteApiUrl(resultsUrl));
      const data = await response.json();
      if (data.success && typeof onComplete === "function") {
        onComplete(data.results);
      } else if (typeof onFailed === "function") {
        onFailed(data.error || "Failed to load scan results");
      }
    } catch (error) {
      if (typeof onFailed === "function") {
        onFailed(error.message || "Failed to load scan results");
      }
    }
  });

  source.addEventListener("failed", (event) => {
    closeLiveStream(streamKey);
    const payload = JSON.parse(event.data || "{}");
    if (typeof onFailed === "function") {
      onFailed(payload.error || payload.job?.error || "Scan failed");
    }
  });

  source.onerror = () => {
    closeLiveStream(streamKey);
    if (typeof fallbackPoll === "function") {
      fallbackPoll();
    }
  };
}

// =============================================
// API Health Check
// =============================================
async function checkAPIHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    const data = await response.json();

    if (data.status === "healthy") {
      updateStatusBadge(true, "Systems Operational");
      console.log("✅ API is healthy:", data);
    } else {
      updateStatusBadge(false, "API Issue Detected");
    }
  } catch (error) {
    console.error("❌ API health check failed:", error);
    updateStatusBadge(false, "API Offline");
    showNotification(
      "Unable to connect to API server. Make sure the backend is running.",
      "error",
    );
  }
}

function updateStatusBadge(isHealthy, text) {
  const badge = document.querySelector(".status-badge");
  if (badge) {
    badge.innerHTML = `
            <div class="pulse" style="background-color: ${isHealthy ? "#3b82f6" : "#ef4444"}"></div>
            ${text}
        `;
    badge.style.background = isHealthy ? "#dbeafe" : "#fee2e2";
    badge.style.color = isHealthy ? "#1e40af" : "#991b1b";
  }
}

// =============================================
// Load Statistics
// =============================================
async function loadStats() {
  try {
    // Load subdomain/path stats
    const response = await fetch(`${API_BASE_URL}/stats`);
    const data = await response.json();

    if (data.success) {
      statsData.totalScans = data.statistics.total_scans;
    }
  } catch (error) {
    console.error("Failed to load stats:", error);
  }

  // Load XSS stats to enrich dashboard
  try {
    const xssResponse = await fetch(`${API_BASE_URL}/xss/stats`);
    const xssData = await xssResponse.json();

    if (xssData.success) {
      statsData.totalScans += xssData.statistics.total_scans || 0;
      statsData.highSeverity +=
        (xssData.statistics.critical_findings || 0) +
        (xssData.statistics.high_findings || 0);
      statsData.xssFindings = xssData.statistics.total_findings || 0;
    }
  } catch (error) {
    console.error("Failed to load XSS stats:", error);
  }

  // Load SQL Injection stats to enrich dashboard
  try {
    const sqliResponse = await fetch(`${API_BASE_URL}/sqli/stats`);
    const sqliData = await sqliResponse.json();

    if (sqliData.success) {
      statsData.totalScans += sqliData.statistics.total_scans || 0;
      statsData.highSeverity +=
        (sqliData.statistics.critical_findings || 0) +
        (sqliData.statistics.high_findings || 0);
      statsData.sqliFindings = sqliData.statistics.total_findings || 0;
    }
  } catch (error) {
    console.error("Failed to load SQL Injection stats:", error);
  }

  updateStatsDisplay();
}

function updateStatsDisplay() {
  const statCards = document.querySelectorAll(".stat-value");
  if (statCards.length >= 3) {
    statCards[0].textContent = statsData.totalScans;
    statCards[1].textContent = statsData.highSeverity;
    statCards[2].textContent = statsData.subdomainsFound.toLocaleString();
  }
  const xssEl = document.getElementById("stat-xss-findings");
  if (xssEl) {
    xssEl.textContent = statsData.xssFindings || 0;
  }
  const sqliEl = document.getElementById("stat-sqli-findings");
  if (sqliEl) {
    sqliEl.textContent = statsData.sqliFindings || 0;
  }
}

// =============================================
// Load Tools Configuration
// =============================================
async function loadToolsConfig() {
  try {
    const response = await fetch(`${API_BASE_URL}/tools`);
    const data = await response.json();

    if (data.success) {
      data.tools.forEach((tool) => {
        const checkbox = document.getElementById(`tool-${tool.name}`);
        if (checkbox) {
          checkbox.checked = tool.enabled;
        }
      });
    }
  } catch (error) {
    console.error("Failed to load tools config:", error);
  }

  // Load XSS tools dynamically
  await loadXSSToolsConfig();

  // Load SQLi tools dynamically
  await loadSQLiToolsConfig();
}

async function loadProfiles() {
  try {
    const response = await fetch(`${API_BASE_URL}/profiles`);
    const data = await response.json();

    if (!data.success) return;

    profileOptions = data.profiles || [];
    const targets = [
      "subdomainProfile",
      "pathProfile",
      "xssProfile",
      "sqliProfile",
      "lfiProfile",
    ];

    targets.forEach((selectId) => {
      const select = document.getElementById(selectId);
      if (!select) return;

      select.innerHTML = "";
      profileOptions.forEach((profile) => {
        const option = document.createElement("option");
        option.value = profile.id;
        option.textContent = profile.label;
        option.title = profile.description || profile.label;
        if (profile.id === (data.default || "standard")) {
          option.selected = true;
        }
        select.appendChild(option);
      });
    });

    bindProfileSelectors();
    refreshProfileMeta();
  } catch (error) {
    console.error("Failed to load profiles:", error);
    bindProfileSelectors();
    refreshProfileMeta();
  }
}

async function loadToolHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/tool-health`);
    const data = await response.json();
    if (!data.success) return;

    const tbody = document.querySelector("#toolHealthTable tbody");
    const summary = document.getElementById("tool-health-summary");
    if (summary && data.summary) {
      summary.textContent = `${data.summary.installed}/${data.summary.tools} tools installed`;
    }

    if (!tbody) return;
    tbody.innerHTML = "";

    Object.entries(data.modules || {}).forEach(([moduleName, tools]) => {
      tools.forEach((tool) => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${moduleName}</td>
          <td>${tool.name}</td>
          <td>${tool.installed ? "Installed" : "Missing"}</td>
          <td>${tool.version || "Unknown"}</td>
          <td><code>${tool.path || "-"}</code></td>
        `;
        tbody.appendChild(row);
      });
    });
  } catch (error) {
    console.error("Failed to load tool health:", error);
  }
}

async function loadRecommendationSummary() {
  const container = document.getElementById("recommendation-summary-content");
  if (container) {
    container.textContent = "Generating summary...";
  }

  try {
    const response = await fetch(`${API_BASE_URL}/recommendations/summary`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    const data = await response.json();

    if (!data.success) {
      if (container) {
        container.textContent =
          data.error || "No completed scans available yet.";
      }
      return;
    }

    const summary = data.summary || {};
    const recommendations = summary.recommendations || [];
    const topFindings = summary.top_findings || [];

    if (container) {
      container.innerHTML = `
        <p><strong>${summary.headline || "Summary unavailable"}</strong></p>
        <p>Risk posture: ${(summary.risk_posture || "info").toUpperCase()}</p>
        <p>Total findings: ${summary.summary?.total_findings || 0}</p>
        <ul>
          ${recommendations
            .slice(0, 5)
            .map(
              (item) =>
                `<li>[${(item.priority || "info").toUpperCase()}] ${item.title} (${item.module || "combined"})</li>`,
            )
            .join("")}
        </ul>
        <p>Top findings tracked: ${topFindings.length}</p>
      `;
    }
  } catch (error) {
    if (container) {
      container.textContent = "Failed to generate unified summary.";
    }
    console.error("Failed to load recommendation summary:", error);
  }
}

async function loadXSSToolsConfig() {
  try {
    const response = await fetch(`${API_BASE_URL}/xss/tools`);
    const data = await response.json();

    if (data.success && data.tools) {
      const toolsGrid = document.getElementById("xss-tools-grid");
      if (toolsGrid) {
        toolsGrid.innerHTML = "";
        data.tools.forEach((tool) => {
          const div = document.createElement("div");
          div.className = "tool-check";
          const isReady = tool.installed && tool.enabled;
          const statusIcon = tool.installed
            ? '<i class="fa-solid fa-circle-check" style="color:#16a34a;margin-left:4px;font-size:0.7rem"></i>'
            : '<i class="fa-solid fa-circle-xmark" style="color:#dc2626;margin-left:4px;font-size:0.7rem"></i>';
          div.innerHTML = `
            <input type="checkbox" id="xss-${tool.name}" ${isReady ? "checked" : ""} ${!tool.installed ? "disabled" : ""}>
            <label for="xss-${tool.name}" ${!tool.installed ? 'style="opacity:0.5"' : ""}>
              ${tool.name.charAt(0).toUpperCase() + tool.name.slice(1)} ${statusIcon}
            </label>
          `;
          toolsGrid.appendChild(div);
        });
      }
    }
  } catch (error) {
    console.error("Failed to load XSS tools config:", error);
  }
}

async function loadSQLiToolsConfig() {
  try {
    const response = await fetch(`${API_BASE_URL}/sqli/tools`);
    const data = await response.json();

    if (data.success && data.tools) {
      const toolsGrid = document.getElementById("sqli-tools-grid");
      if (toolsGrid) {
        toolsGrid.innerHTML = "";
        data.tools.forEach((tool) => {
          const div = document.createElement("div");
          div.className = "tool-check";
          const isReady = tool.installed && tool.enabled;
          const statusIcon = tool.installed
            ? '<i class="fa-solid fa-circle-check" style="color:#16a34a;margin-left:4px;font-size:0.7rem"></i>'
            : '<i class="fa-solid fa-circle-xmark" style="color:#dc2626;margin-left:4px;font-size:0.7rem"></i>';
          div.innerHTML = `
            <input type="checkbox" id="sqli-${tool.name}" ${isReady ? "checked" : ""} ${!tool.installed ? "disabled" : ""}>
            <label for="sqli-${tool.name}" ${!tool.installed ? 'style="opacity:0.5"' : ""}>
              <span class="tool-name">${tool.name.charAt(0).toUpperCase() + tool.name.slice(1)}</span>
              <span class="tool-desc">${tool.description || ""}</span>
              ${statusIcon}
            </label>
          `;
          toolsGrid.appendChild(div);
        });
      }
    }
  } catch (error) {
    console.error("Failed to load SQLi tools config:", error);
  }
}

// =============================================
// Form Handlers
// =============================================
function setupFormHandlers() {
  // Subdomain scan form
  const subdomainForm = document.getElementById("subdomainForm");
  if (subdomainForm) {
    subdomainForm.addEventListener("submit", handleSubdomainScan);
  }

  // Path discovery form
  const pathForm = document.getElementById("pathForm");
  if (pathForm) {
    pathForm.addEventListener("submit", handlePathDiscovery);
  }

  // XSS scanner form
  const xssForm = document.getElementById("xssForm");
  if (xssForm) {
    xssForm.addEventListener("submit", handleXSSScan);
  }

  // SQL Injection scanner form
  const sqliForm = document.getElementById("sqliForm");
  if (sqliForm) {
    sqliForm.addEventListener("submit", handleSQLiScan);
  }

  // LFI scanner form
  const lfiForm = document.getElementById("lfiForm");
  if (lfiForm) {
    lfiForm.addEventListener("submit", handleLFIScan);
  }
}

// =============================================
// Subdomain Scanning
// =============================================
async function handleSubdomainScan(event) {
  event.preventDefault();

  const domainInput = document.getElementById("subdomainInput");
  const domain = domainInput.value.trim();

  if (!domain) {
    showNotification("Please enter a domain", "error");
    return;
  }

  // Validate domain format
  if (!isValidDomain(domain)) {
    showNotification(
      "Please enter a valid domain (e.g., example.com)",
      "error",
    );
    return;
  }

  // Get selected tools
  const selectedTools = getSelectedTools();

  if (selectedTools.length === 0) {
    showNotification("Please select at least one scanning tool", "error");
    return;
  }

  // Show loader
  showLoader("subdomain-loader");
  disableForm("subdomainForm");

  try {
    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        domain: domain,
        tools: selectedTools,
        profile: getSelectedProfile("subdomainProfile"),
        parallel: true,
        validate_dns: true,
      }),
    });

    const data = await response.json();

    if (data.success) {
      currentScanJobId = data.job_id;
      showNotification(`Scan started for ${domain}`, "success");
      monitorJobLive({
        streamKey: "subdomains",
        eventUrl: data.event_url,
        resultsUrl: data.results_url,
        onProgress: (payload) => {
          updateLoaderProgress(
            "subdomain-loader",
            payload.progress || 0,
            "Running subdomain scan",
          );
        },
        onComplete: (results) => {
          hideLoader("subdomain-loader");
          enableForm("subdomainForm");
          subdomainResults = results.subdomains || [];
          displaySubdomainResults(results);
          statsData.subdomainsFound += subdomainResults.length;
          statsData.highSeverity += results.summary?.severity?.high || 0;
          statsData.totalScans++;
          updateStatsDisplay();
          showNotification(
            `Scan completed! Found ${subdomainResults.length} subdomains`,
            "success",
          );
        },
        onFailed: (errorMessage) => {
          hideLoader("subdomain-loader");
          enableForm("subdomainForm");
          showNotification(`Scan failed: ${errorMessage}`, "error");
        },
        fallbackPoll: () => startPolling(data.job_id),
      });
    } else {
      throw new Error(data.error || "Failed to start scan");
    }
  } catch (error) {
    console.error("Scan error:", error);
    showNotification(`Scan failed: ${error.message}`, "error");
    hideLoader("subdomain-loader");
    enableForm("subdomainForm");
  }
}

function getSelectedTools() {
  const tools = [];
  const toolCheckboxes = document.querySelectorAll(
    '.tool-check input[type="checkbox"]',
  );

  toolCheckboxes.forEach((checkbox) => {
    if (checkbox.checked) {
      // Extract tool name from ID (e.g., "tool-subfinder" -> "subfinder")
      const toolName = checkbox.id.replace("tool-", "");
      tools.push(toolName);
    }
  });

  return tools;
}

function startPolling(jobId) {
  // Clear any existing interval
  if (scanPollInterval) {
    clearInterval(scanPollInterval);
  }

  // Poll every 2 seconds
  scanPollInterval = setInterval(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/scan/${jobId}`);
      const data = await response.json();

      if (data.success) {
        const job = data.job;

        if (job.status === "completed") {
          clearInterval(scanPollInterval);
          await fetchScanResults(jobId);
        } else if (job.status === "failed") {
          clearInterval(scanPollInterval);
          showNotification(
            `Scan failed: ${job.error || "Unknown error"}`,
            "error",
          );
          hideLoader("subdomain-loader");
          enableForm("subdomainForm");
        }
        // Still running - continue polling
      }
    } catch (error) {
      console.error("Polling error:", error);
    }
  }, 2000);
}

async function fetchScanResults(jobId) {
  try {
    const response = await fetch(`${API_BASE_URL}/scan/${jobId}/results`);
    const data = await response.json();

    if (data.success && data.results) {
      subdomainResults = data.results.subdomains || [];
      displaySubdomainResults(data.results);

      // Update stats
      statsData.subdomainsFound += subdomainResults.length;
      statsData.highSeverity += data.results.summary?.severity?.high || 0;
      statsData.totalScans++;
      updateStatsDisplay();

      showNotification(
        `Scan completed! Found ${subdomainResults.length} subdomains`,
        "success",
      );
    }
  } catch (error) {
    console.error("Failed to fetch results:", error);
    showNotification("Failed to fetch scan results", "error");
  } finally {
    hideLoader("subdomain-loader");
    enableForm("subdomainForm");
  }
}

function displaySubdomainResults(results) {
  const resultsCard = document.getElementById("subdomain-results");
  const foundBadge = document.querySelector(".badge-found");

  // Store all subdomains for pagination
  allSubdomains = results.subdomains || [];
  originalSubdomains = [...allSubdomains];
  subdomainResults = allSubdomains;

  // Update found count
  if (foundBadge) {
    foundBadge.textContent = `${allSubdomains.length} Found`;
  }

  // Clear search input
  const searchInput = document.getElementById("subdomainSearch");
  if (searchInput) searchInput.value = "";

  // Reset to first page
  subdomainCurrentPage = 1;
  subdomainPageSize = parseInt(
    document.getElementById("subdomainPageSize")?.value || 50,
  );

  // Render paginated results
  renderSubdomainPage();

  // Show results card
  if (resultsCard) {
    resultsCard.classList.remove("hidden");
  }

  loadRecommendationSummary();
}

function renderSubdomainPage() {
  const tableBody = document.querySelector("#subResultsTable tbody");
  if (!tableBody) return;

  // Clear existing results
  tableBody.innerHTML = "";

  const totalItems = allSubdomains.length;
  subdomainTotalPages = Math.ceil(totalItems / subdomainPageSize) || 1;

  // Calculate slice indices
  const startIndex = (subdomainCurrentPage - 1) * subdomainPageSize;
  const endIndex = Math.min(startIndex + subdomainPageSize, totalItems);

  // Get current page items
  const pageItems = allSubdomains.slice(startIndex, endIndex);

  // Render items
  pageItems.forEach((sub, index) => {
    const row = document.createElement("tr");
    row.style.animationDelay = `${index * 0.02}s`;

    const priorityClass = getPriorityClass(sub.priority);
    const ips = sub.dns_records?.ip_addresses?.join(", ") || "N/A";
    const status = sub.status || "unknown";

    row.innerHTML = `
      <td><code>${sub.subdomain}</code></td>
      <td><span class="badge ${priorityClass}">${sub.priority || "medium"}</span></td>
      <td>${ips}</td>
      <td><span class="${status === "active" ? "success-message" : "error-message"}">${status}</span></td>
    `;

    tableBody.appendChild(row);
  });

  // Update pagination controls
  updateSubdomainPagination(startIndex + 1, endIndex, totalItems);
}

function updateSubdomainPagination(start, end, total) {
  // Update info text
  const infoEl = document.getElementById("subdomainPaginationInfo");
  if (infoEl) {
    infoEl.textContent = `Showing ${total > 0 ? start : 0}-${end} of ${total} results`;
  }

  // Update prev/next buttons
  const prevBtn = document.getElementById("subdomainPrevBtn");
  const nextBtn = document.getElementById("subdomainNextBtn");

  if (prevBtn) prevBtn.disabled = subdomainCurrentPage <= 1;
  if (nextBtn) nextBtn.disabled = subdomainCurrentPage >= subdomainTotalPages;

  // Update page numbers
  renderSubdomainPageNumbers();
}

function renderSubdomainPageNumbers() {
  const container = document.getElementById("subdomainPageNumbers");
  if (!container) return;

  container.innerHTML = "";

  // Calculate visible page range
  const maxVisiblePages = 5;
  let startPage = Math.max(
    1,
    subdomainCurrentPage - Math.floor(maxVisiblePages / 2),
  );
  let endPage = Math.min(subdomainTotalPages, startPage + maxVisiblePages - 1);

  if (endPage - startPage < maxVisiblePages - 1) {
    startPage = Math.max(1, endPage - maxVisiblePages + 1);
  }

  // First page
  if (startPage > 1) {
    container.appendChild(createSubdomainPageButton(1));
    if (startPage > 2) {
      const ellipsis = document.createElement("span");
      ellipsis.className = "pagination-ellipsis";
      ellipsis.textContent = "...";
      container.appendChild(ellipsis);
    }
  }

  // Middle pages
  for (let i = startPage; i <= endPage; i++) {
    container.appendChild(createSubdomainPageButton(i));
  }

  // Last page
  if (endPage < subdomainTotalPages) {
    if (endPage < subdomainTotalPages - 1) {
      const ellipsis = document.createElement("span");
      ellipsis.className = "pagination-ellipsis";
      ellipsis.textContent = "...";
      container.appendChild(ellipsis);
    }
    container.appendChild(createSubdomainPageButton(subdomainTotalPages));
  }
}

function createSubdomainPageButton(pageNum) {
  const btn = document.createElement("button");
  btn.className = `pagination-page-btn ${pageNum === subdomainCurrentPage ? "active" : ""}`;
  btn.textContent = pageNum;
  btn.onclick = () => goToSubdomainPage(pageNum);
  return btn;
}

function changeSubdomainPage(delta) {
  const newPage = subdomainCurrentPage + delta;
  if (newPage >= 1 && newPage <= subdomainTotalPages) {
    subdomainCurrentPage = newPage;
    renderSubdomainPage();
  }
}

function goToSubdomainPage(pageNum) {
  if (pageNum >= 1 && pageNum <= subdomainTotalPages) {
    subdomainCurrentPage = pageNum;
    renderSubdomainPage();
  }
}

function changeSubdomainPageSize() {
  const select = document.getElementById("subdomainPageSize");
  if (select) {
    subdomainPageSize = parseInt(select.value);
    subdomainCurrentPage = 1;
    renderSubdomainPage();
  }
}

function getPriorityClass(priority) {
  switch (priority?.toLowerCase()) {
    case "high":
    case "critical":
      return "badge-high";
    case "medium":
      return "badge-medium";
    case "low":
      return "badge-low";
    default:
      return "badge-medium";
  }
}

// =============================================
// Path Discovery
// =============================================
let currentPathJobId = null;
let pathPollInterval = null;

async function handlePathDiscovery(event) {
  event.preventDefault();

  const urlInput = document.getElementById("pathUrlInput");
  const url = urlInput.value.trim();

  if (!url) {
    showNotification("Please enter a target URL", "error");
    return;
  }

  // Get selected tools
  const selectedPathTools = getSelectedPathTools();

  if (selectedPathTools.length === 0) {
    showNotification("Please select at least one discovery tool", "error");
    return;
  }

  showLoader("path-loader");
  disableForm("pathForm");

  try {
    const response = await fetch(`${API_BASE_URL}/path/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        tools: selectedPathTools,
        profile: getSelectedProfile("pathProfile"),
      }),
    });

    const data = await response.json();

    if (data.success) {
      currentPathJobId = data.job_id;
      showNotification(`Path discovery started for ${url}`, "success");
      monitorJobLive({
        streamKey: "paths",
        eventUrl: data.event_url,
        resultsUrl: data.results_url,
        onProgress: (payload) => {
          updateLoaderProgress(
            "path-loader",
            payload.progress || 0,
            "Discovering paths and parameters",
          );
        },
        onComplete: (results) => {
          hideLoader("path-loader");
          enableForm("pathForm");
          pathResults = results;
          displayPathResults(results);
          const metrics = results.summary?.module_metrics || {};
          const totalPaths = metrics.paths?.total || 0;
          const totalParams = metrics.parameters?.total || 0;
          showNotification(
            `Scan completed! Found ${totalPaths} paths and ${totalParams} parameters`,
            "success",
          );
        },
        onFailed: (errorMessage) => {
          hideLoader("path-loader");
          enableForm("pathForm");
          showNotification(`Path discovery failed: ${errorMessage}`, "error");
        },
        fallbackPoll: () => startPathPolling(data.job_id),
      });
    } else {
      throw new Error(data.error || "Failed to start path discovery");
    }
  } catch (error) {
    console.error("Path discovery error:", error);
    showNotification(`Path discovery failed: ${error.message}`, "error");
    hideLoader("path-loader");
    enableForm("pathForm");
  }
}

function getSelectedPathTools() {
  const tools = [];
  const toolMappings = {
    "pt-ffuf": "ffuf",
    "pt-dirsearch": "dirsearch",
    "pt-arjun": "arjun",
    "pt-paramspider": "paramspider",
  };

  Object.entries(toolMappings).forEach(([checkboxId, toolName]) => {
    const checkbox = document.getElementById(checkboxId);
    if (checkbox && checkbox.checked) {
      tools.push(toolName);
    }
  });

  return tools;
}

function startPathPolling(jobId) {
  // Clear any existing interval
  if (pathPollInterval) {
    clearInterval(pathPollInterval);
  }

  // Poll every 2 seconds
  pathPollInterval = setInterval(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/path/scan/${jobId}`);
      const data = await response.json();

      if (data.success) {
        const job = data.job;

        if (job.status === "completed") {
          clearInterval(pathPollInterval);
          await fetchPathResults(jobId);
        } else if (job.status === "failed") {
          clearInterval(pathPollInterval);
          showNotification(
            `Path discovery failed: ${job.error || "Unknown error"}`,
            "error",
          );
          hideLoader("path-loader");
          enableForm("pathForm");
        }
        // Still running - continue polling
      }
    } catch (error) {
      console.error("Path polling error:", error);
    }
  }, 2000);
}

async function fetchPathResults(jobId) {
  try {
    const response = await fetch(`${API_BASE_URL}/path/scan/${jobId}/results`);
    const data = await response.json();

    if (data.success && data.results) {
      pathResults = data.results;
      displayPathResults(data.results);

      const metrics = data.results.summary?.module_metrics || {};
      const totalPaths = metrics.paths?.total || 0;
      const totalParams = metrics.parameters?.total || 0;

      showNotification(
        `Scan completed! Found ${totalPaths} paths and ${totalParams} parameters`,
        "success",
      );
    }
  } catch (error) {
    console.error("Failed to fetch path results:", error);
    showNotification("Failed to fetch path discovery results", "error");
  } finally {
    hideLoader("path-loader");
    enableForm("pathForm");
  }
}

function displayPathResults(results) {
  const resultsCard = document.getElementById("path-results");
  const tableBody = document.querySelector("#pathResultsTable tbody");

  if (!tableBody) return;

  // Store all paths and parameters for pagination
  allDiscoveredPaths = results.discovered_paths || [];
  allDiscoveredParams = results.discovered_parameters || [];

  // Store original data for filtering
  originalDiscoveredPaths = [...allDiscoveredPaths];
  originalDiscoveredParams = [...allDiscoveredParams];

  // Clear search input
  const searchInput = document.getElementById("pathSearch");
  if (searchInput) searchInput.value = "";

  // Reset to first page
  pathCurrentPage = 1;
  pathPageSize = parseInt(document.getElementById("pathPageSize")?.value || 50);

  // Render paginated results
  renderPathPage();

  // Show results card
  if (resultsCard) {
    resultsCard.classList.remove("hidden");
  }

  // Show summary if available
  if (results.interesting_findings) {
    const findings = results.interesting_findings;
    const criticalCount = findings.critical_paths?.length || 0;
    const adminCount = findings.admin_panels?.length || 0;
    const vulnParamCount = findings.vulnerable_params?.length || 0;

    if (criticalCount > 0 || adminCount > 0 || vulnParamCount > 0) {
      showNotification(
        `⚠️ Found ${criticalCount} critical paths, ${adminCount} admin panels, ${vulnParamCount} vulnerable params`,
        "warning",
      );
    }
  }

  loadRecommendationSummary();
}

function renderPathPage() {
  const tableBody = document.querySelector("#pathResultsTable tbody");
  if (!tableBody) return;

  // Clear existing results
  tableBody.innerHTML = "";

  // Combine all items for pagination
  const allItems = [
    ...allDiscoveredPaths.map((p) => ({ type: "path", data: p })),
    ...allDiscoveredParams.map((p) => ({ type: "param", data: p })),
  ];

  const totalItems = allItems.length;
  pathTotalPages = Math.ceil(totalItems / pathPageSize) || 1;

  // Calculate slice indices
  const startIndex = (pathCurrentPage - 1) * pathPageSize;
  const endIndex = Math.min(startIndex + pathPageSize, totalItems);

  // Get current page items
  const pageItems = allItems.slice(startIndex, endIndex);

  // Render items
  pageItems.forEach((item, index) => {
    const row = document.createElement("tr");
    row.style.animationDelay = `${index * 0.02}s`;

    if (item.type === "path") {
      const path = item.data;
      const riskClass = getRiskClass(path.risk_level);
      const statusClass = getStatusClass(path.status_code);
      const fullUrl = path.url || `${path.path}`;

      row.innerHTML = `
        <td><code class="url-code"><a href="${fullUrl}" target="_blank" rel="noopener noreferrer">${fullUrl}</a></code></td>
        <td><span class="badge ${statusClass}">${path.status_code}</span></td>
        <td><span class="badge ${riskClass}">${path.risk_level || "info"}</span></td>
        <td>${path.discovery_tool}</td>
      `;
    } else {
      const param = item.data;
      const vulnClass =
        param.potential_vuln?.length > 0 ? "badge-high" : "badge-low";
      const vulnText =
        param.potential_vuln?.length > 0
          ? param.potential_vuln.join(", ")
          : "None";
      const paramUrl = param.url || `?${param.parameter}=`;

      row.innerHTML = `
        <td><code class="url-code">${paramUrl}</code></td>
        <td><span class="badge badge-medium">${param.method}</span></td>
        <td><span class="badge ${vulnClass}" title="${vulnText}">PARAM</span></td>
        <td>${param.discovery_tool}</td>
      `;
    }

    tableBody.appendChild(row);
  });

  // Update pagination controls
  updatePathPagination(startIndex + 1, endIndex, totalItems);
}

function updatePathPagination(start, end, total) {
  // Update info text
  const infoEl = document.getElementById("pathPaginationInfo");
  if (infoEl) {
    infoEl.textContent = `Showing ${total > 0 ? start : 0}-${end} of ${total} results`;
  }

  // Update prev/next buttons
  const prevBtn = document.getElementById("pathPrevBtn");
  const nextBtn = document.getElementById("pathNextBtn");

  if (prevBtn) prevBtn.disabled = pathCurrentPage <= 1;
  if (nextBtn) nextBtn.disabled = pathCurrentPage >= pathTotalPages;

  // Update page numbers
  renderPathPageNumbers();
}

function renderPathPageNumbers() {
  const container = document.getElementById("pathPageNumbers");
  if (!container) return;

  container.innerHTML = "";

  // Calculate visible page range
  const maxVisiblePages = 5;
  let startPage = Math.max(
    1,
    pathCurrentPage - Math.floor(maxVisiblePages / 2),
  );
  let endPage = Math.min(pathTotalPages, startPage + maxVisiblePages - 1);

  if (endPage - startPage < maxVisiblePages - 1) {
    startPage = Math.max(1, endPage - maxVisiblePages + 1);
  }

  // First page
  if (startPage > 1) {
    container.appendChild(createPageButton(1));
    if (startPage > 2) {
      const ellipsis = document.createElement("span");
      ellipsis.className = "pagination-ellipsis";
      ellipsis.textContent = "...";
      container.appendChild(ellipsis);
    }
  }

  // Middle pages
  for (let i = startPage; i <= endPage; i++) {
    container.appendChild(createPageButton(i));
  }

  // Last page
  if (endPage < pathTotalPages) {
    if (endPage < pathTotalPages - 1) {
      const ellipsis = document.createElement("span");
      ellipsis.className = "pagination-ellipsis";
      ellipsis.textContent = "...";
      container.appendChild(ellipsis);
    }
    container.appendChild(createPageButton(pathTotalPages));
  }
}

function createPageButton(pageNum) {
  const btn = document.createElement("button");
  btn.className = `pagination-page-btn ${pageNum === pathCurrentPage ? "active" : ""}`;
  btn.textContent = pageNum;
  btn.onclick = () => goToPathPage(pageNum);
  return btn;
}

function changePathPage(delta) {
  const newPage = pathCurrentPage + delta;
  if (newPage >= 1 && newPage <= pathTotalPages) {
    pathCurrentPage = newPage;
    renderPathPage();
  }
}

function goToPathPage(pageNum) {
  if (pageNum >= 1 && pageNum <= pathTotalPages) {
    pathCurrentPage = pageNum;
    renderPathPage();
  }
}

function changePathPageSize() {
  const select = document.getElementById("pathPageSize");
  if (select) {
    pathPageSize = parseInt(select.value);
    pathCurrentPage = 1;
    renderPathPage();
  }
}

function getRiskClass(risk) {
  switch (risk?.toLowerCase()) {
    case "critical":
      return "badge-critical";
    case "high":
      return "badge-high";
    case "medium":
      return "badge-medium";
    case "low":
      return "badge-low";
    default:
      return "badge-info";
  }
}

function getStatusClass(status) {
  if (status >= 200 && status < 300) return "badge-success";
  if (status >= 300 && status < 400) return "badge-medium";
  if (status >= 400 && status < 500) return "badge-high";
  if (status >= 500) return "badge-critical";
  return "badge-info";
}

// =============================================
// Tab Navigation
// =============================================
function switchTab(tabName) {
  // Update nav items
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.remove("active");
  });
  document.getElementById(`nav-${tabName}`)?.classList.add("active");

  // Update views
  document.querySelectorAll(".section-view").forEach((view) => {
    view.classList.remove("active");
  });
  document.getElementById(`view-${tabName}`)?.classList.add("active");

  // Update page title
  const titles = {
    dashboard: {
      h1: "Dashboard",
      desc: "System overview and recent activities",
    },
    subdomain: {
      h1: "Subdomain Scanner",
      desc: "Discover subdomains using multiple engines",
    },
    path: { h1: "Path Discovery", desc: "Find hidden paths and endpoints" },
    xss: {
      h1: "XSS Scanner",
      desc: "Detect Cross-Site Scripting vulnerabilities",
    },
    sqli: {
      h1: "SQL Injection Scanner",
      desc: "Detect SQL injection vulnerabilities using multiple tools",
    },
    lfi: {
      h1: "LFI Detection",
      desc: "Detect Local File Inclusion vulnerabilities",
    },
    "tool-health": {
      h1: "Tool Health",
      desc: "Installed tools, versions, and resolved executable paths",
    },
  };

  const titleData = titles[tabName];
  if (titleData) {
    document.getElementById("page-heading").textContent = titleData.h1;
    document.getElementById("page-desc").textContent = titleData.desc;
  }

  if (tabName === "tool-health") {
    loadToolHealth();
  }
}

// =============================================
// Utility Functions
// =============================================
function isValidDomain(domain) {
  const domainRegex =
    /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

function truncateText(text, maxLength) {
  if (!text) return "";
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + "...";
}

function getSeveritySummary(summary = {}) {
  const severity = summary.severity || {};
  const legacy = summary.module_metrics || summary;
  return {
    critical: severity.critical ?? legacy.critical ?? 0,
    high: severity.high ?? legacy.high ?? legacy.high_severity ?? 0,
    medium: severity.medium ?? legacy.medium ?? legacy.medium_severity ?? 0,
    low: severity.low ?? legacy.low ?? legacy.low_severity ?? 0,
    info: severity.info ?? legacy.info ?? 0,
    total: summary.total_findings ?? legacy.total_findings ?? 0,
  };
}

function getToolResultsList(toolResults) {
  if (Array.isArray(toolResults)) {
    return toolResults;
  }

  return Object.entries(toolResults || {}).map(([tool, details]) => ({
    tool,
    ...details,
  }));
}

function showLoader(loaderId) {
  const loader = document.getElementById(loaderId);
  if (loader) {
    loader.style.display = "block";
  }
}

function hideLoader(loaderId) {
  const loader = document.getElementById(loaderId);
  if (loader) {
    loader.style.display = "none";
  }
}

function disableForm(formId) {
  const form = document.getElementById(formId);
  if (form) {
    const button = form.querySelector('button[type="submit"]');
    if (button) {
      button.disabled = true;
    }
  }
}

function enableForm(formId) {
  const form = document.getElementById(formId);
  if (form) {
    const button = form.querySelector('button[type="submit"]');
    if (button) {
      button.disabled = false;
    }
  }
}

function showNotification(message, type = "success") {
  // Remove existing notifications
  document.querySelectorAll(".notification").forEach((n) => n.remove());

  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.innerHTML = `
        <i class="fa-solid ${type === "success" ? "fa-check-circle" : type === "error" ? "fa-exclamation-circle" : "fa-info-circle"}"></i>
        <span>${message}</span>
    `;

  document.body.appendChild(notification);

  // Auto remove after 5 seconds
  setTimeout(() => {
    notification.style.animation = "slideOutRight 0.3s ease forwards";
    setTimeout(() => notification.remove(), 300);
  }, 5000);
}

// =============================================
// Search & Filter Functions
// =============================================
function filterSubdomainResults() {
  const searchInput = document.getElementById("subdomainSearch");
  const searchTerm = searchInput?.value.toLowerCase() || "";

  if (!searchTerm) {
    // Restore original data
    allSubdomains = [...originalSubdomains];
  } else {
    // Filter subdomains
    allSubdomains = originalSubdomains.filter((sub) => {
      const subdomain = (sub.subdomain || "").toLowerCase();
      const ips = (
        sub.dns_records?.ip_addresses?.join(", ") || ""
      ).toLowerCase();
      return subdomain.includes(searchTerm) || ips.includes(searchTerm);
    });
  }

  // Reset to first page and re-render
  subdomainCurrentPage = 1;
  renderSubdomainPage();
}

// Store original data for filtering
let originalDiscoveredPaths = [];
let originalDiscoveredParams = [];

function filterPathResults() {
  const searchInput = document.getElementById("pathSearch");
  const searchTerm = searchInput?.value.toLowerCase() || "";

  if (!searchTerm) {
    // Restore original data
    allDiscoveredPaths = [...originalDiscoveredPaths];
    allDiscoveredParams = [...originalDiscoveredParams];
  } else {
    // Filter paths
    allDiscoveredPaths = originalDiscoveredPaths.filter((path) => {
      const url = (path.url || path.path || "").toLowerCase();
      return url.includes(searchTerm);
    });

    // Filter params
    allDiscoveredParams = originalDiscoveredParams.filter((param) => {
      const url = (param.url || param.parameter || "").toLowerCase();
      return url.includes(searchTerm);
    });
  }

  // Reset to first page and re-render
  pathCurrentPage = 1;
  renderPathPage();
}

// =============================================
// Export Functions
// =============================================
function exportSubdomainResults(format) {
  if (originalSubdomains.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  if (format === "json") {
    const exportData = {
      subdomains: originalSubdomains,
      exportDate: new Date().toISOString(),
      totalCount: originalSubdomains.length,
    };
    const dataStr = JSON.stringify(exportData, null, 2);
    downloadFile(dataStr, "subdomain_results.json", "application/json");
    showNotification("Results exported successfully", "success");
  }
}

function exportSubdomainResultsPDF() {
  if (originalSubdomains.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF("landscape", "mm", "a4");

  // Title
  doc.setFontSize(20);
  doc.setTextColor(79, 70, 229);
  doc.text("Subdomain Enumeration Report", 14, 20);

  // Subtitle with date
  doc.setFontSize(10);
  doc.setTextColor(100);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);

  // Summary
  doc.setFontSize(12);
  doc.setTextColor(0);
  doc.text(`Total Subdomains: ${originalSubdomains.length}`, 14, 38);

  // Count by priority
  const priorityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const statusCounts = { active: 0, inactive: 0, unknown: 0 };

  originalSubdomains.forEach((s) => {
    const priority = (s.priority || "medium").toLowerCase();
    const status = (s.status || "unknown").toLowerCase();
    if (priorityCounts[priority] !== undefined) priorityCounts[priority]++;
    if (statusCounts[status] !== undefined) statusCounts[status]++;
    else statusCounts.unknown++;
  });

  doc.text(
    `Priority - Critical: ${priorityCounts.critical}  |  High: ${priorityCounts.high}  |  Medium: ${priorityCounts.medium}  |  Low: ${priorityCounts.low}`,
    14,
    46,
  );
  doc.text(
    `Status - Active: ${statusCounts.active}  |  Inactive: ${statusCounts.inactive}  |  Unknown: ${statusCounts.unknown}`,
    14,
    54,
  );

  // Subdomains Table
  const subdomainsData = originalSubdomains.map((s) => [
    s.subdomain || "",
    (s.priority || "medium").toUpperCase(),
    s.dns_records?.ip_addresses?.join(", ") || "N/A",
    (s.status || "unknown").toUpperCase(),
    s.discovered_by?.join(", ") || "N/A",
  ]);

  doc.autoTable({
    startY: 62,
    head: [
      ["Subdomain", "Priority", "IP Addresses", "Status", "Discovered By"],
    ],
    body: subdomainsData,
    styles: {
      fontSize: 8,
      cellPadding: 2,
      overflow: "linebreak",
    },
    headStyles: {
      fillColor: [79, 70, 229],
      textColor: 255,
    },
    columnStyles: {
      0: { cellWidth: 80 },
      1: { cellWidth: 25, halign: "center" },
      2: { cellWidth: 50 },
      3: { cellWidth: 25, halign: "center" },
      4: { cellWidth: 50 },
    },
    alternateRowStyles: {
      fillColor: [245, 247, 250],
    },
    didParseCell: function (data) {
      if (data.section === "body" && data.column.index === 1) {
        const priority = data.cell.raw.toLowerCase();
        if (priority === "critical") {
          data.cell.styles.textColor = [153, 27, 27];
          data.cell.styles.fontStyle = "bold";
        } else if (priority === "high") {
          data.cell.styles.textColor = [220, 38, 38];
          data.cell.styles.fontStyle = "bold";
        } else if (priority === "medium") {
          data.cell.styles.textColor = [217, 119, 6];
        } else if (priority === "low") {
          data.cell.styles.textColor = [22, 163, 74];
        }
      }
      if (data.section === "body" && data.column.index === 3) {
        const status = data.cell.raw.toLowerCase();
        if (status === "active") {
          data.cell.styles.textColor = [22, 163, 74];
        } else if (status === "inactive") {
          data.cell.styles.textColor = [220, 38, 38];
        }
      }
    },
  });

  // Footer
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(
      `SecOps Orchestrator - Page ${i} of ${pageCount}`,
      doc.internal.pageSize.width / 2,
      doc.internal.pageSize.height - 10,
      { align: "center" },
    );
  }

  // Save
  const filename = `subdomain_enumeration_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  showNotification("PDF exported successfully", "success");
}

function exportPathResults(format) {
  if (allDiscoveredPaths.length === 0 && allDiscoveredParams.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  if (format === "json") {
    const exportData = {
      paths: originalDiscoveredPaths,
      parameters: originalDiscoveredParams,
      exportDate: new Date().toISOString(),
      totalPaths: originalDiscoveredPaths.length,
      totalParams: originalDiscoveredParams.length,
    };
    const dataStr = JSON.stringify(exportData, null, 2);
    downloadFile(dataStr, "path_results.json", "application/json");
    showNotification("Results exported successfully", "success");
  }
}

function exportPathResultsPDF() {
  if (
    originalDiscoveredPaths.length === 0 &&
    originalDiscoveredParams.length === 0
  ) {
    showNotification("No results to export", "error");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF("landscape", "mm", "a4");

  // Title
  doc.setFontSize(20);
  doc.setTextColor(79, 70, 229);
  doc.text("Path Discovery Report", 14, 20);

  // Subtitle with date
  doc.setFontSize(10);
  doc.setTextColor(100);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);

  // Summary
  doc.setFontSize(12);
  doc.setTextColor(0);
  doc.text(`Total Paths: ${originalDiscoveredPaths.length}`, 14, 38);
  doc.text(`Total Parameters: ${originalDiscoveredParams.length}`, 80, 38);

  // Count by risk level
  const riskCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  originalDiscoveredPaths.forEach((p) => {
    const risk = (p.risk_level || "info").toLowerCase();
    if (riskCounts[risk] !== undefined) riskCounts[risk]++;
  });

  doc.text(
    `Critical: ${riskCounts.critical}  |  High: ${riskCounts.high}  |  Medium: ${riskCounts.medium}  |  Low: ${riskCounts.low}  |  Info: ${riskCounts.info}`,
    14,
    46,
  );

  // Paths Table
  if (originalDiscoveredPaths.length > 0) {
    doc.setFontSize(14);
    doc.setTextColor(79, 70, 229);
    doc.text("Discovered Paths", 14, 56);

    const pathsData = originalDiscoveredPaths.map((p) => [
      p.url || p.path || "",
      p.status_code || "",
      (p.risk_level || "info").toUpperCase(),
      p.category || "",
      p.discovery_tool || "",
    ]);

    doc.autoTable({
      startY: 60,
      head: [["URL", "Status", "Risk", "Category", "Tool"]],
      body: pathsData,
      styles: {
        fontSize: 8,
        cellPadding: 2,
        overflow: "linebreak",
      },
      headStyles: {
        fillColor: [79, 70, 229],
        textColor: 255,
      },
      columnStyles: {
        0: { cellWidth: 120 },
        1: { cellWidth: 20, halign: "center" },
        2: { cellWidth: 20, halign: "center" },
        3: { cellWidth: 40 },
        4: { cellWidth: 30 },
      },
      alternateRowStyles: {
        fillColor: [245, 247, 250],
      },
      didParseCell: function (data) {
        if (data.section === "body" && data.column.index === 2) {
          const risk = data.cell.raw.toLowerCase();
          if (risk === "critical") {
            data.cell.styles.textColor = [153, 27, 27];
            data.cell.styles.fontStyle = "bold";
          } else if (risk === "high") {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = "bold";
          } else if (risk === "medium") {
            data.cell.styles.textColor = [217, 119, 6];
          } else if (risk === "low") {
            data.cell.styles.textColor = [22, 163, 74];
          }
        }
      },
    });
  }

  // Parameters Table (on new page if needed)
  if (originalDiscoveredParams.length > 0) {
    doc.addPage();
    doc.setFontSize(14);
    doc.setTextColor(79, 70, 229);
    doc.text("Discovered Parameters", 14, 20);

    const paramsData = originalDiscoveredParams.map((p) => [
      p.url || `?${p.parameter}=`,
      p.parameter || "",
      p.method || "",
      (p.potential_vuln || []).join(", ") || "None",
      p.discovery_tool || "",
    ]);

    doc.autoTable({
      startY: 25,
      head: [["URL", "Parameter", "Method", "Potential Vulns", "Tool"]],
      body: paramsData,
      styles: {
        fontSize: 8,
        cellPadding: 2,
        overflow: "linebreak",
      },
      headStyles: {
        fillColor: [236, 72, 153],
        textColor: 255,
      },
      alternateRowStyles: {
        fillColor: [245, 247, 250],
      },
    });
  }

  // Footer
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150);
    doc.text(
      `SecOps Orchestrator - Page ${i} of ${pageCount}`,
      doc.internal.pageSize.width / 2,
      doc.internal.pageSize.height - 10,
      { align: "center" },
    );
  }

  // Save
  const filename = `path_discovery_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  showNotification("PDF exported successfully", "success");
}

function downloadFile(content, filename, contentType) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================
// Clear Functions
// =============================================
function clearSubdomainResults() {
  subdomainResults = [];
  allSubdomains = [];
  originalSubdomains = [];
  subdomainCurrentPage = 1;

  const tableBody = document.querySelector("#subResultsTable tbody");
  if (tableBody) {
    tableBody.innerHTML = "";
  }

  // Reset pagination display
  const infoEl = document.getElementById("subdomainPaginationInfo");
  if (infoEl) infoEl.textContent = "Showing 0-0 of 0 results";

  const pageNumbers = document.getElementById("subdomainPageNumbers");
  if (pageNumbers) pageNumbers.innerHTML = "";

  const prevBtn = document.getElementById("subdomainPrevBtn");
  const nextBtn = document.getElementById("subdomainNextBtn");
  if (prevBtn) prevBtn.disabled = true;
  if (nextBtn) nextBtn.disabled = true;

  const foundBadge = document.querySelector(".badge-found");
  if (foundBadge) foundBadge.textContent = "0 Found";

  const resultsCard = document.getElementById("subdomain-results");
  if (resultsCard) {
    resultsCard.classList.add("hidden");
  }
  showNotification("Results cleared", "success");
}

function clearPathResults() {
  pathResults = [];
  allDiscoveredPaths = [];
  allDiscoveredParams = [];
  originalDiscoveredPaths = [];
  originalDiscoveredParams = [];
  pathCurrentPage = 1;

  const tableBody = document.querySelector("#pathResultsTable tbody");
  if (tableBody) {
    tableBody.innerHTML = "";
  }

  // Reset pagination display
  const infoEl = document.getElementById("pathPaginationInfo");
  if (infoEl) infoEl.textContent = "Showing 0-0 of 0 results";

  const pageNumbers = document.getElementById("pathPageNumbers");
  if (pageNumbers) pageNumbers.innerHTML = "";

  const prevBtn = document.getElementById("pathPrevBtn");
  const nextBtn = document.getElementById("pathNextBtn");
  if (prevBtn) prevBtn.disabled = true;
  if (nextBtn) nextBtn.disabled = true;

  const resultsCard = document.getElementById("path-results");
  if (resultsCard) {
    resultsCard.classList.add("hidden");
  }
  showNotification("Results cleared", "success");
}

// =============================================
// Chart Initialization
// =============================================
function initializeChart() {
  const ctx = document.getElementById("overviewChart");
  if (!ctx) return;

  new Chart(ctx, {
    type: "line",
    data: {
      labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      datasets: [
        {
          label: "Subdomains Found",
          data: [45, 72, 56, 89, 123, 98, 156],
          borderColor: "#4f46e5",
          backgroundColor: "rgba(79, 70, 229, 0.1)",
          fill: true,
          tension: 0.4,
        },
        {
          label: "High Priority",
          data: [5, 8, 12, 6, 15, 9, 18],
          borderColor: "#ec4899",
          backgroundColor: "rgba(236, 72, 153, 0.1)",
          fill: true,
          tension: 0.4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "bottom",
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: {
            color: "rgba(0, 0, 0, 0.05)",
          },
        },
        x: {
          grid: {
            display: false,
          },
        },
      },
    },
  });
}

// =============================================
// XSS Scanner Functions
// =============================================
async function handleXSSScan(event) {
  event.preventDefault();

  const urlInput = document.getElementById("xssUrlInput");
  const url = urlInput.value.trim();

  if (!url) {
    showNotification("Please enter a target URL", "error");
    return;
  }

  // Validate URL format
  if (!isValidURL(url)) {
    showNotification("Please enter a valid URL", "error");
    return;
  }

  // Get selected XSS tools
  const selectedTools = getSelectedXSSTools();

  if (selectedTools.length === 0) {
    showNotification("Please select at least one XSS detection tool", "error");
    return;
  }

  // Show loader
  showLoader("xss-loader");
  disableForm("xssForm");

  // Reset progress bar
  const progressBar = document.getElementById("xss-progress");
  const progressText = document.getElementById("xss-progress-text");
  if (progressBar) progressBar.style.width = "0%";
  if (progressText) progressText.textContent = "0%";

  try {
    const response = await fetch(`${API_BASE_URL}/xss/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        tools: selectedTools,
        profile: getSelectedProfile("xssProfile"),
        check_dom: true,
        follow_redirects: true,
      }),
    });

    const data = await response.json();

    if (data.success) {
      currentXSSJobId = data.job_id;
      showNotification(`XSS scan started for ${url}`, "success");
      monitorJobLive({
        streamKey: "xss",
        eventUrl: data.event_url,
        resultsUrl: data.results_url,
        onProgress: (payload) => {
          const progress = payload.progress || 0;
          const progressBar = document.getElementById("xss-progress");
          const progressText = document.getElementById("xss-progress-text");
          if (progressBar) progressBar.style.width = `${progress}%`;
          if (progressText) progressText.textContent = `${progress}%`;
          updateLoaderProgress("xss-loader", progress, "Running XSS scan");
        },
        onComplete: (results) => {
          hideLoader("xss-loader");
          enableForm("xssForm");
          displayXSSResults(results);
          showNotification(
            `XSS scan completed. Found ${results.findings?.length || 0} potential vulnerabilities.`,
            "success",
          );
        },
        onFailed: (errorMessage) => {
          hideLoader("xss-loader");
          enableForm("xssForm");
          showNotification(errorMessage, "error");
        },
        fallbackPoll: () => startXSSPollResults(),
      });
    } else {
      showNotification(data.message || "Failed to start XSS scan", "error");
      hideLoader("xss-loader");
      enableForm("xssForm");
    }
  } catch (error) {
    console.error("XSS scan error:", error);
    showNotification("Failed to connect to API server", "error");
    hideLoader("xss-loader");
    enableForm("xssForm");
  }
}

function getSelectedXSSTools() {
  const tools = [];
  const checkboxes = document.querySelectorAll(
    '#xss-tools-grid input[type="checkbox"]',
  );
  checkboxes.forEach((cb) => {
    if (cb.checked && !cb.disabled) {
      const toolName = cb.id.replace("xss-", "");
      tools.push(toolName);
    }
  });
  return tools;
}

function isValidURL(string) {
  try {
    const url = new URL(string);
    // Ensure it's http or https protocol
    if (!["http:", "https:"].includes(url.protocol)) {
      return false;
    }
    // Ensure there's a hostname
    if (!url.hostname || url.hostname.length === 0) {
      return false;
    }
    return true;
  } catch (_) {
    return false;
  }
}

function startXSSPollResults() {
  if (xssPollInterval) {
    clearInterval(xssPollInterval);
  }

  let pollCount = 0;
  const maxPolls = 300; // 10 minutes (300 * 2 seconds)

  xssPollInterval = setInterval(async () => {
    try {
      pollCount++;

      // Timeout after max polls
      if (pollCount > maxPolls) {
        clearInterval(xssPollInterval);
        xssPollInterval = null;
        hideLoader("xss-loader");
        enableForm("xssForm");
        showNotification(
          "XSS scan timeout. The scan is taking too long.",
          "error",
        );
        return;
      }

      const response = await fetch(
        `${API_BASE_URL}/xss/scan/${currentXSSJobId}`,
      );
      const data = await response.json();

      if (data.success && data.job) {
        // Update progress if available
        if (data.job.progress !== undefined) {
          const progressBar = document.getElementById("xss-progress");
          const progressText = document.getElementById("xss-progress-text");
          if (progressBar) {
            progressBar.style.width = data.job.progress + "%";
          }
          if (progressText) {
            progressText.textContent = data.job.progress + "%";
          }
        }

        if (data.job.status === "completed") {
          clearInterval(xssPollInterval);
          xssPollInterval = null;

          // Get full results
          const resultsResponse = await fetch(
            `${API_BASE_URL}/xss/scan/${currentXSSJobId}/results`,
          );
          const resultsData = await resultsResponse.json();

          hideLoader("xss-loader");
          enableForm("xssForm");

          if (resultsData.success) {
            displayXSSResults(resultsData.results);
            showNotification(
              `XSS scan completed. Found ${resultsData.results.findings?.length || 0} potential vulnerabilities.`,
              "success",
            );
          }
        } else if (data.job.status === "failed") {
          clearInterval(xssPollInterval);
          xssPollInterval = null;
          hideLoader("xss-loader");
          enableForm("xssForm");
          showNotification(
            "XSS scan failed: " + (data.job.error || "Unknown error"),
            "error",
          );
        }
      }
    } catch (error) {
      console.error("Poll XSS results error:", error);
    }
  }, 2000);
}

function displayXSSResults(results) {
  const findings = results.findings || [];
  allXSSFindings = findings;
  xssResults = findings;
  xssCurrentPage = 1;

  // Show results section
  const resultsSection = document.getElementById("xss-results");
  if (resultsSection) {
    resultsSection.classList.remove("hidden");
  }

  // Show summary stats
  displayXSSSummary(results);

  updateXSSResultsTable();

  // Update dashboard overview stats
  updateDashboardXSSStats(results);
  loadRecommendationSummary();
}

function displayXSSSummary(results) {
  const summary = results.summary || {};
  const scanInfo = results.scan_info || {};
  const toolResults = getToolResultsList(results.tool_results || {});

  const container = document.getElementById("xss-summary");
  if (!container) return;
  container.classList.remove("hidden");

  // Severity counts
  const severity = getSeveritySummary(summary);
  const critical = severity.critical;
  const high = severity.high;
  const medium = severity.medium;
  const low = severity.low;
  const total = severity.total;

  // Tool stats
  let toolsHtml = "";
  for (const toolData of toolResults) {
    const toolName = toolData.tool || "tool";
    const statusIcon = toolData.success
      ? '<i class="fa-solid fa-circle-check" style="color:#16a34a"></i>'
      : '<i class="fa-solid fa-circle-xmark" style="color:#dc2626"></i>';
    const time = toolData.execution_time
      ? toolData.execution_time.toFixed(1) + "s"
      : "-";
    toolsHtml += `
      <div class="xss-tool-stat">
        <span class="xss-tool-stat-icon">${statusIcon}</span>
        <span class="xss-tool-stat-name">${toolName}</span>
        <span class="xss-tool-stat-count">${toolData.items_found || toolData.findings_count || 0} findings</span>
        <span class="xss-tool-stat-time">${time}</span>
      </div>
    `;
  }

  container.innerHTML = `
    <div class="xss-summary-stats">
      <div class="xss-stat-card xss-stat-total">
        <span class="xss-stat-number">${total}</span>
        <span class="xss-stat-label">Total Findings</span>
      </div>
      <div class="xss-stat-card xss-stat-critical">
        <span class="xss-stat-number">${critical}</span>
        <span class="xss-stat-label">Critical</span>
      </div>
      <div class="xss-stat-card xss-stat-high">
        <span class="xss-stat-number">${high}</span>
        <span class="xss-stat-label">High</span>
      </div>
      <div class="xss-stat-card xss-stat-medium">
        <span class="xss-stat-number">${medium}</span>
        <span class="xss-stat-label">Medium</span>
      </div>
      <div class="xss-stat-card xss-stat-low">
        <span class="xss-stat-number">${low}</span>
        <span class="xss-stat-label">Low</span>
      </div>
    </div>
    <div class="xss-tool-results">
      <h4><i class="fa-solid fa-wrench"></i> Tool Results</h4>
      <div class="xss-tools-list">${toolsHtml}</div>
      <div class="xss-scan-meta">
        <span><i class="fa-solid fa-clock"></i> ${scanInfo.execution_time ? scanInfo.execution_time.toFixed(1) + "s" : "-"}</span>
        <span><i class="fa-solid fa-globe"></i> ${scanInfo.target || "-"}</span>
      </div>
    </div>
  `;
}

function updateDashboardXSSStats(results) {
  const severity = getSeveritySummary(results.summary || {});
  const statCards = document.querySelectorAll(".stat-value");
  if (statCards.length >= 3) {
    statsData.totalScans += 1;
    statsData.highSeverity += severity.critical + severity.high;
    statCards[0].textContent = statsData.totalScans;
    statCards[1].textContent = statsData.highSeverity;
  }
}

function updateXSSResultsTable() {
  const tbody = document.querySelector("#xssResultsTable tbody");
  if (!tbody) return;

  // Calculate pagination
  xssTotalPages = Math.ceil(allXSSFindings.length / xssPageSize);
  const start = (xssCurrentPage - 1) * xssPageSize;
  const end = Math.min(start + xssPageSize, allXSSFindings.length);
  const pageFindings = allXSSFindings.slice(start, end);

  // Clear existing rows
  tbody.innerHTML = "";

  if (pageFindings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 20px; color: #64748b;">
          No XSS vulnerabilities detected
        </td>
      </tr>
    `;
  } else {
    pageFindings.forEach((finding) => {
      const row = document.createElement("tr");

      const severityClass = getSeverityClass(finding.severity);
      const confidenceClass = getConfidenceClass(finding.confidence);

      row.innerHTML = `
        <td><a href="${escapeHtml(finding.url)}" target="_blank" class="url-link">${escapeHtml(truncateURL(finding.url))}</a></td>
        <td><span class="xss-type-badge">${escapeHtml(finding.xss_type || "Unknown")}</span></td>
        <td><span class="severity-badge ${severityClass}">${escapeHtml(finding.severity || "Unknown")}</span></td>
        <td>${escapeHtml(finding.parameter || "-")}</td>
        <td><span class="confidence-badge ${confidenceClass}">${findingConfidence(finding.confidence)}</span></td>
        <td><span class="tool-badge">${escapeHtml(finding.tool || "Unknown")}</span></td>
      `;
      tbody.appendChild(row);
    });
  }

  // Update pagination info
  updateXSSPaginationInfo(start + 1, end, allXSSFindings.length);
  updateXSSPaginationControls();
}

function getSeverityClass(severity) {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-info";
  }
}

function getConfidenceClass(confidence) {
  if (typeof confidence === "string") {
    const c = confidence.toLowerCase();
    if (c === "confirmed" || c === "high") return "confidence-high";
    if (c === "medium") return "confidence-medium";
    return "confidence-low";
  }
  if (confidence >= 90) return "confidence-high";
  if (confidence >= 70) return "confidence-medium";
  return "confidence-low";
}

function findingConfidence(confidence) {
  if (typeof confidence === "number") {
    return `${confidence}%`;
  }
  if (typeof confidence === "string") {
    return confidence.charAt(0).toUpperCase() + confidence.slice(1);
  }
  return "Unknown";
}

function truncateURL(url, maxLength = 50) {
  if (!url) return "";
  if (url.length <= maxLength) return url;
  return url.substring(0, maxLength) + "...";
}

function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function updateXSSPaginationInfo(start, end, total) {
  const info = document.getElementById("xssPaginationInfo");
  if (info) {
    info.textContent = `Showing ${start}-${end} of ${total} results`;
  }
}

function updateXSSPaginationControls() {
  const prevBtn = document.getElementById("xssPrevBtn");
  const nextBtn = document.getElementById("xssNextBtn");
  const pageNumbers = document.getElementById("xssPageNumbers");

  if (prevBtn) prevBtn.disabled = xssCurrentPage <= 1;
  if (nextBtn) nextBtn.disabled = xssCurrentPage >= xssTotalPages;

  if (pageNumbers) {
    pageNumbers.innerHTML = "";
    const maxButtons = 5;
    let startPage = Math.max(1, xssCurrentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(xssTotalPages, startPage + maxButtons - 1);
    startPage = Math.max(1, endPage - maxButtons + 1);

    for (let i = startPage; i <= endPage; i++) {
      const btn = document.createElement("button");
      btn.className = `pagination-page-btn ${i === xssCurrentPage ? "active" : ""}`;
      btn.textContent = i;
      btn.onclick = () => goToXSSPage(i);
      pageNumbers.appendChild(btn);
    }
  }
}

function changeXSSPage(delta) {
  const newPage = xssCurrentPage + delta;
  if (newPage >= 1 && newPage <= xssTotalPages) {
    xssCurrentPage = newPage;
    updateXSSResultsTable();
  }
}

function goToXSSPage(page) {
  xssCurrentPage = page;
  updateXSSResultsTable();
}

function changeXSSPageSize() {
  const select = document.getElementById("xssPageSize");
  if (select) {
    xssPageSize = parseInt(select.value);
    xssCurrentPage = 1;
    updateXSSResultsTable();
  }
}

function filterXSSResults() {
  const searchInput = document.getElementById("xssSearch");
  const searchTerm = searchInput?.value.toLowerCase() || "";

  if (!searchTerm) {
    allXSSFindings = xssResults;
  } else {
    allXSSFindings = xssResults.filter(
      (finding) =>
        finding.url?.toLowerCase().includes(searchTerm) ||
        finding.xss_type?.toLowerCase().includes(searchTerm) ||
        finding.parameter?.toLowerCase().includes(searchTerm) ||
        finding.tool?.toLowerCase().includes(searchTerm),
    );
  }

  xssCurrentPage = 1;
  updateXSSResultsTable();
}

function exportXSSResults(format) {
  if (allXSSFindings.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  if (format === "json") {
    const dataStr = JSON.stringify(allXSSFindings, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `xss_findings_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showNotification("XSS findings exported as JSON", "success");
  }
}

function exportXSSResultsPDF() {
  if (allXSSFindings.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  // Create printable HTML
  const printWindow = window.open("", "_blank");
  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>XSS Scan Report</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #1e293b; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f1f5f9; }
        .severity-critical { color: #dc2626; font-weight: bold; }
        .severity-high { color: #ea580c; font-weight: bold; }
        .severity-medium { color: #ca8a04; }
        .severity-low { color: #16a34a; }
        .report-header { margin-bottom: 20px; }
        .report-date { color: #64748b; }
      </style>
    </head>
    <body>
      <div class="report-header">
        <h1>XSS Vulnerability Scan Report</h1>
        <p class="report-date">Generated: ${new Date().toLocaleString()}</p>
        <p>Total Findings: ${allXSSFindings.length}</p>
      </div>
      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>XSS Type</th>
            <th>Severity</th>
            <th>Parameter</th>
            <th>Confidence</th>
            <th>Tool</th>
          </tr>
        </thead>
        <tbody>
          ${allXSSFindings
            .map(
              (f) => `
            <tr>
              <td>${escapeHtml(f.url)}</td>
              <td>${escapeHtml(f.xss_type || "Unknown")}</td>
              <td class="severity-${(f.severity || "").toLowerCase()}">${escapeHtml(f.severity || "Unknown")}</td>
              <td>${escapeHtml(f.parameter || "-")}</td>
              <td>${findingConfidence(f.confidence)}</td>
              <td>${escapeHtml(f.tool || "Unknown")}</td>
            </tr>
          `,
            )
            .join("")}
        </tbody>
      </table>
    </body>
    </html>
  `);
  printWindow.document.close();
  printWindow.print();
  showNotification("Print dialog opened", "success");
}

function clearXSSResults() {
  allXSSFindings = [];
  xssResults = [];
  xssCurrentPage = 1;

  const resultsSection = document.getElementById("xss-results");
  if (resultsSection) {
    resultsSection.classList.add("hidden");
  }

  const summarySection = document.getElementById("xss-summary");
  if (summarySection) {
    summarySection.classList.add("hidden");
    summarySection.innerHTML = "";
  }

  const tbody = document.querySelector("#xssResultsTable tbody");
  if (tbody) {
    tbody.innerHTML = "";
  }

  showNotification("XSS results cleared", "success");
}

// =============================================
// SQL Injection Scanner Functions
// =============================================

async function handleSQLiScan(event) {
  event.preventDefault();

  const urlInput = document.getElementById("sqliUrlInput");
  const url = urlInput.value.trim();

  if (!url) {
    showNotification("Please enter a target URL", "error");
    return;
  }

  if (!isValidURL(url)) {
    showNotification("Please enter a valid URL with parameters", "error");
    return;
  }

  try {
    // Show loader
    showSQLiLoader(true);

    // Clear previous results
    clearSQLiResults();

    // Get selected tools (for future use)
    const selectedTools = [];
    const toolCheckboxes = document.querySelectorAll(
      '#sqli-tools-grid input[type="checkbox"]:checked',
    );
    toolCheckboxes.forEach((checkbox) => {
      selectedTools.push(checkbox.id.replace("sqli-", ""));
    });

    // Get scan intensity
    const intensityRadio = document.querySelector(
      'input[name="scanIntensity"]:checked',
    );
    const intensity = intensityRadio ? intensityRadio.value : "basic";

    showNotification("Starting SQL injection scan...", "info");

    // Start scan
    const response = await fetch(`${API_BASE_URL}/sqli/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        tools: selectedTools.length > 0 ? selectedTools : undefined,
        profile: getSelectedProfile("sqliProfile"),
        intensity: intensity,
      }),
    });

    const data = await response.json();

    if (data.success) {
      currentSQLiJobId = data.job_id;
      showNotification("SQL injection scan started successfully", "success");
      monitorJobLive({
        streamKey: "sqli",
        eventUrl: data.event_url,
        resultsUrl: data.results_url,
        onProgress: (payload) => updateSQLiProgress(payload.job || payload),
        onComplete: (results) => {
          processSQLiResults(results);
          showSQLiLoader(false);
          showNotification("SQL injection scan completed!", "success");
        },
        onFailed: (errorMessage) => {
          showSQLiLoader(false);
          showNotification(`SQL injection scan failed: ${errorMessage}`, "error");
        },
        fallbackPoll: () => startSQLiPolling(),
      });
    } else {
      throw new Error(data.error || "Failed to start SQL injection scan");
    }
  } catch (error) {
    console.error("SQL Injection scan error:", error);
    showNotification(`SQL Injection scan failed: ${error.message}`, "error");
    showSQLiLoader(false);
  }
}

function startSQLiPolling() {
  if (sqliPollInterval) {
    clearInterval(sqliPollInterval);
  }

  sqliPollInterval = setInterval(async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/sqli/scan/${currentSQLiJobId}`,
      );
      const data = await response.json();

      if (data.success && data.job) {
        updateSQLiProgress(data.job);

        if (data.job.status === "completed") {
          clearInterval(sqliPollInterval);
          await loadSQLiResults();
          showSQLiLoader(false);
          showNotification("SQL injection scan completed!", "success");
        } else if (data.job.status === "failed") {
          clearInterval(sqliPollInterval);
          showSQLiLoader(false);
          showNotification(
            `SQL injection scan failed: ${data.job.error || "Unknown error"}`,
            "error",
          );
        }
      }
    } catch (error) {
      console.error("Error polling SQL injection status:", error);
    }
  }, 2000); // Poll every 2 seconds
}

function updateSQLiProgress(jobData) {
  const progressBar = document.getElementById("sqli-progress");
  const progressText = document.getElementById("sqli-progress-text");
  const statusElement = document.getElementById("sqli-status");

  if (progressBar && progressText) {
    const progress = jobData.progress || 0;
    progressBar.style.width = `${progress}%`;
    progressText.textContent = `${progress}%`;
  }

  if (statusElement) {
    let statusMessage = "Scanning...";
    const progress = jobData.progress || 0;
    if (progress < 10) {
      statusMessage = "🔧 Initializing detection tools...";
    } else if (progress < 30) {
      statusMessage = "🔍 Running SQLMap analysis...";
    } else if (progress < 55) {
      statusMessage = "⚡ Running Nuclei template scans...";
    } else if (progress < 80) {
      statusMessage = "🎯 Running Ghauri detection...";
    } else if (progress < 90) {
      statusMessage = "📊 Analyzing and deduplicating results...";
    } else {
      statusMessage = "✅ Finalizing scan report...";
    }
    statusElement.textContent = statusMessage;
  }
}

async function loadSQLiResults() {
  if (!currentSQLiJobId) return;

  try {
    const response = await fetch(
      `${API_BASE_URL}/sqli/scan/${currentSQLiJobId}/results`,
    );
    const data = await response.json();

    if (data.success && data.results) {
      processSQLiResults(data.results);
    } else {
      throw new Error(data.error || "Failed to load results");
    }
  } catch (error) {
    console.error("Error loading SQL injection results:", error);
    showNotification(`Failed to load results: ${error.message}`, "error");
  }
}

function processSQLiResults(results) {
  // Store all findings
  allSQLiFindings = results.findings || [];

  // Update summary with full results data
  updateSQLiSummary(
    results.summary || {},
    results.tool_results || {},
    results.scan_info || {},
  );

  // Display results
  updateSQLiResultsDisplay();

  // Show results section
  const resultsCard = document.getElementById("sqli-results");
  const summaryCard = document.getElementById("sqli-summary");

  if (resultsCard) {
    resultsCard.classList.remove("hidden");
  }

  if (summaryCard) {
    summaryCard.classList.remove("hidden");
  }

  // Update dashboard stats
  loadStats();
  loadRecommendationSummary();
}

function updateSQLiSummary(summary, toolResults, scanInfo) {
  const severity = getSeveritySummary(summary);
  const moduleMetrics = summary.module_metrics || summary;
  const toolResultsList = getToolResultsList(toolResults);
  // Update severity counts
  const criticalEl = document.getElementById("sqli-critical-count");
  const highEl = document.getElementById("sqli-high-count");
  const mediumEl = document.getElementById("sqli-medium-count");
  const lowEl = document.getElementById("sqli-low-count");

  if (criticalEl) criticalEl.textContent = severity.critical;
  if (highEl) highEl.textContent = severity.high;
  if (mediumEl) mediumEl.textContent = severity.medium;
  if (lowEl) lowEl.textContent = severity.low;

  // Update scan meta info
  const metaEl = document.getElementById("sqli-scan-meta");
  if (metaEl && scanInfo) {
    const execTime = scanInfo.execution_time
      ? `${scanInfo.execution_time}s`
      : "N/A";
    const toolsUsed = scanInfo.tools_used ? scanInfo.tools_used.length : 0;
    metaEl.innerHTML = `
      <span class="meta-badge"><i class="fa-solid fa-clock"></i> ${execTime}</span>
      <span class="meta-badge"><i class="fa-solid fa-tools"></i> ${toolsUsed} tools</span>
      <span class="meta-badge"><i class="fa-solid fa-crosshairs"></i> ${severity.total} findings</span>
    `;
  }

  // Update tool results breakdown
  const toolsCardsEl = document.getElementById("sqli-tools-cards");
  if (toolsCardsEl && toolResultsList) {
    toolsCardsEl.innerHTML = "";
    const toolIcons = {
      sqlmap: "fa-solid fa-database",
      nuclei: "fa-solid fa-atom",
      ghauri: "fa-solid fa-magnifying-glass-arrow-right",
    };
    const toolColors = {
      sqlmap: "#e74c3c",
      nuclei: "#3498db",
      ghauri: "#2ecc71",
    };

    for (const stats of toolResultsList) {
      const toolName = stats.tool || "tool";
      const statusIcon = stats.success
        ? '<i class="fa-solid fa-circle-check" style="color:#16a34a"></i>'
        : '<i class="fa-solid fa-circle-xmark" style="color:#dc2626"></i>';
      const execTime = stats.execution_time
        ? `${stats.execution_time.toFixed(1)}s`
        : "N/A";
      const findingsCount =
        stats.validated_findings || stats.findings_count || 0;
      const errorMsg = stats.error
        ? `<div class="tool-error-msg">${truncateText(stats.error, 60)}</div>`
        : "";

      const card = document.createElement("div");
      card.className = "sqli-tool-card";
      card.style.borderLeftColor = toolColors[toolName] || "#64748b";
      card.innerHTML = `
        <div class="sqli-tool-card-header">
          <span class="sqli-tool-card-name">
            <i class="${toolIcons[toolName] || "fa-solid fa-wrench"}" style="color:${toolColors[toolName] || "#64748b"}"></i>
            ${toolName.charAt(0).toUpperCase() + toolName.slice(1)}
          </span>
          ${statusIcon}
        </div>
        <div class="sqli-tool-card-stats">
          <div class="sqli-tool-stat">
            <span class="sqli-tool-stat-val">${findingsCount}</span>
            <span class="sqli-tool-stat-lbl">Findings</span>
          </div>
          <div class="sqli-tool-stat">
            <span class="sqli-tool-stat-val">${execTime}</span>
            <span class="sqli-tool-stat-lbl">Time</span>
          </div>
        </div>
        ${errorMsg}
      `;
      toolsCardsEl.appendChild(card);
    }
  }

  // Update injection types breakdown
  const typesTagsEl = document.getElementById("sqli-types-tags");
  if (typesTagsEl && moduleMetrics.by_type) {
    typesTagsEl.innerHTML = "";
    const typeColors = {
      "error-based": "#e74c3c",
      "blind-boolean": "#f39c12",
      "blind-time": "#e67e22",
      union: "#9b59b6",
      stacked: "#c0392b",
      unknown: "#95a5a6",
    };
    for (const [typeName, count] of Object.entries(moduleMetrics.by_type)) {
      const tag = document.createElement("span");
      tag.className = "sqli-type-tag";
      tag.style.borderColor = typeColors[typeName] || "#64748b";
      tag.style.color = typeColors[typeName] || "#64748b";
      tag.innerHTML = `<strong>${count}</strong> ${typeName}`;
      typesTagsEl.appendChild(tag);
    }
  }

  // Show/hide breakdowns
  const typesBreakdown = document.getElementById("sqli-types-breakdown");
  if (typesBreakdown) {
    typesBreakdown.style.display =
      moduleMetrics.by_type && Object.keys(moduleMetrics.by_type).length > 0
        ? "block"
        : "none";
  }

  // Update risk assessment
  const riskValueEl = document.getElementById("sqli-risk-value");
  const riskLevelEl = document.getElementById("sqli-risk-level");

  if (riskValueEl && riskLevelEl) {
    let riskLevel = "none";
    if (severity.critical > 0) riskLevel = "critical";
    else if (severity.high > 0) riskLevel = "high";
    else if (severity.medium > 0) riskLevel = "medium";
    else if (severity.low > 0) riskLevel = "low";

    const riskLabels = {
      none: "Clean",
      low: "Low Risk",
      medium: "Medium Risk",
      high: "High Risk",
      critical: "Critical Risk",
    };

    riskValueEl.textContent = riskLabels[riskLevel] || "None";

    riskLevelEl.className = "risk-level";
    riskLevelEl.classList.add(`risk-${riskLevel.toLowerCase()}`);
  }
}

function updateSQLiResultsDisplay() {
  sqliCurrentPage = 1;
  sqliTotalPages = Math.ceil(allSQLiFindings.length / sqliPageSize);

  displaySQLiPage();
  updateSQLiPagination();
}

function displaySQLiPage() {
  const tbody = document.querySelector("#sqliResultsTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";

  // Use filtered results if available, otherwise all findings
  const data =
    sqliResults && sqliResults.length > 0 ? sqliResults : allSQLiFindings;

  if (!data || data.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="8" class="sqli-empty-state"><i class="fa-solid fa-shield-check" style="margin-right:8px;color:#16a34a"></i> No SQL injection vulnerabilities found</td></tr>';
    return;
  }

  const startIndex = (sqliCurrentPage - 1) * sqliPageSize;
  const endIndex = startIndex + sqliPageSize;
  const pageFindings = data.slice(startIndex, endIndex);

  pageFindings.forEach((finding) => {
    const row = createSQLiResultRow(finding);
    tbody.appendChild(row);
  });
}

function createSQLiResultRow(finding) {
  const row = document.createElement("tr");

  // Get severity class for styling
  const sevLower = (finding.severity || "unknown").toLowerCase();
  const severityClass = `severity-${sevLower}`;
  row.classList.add(severityClass);

  // Confidence color mapping
  const confColors = {
    confirmed: "#16a34a",
    high: "#2563eb",
    medium: "#d97706",
    low: "#94a3b8",
  };
  const confColor =
    confColors[(finding.confidence || "").toLowerCase()] || "#64748b";

  // Database icon mapping
  const dbIcons = {
    mysql: "🐬",
    postgresql: "🐘",
    mssql: "🔷",
    oracle: "🔶",
    sqlite: "📦",
  };
  const dbIcon = dbIcons[(finding.database_type || "").toLowerCase()] || "💾";

  row.innerHTML = `
    <td>
      <div class="url-cell">
        <span class="url-text" title="${finding.url || "N/A"}">${truncateText(finding.url || "N/A", 45)}</span>
      </div>
    </td>
    <td>
      <span class="parameter-badge">${finding.parameter || "N/A"}</span>
    </td>
    <td>
      <span class="injection-type">${finding.injection_type || finding.sqli_type || "Unknown"}</span>
    </td>
    <td>
      <span class="severity-badge ${severityClass}">${finding.severity || "Unknown"}</span>
    </td>
    <td>
      <span class="confidence-badge" style="border-color:${confColor};color:${confColor}">${finding.confidence || "Unknown"}</span>
    </td>
    <td>
      <span class="database-badge">${dbIcon} ${finding.database_type || "Unknown"}</span>
    </td>
    <td>
      <span class="tool-badge">${finding.tool || finding.detection_tool || "Unknown"}</span>
    </td>
    <td>
      <div class="action-buttons">
        <button class="btn-sm btn-info" onclick="showSQLiDetails('${encodeURIComponent(JSON.stringify(finding))}')" title="View Details">
          <i class="fa-solid fa-eye"></i>
        </button>
        <button class="btn-sm btn-secondary" onclick="copySQLiPayload('${encodeURIComponent(finding.payload || "")}')" title="Copy Payload">
          <i class="fa-solid fa-copy"></i>
        </button>
      </div>
    </td>
  `;

  return row;
}

function showSQLiDetails(encodedFinding) {
  try {
    const finding = JSON.parse(decodeURIComponent(encodedFinding));
    const modal = document.getElementById("sqli-detail-modal");
    const body = document.getElementById("sqli-modal-body");

    if (!modal || !body) return;

    const sevClass = `severity-${(finding.severity || "unknown").toLowerCase()}`;
    const confPercent = {
      confirmed: "100%",
      high: "85%",
      medium: "65%",
      low: "45%",
    };
    const confVal = confPercent[finding.confidence] || "N/A";

    body.innerHTML = `
      <div class="sqli-detail-grid">
        <div class="sqli-detail-section sqli-detail-main">
          <div class="sqli-detail-row">
            <label>Target URL</label>
            <div class="sqli-detail-url">${finding.url || "N/A"}</div>
          </div>
          <div class="sqli-detail-row">
            <label>Parameter</label>
            <span class="parameter-badge">${finding.parameter || "N/A"}</span>
          </div>
          <div class="sqli-detail-badges">
            <div class="sqli-detail-badge-group">
              <label>Severity</label>
              <span class="severity-badge ${sevClass}">${finding.severity || "Unknown"}</span>
            </div>
            <div class="sqli-detail-badge-group">
              <label>Confidence</label>
              <span class="confidence-badge">${finding.confidence || "Unknown"} (${confVal})</span>
            </div>
            <div class="sqli-detail-badge-group">
              <label>CVSS Score</label>
              <span class="sqli-cvss-badge">${finding.cvss_score || "N/A"}</span>
            </div>
          </div>
        </div>

        <div class="sqli-detail-section">
          <h4><i class="fa-solid fa-fingerprint"></i> Classification</h4>
          <div class="sqli-detail-row">
            <label>Injection Type</label>
            <span class="injection-type">${finding.injection_type || finding.sqli_type || "Unknown"}</span>
          </div>
          <div class="sqli-detail-row">
            <label>Database Type</label>
            <span class="database-badge">${finding.database_type || "Unknown"}</span>
          </div>
          <div class="sqli-detail-row">
            <label>Detection Tool</label>
            <span class="tool-badge">${finding.tool || finding.detection_tool || "Unknown"}</span>
          </div>
          <div class="sqli-detail-row">
            <label>CWE ID</label>
            <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" class="sqli-cwe-link">${finding.cwe_id || "CWE-89"}</a>
          </div>
        </div>

        <div class="sqli-detail-section">
          <h4><i class="fa-solid fa-terminal"></i> Payload</h4>
          <pre class="sqli-detail-code">${escapeHtml(finding.payload || "N/A")}</pre>
        </div>

        <div class="sqli-detail-section">
          <h4><i class="fa-solid fa-magnifying-glass"></i> Evidence</h4>
          <pre class="sqli-detail-evidence">${escapeHtml(finding.evidence || "N/A")}</pre>
        </div>

        <div class="sqli-detail-section sqli-detail-remediation">
          <h4><i class="fa-solid fa-shield-halved"></i> Remediation</h4>
          <p>${finding.remediation || "Use parameterized queries/prepared statements."}</p>
        </div>
      </div>
    `;

    modal.style.display = "flex";

    // Close on backdrop click
    modal.onclick = function (e) {
      if (e.target === modal) closeSQLiModal();
    };

    // Close on Escape key
    document.addEventListener("keydown", function closeOnEsc(e) {
      if (e.key === "Escape") {
        closeSQLiModal();
        document.removeEventListener("keydown", closeOnEsc);
      }
    });
  } catch (error) {
    console.error("Error showing SQL injection details:", error);
    showNotification("Error displaying vulnerability details", "error");
  }
}

function closeSQLiModal() {
  const modal = document.getElementById("sqli-detail-modal");
  if (modal) modal.style.display = "none";
}

function copySQLiPayload(encodedPayload) {
  try {
    const payload = decodeURIComponent(encodedPayload);
    navigator.clipboard
      .writeText(payload)
      .then(() => {
        showNotification("Payload copied to clipboard", "success");
      })
      .catch((err) => {
        console.error("Failed to copy payload:", err);
        showNotification("Failed to copy payload", "error");
      });
  } catch (error) {
    console.error("Error copying payload:", error);
    showNotification("Error copying payload", "error");
  }
}

function updateSQLiPagination() {
  const pageInfo = document.getElementById("sqliPageInfo");
  const prevButton = document.getElementById("sqliPrevPage");
  const nextButton = document.getElementById("sqliNextPage");

  if (pageInfo) {
    pageInfo.textContent = `Page ${sqliCurrentPage} of ${sqliTotalPages}`;
  }

  if (prevButton) {
    prevButton.disabled = sqliCurrentPage <= 1;
  }

  if (nextButton) {
    nextButton.disabled = sqliCurrentPage >= sqliTotalPages;
  }
}

function filterSQLiResults() {
  const searchTerm =
    document.getElementById("sqliSearch")?.value.toLowerCase() || "";

  if (!searchTerm) {
    sqliResults = [...allSQLiFindings];
  } else {
    sqliResults = allSQLiFindings.filter(
      (finding) =>
        (finding.url && finding.url.toLowerCase().includes(searchTerm)) ||
        (finding.parameter &&
          finding.parameter.toLowerCase().includes(searchTerm)) ||
        (finding.injection_type &&
          finding.injection_type.toLowerCase().includes(searchTerm)) ||
        (finding.severity &&
          finding.severity.toLowerCase().includes(searchTerm)) ||
        (finding.database_type &&
          finding.database_type.toLowerCase().includes(searchTerm)) ||
        (finding.tool && finding.tool.toLowerCase().includes(searchTerm)) ||
        (finding.detection_tool &&
          finding.detection_tool.toLowerCase().includes(searchTerm)),
    );
  }

  sqliCurrentPage = 1;
  sqliTotalPages = Math.ceil((sqliResults.length || 1) / sqliPageSize);
  displaySQLiPage();
  updateSQLiPagination();
}

function previousSQLiPage() {
  if (sqliCurrentPage > 1) {
    sqliCurrentPage--;
    displaySQLiPage();
    updateSQLiPagination();
  }
}

function nextSQLiPage() {
  if (sqliCurrentPage < sqliTotalPages) {
    sqliCurrentPage++;
    displaySQLiPage();
    updateSQLiPagination();
  }
}

function changeSQLiPageSize() {
  const pageSizeSelect = document.getElementById("sqliPageSize");
  if (pageSizeSelect) {
    sqliPageSize = parseInt(pageSizeSelect.value);
    updateSQLiResultsDisplay();
  }
}

function exportSQLiResults(format) {
  if (!allSQLiFindings || allSQLiFindings.length === 0) {
    showNotification("No SQL injection results to export", "warning");
    return;
  }

  try {
    let content, filename, mimeType;

    if (format === "json") {
      content = JSON.stringify(allSQLiFindings, null, 2);
      filename = `sqli_results_${new Date().toISOString().split("T")[0]}.json`;
      mimeType = "application/json";
    } else if (format === "csv") {
      content = convertSQLiToCSV(allSQLiFindings);
      filename = `sqli_results_${new Date().toISOString().split("T")[0]}.csv`;
      mimeType = "text/csv";
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotification(
      `SQL injection results exported as ${format.toUpperCase()}`,
      "success",
    );
  } catch (error) {
    console.error("Export error:", error);
    showNotification("Failed to export results", "error");
  }
}

function convertSQLiToCSV(findings) {
  const headers = [
    "URL",
    "Parameter",
    "Injection Type",
    "Severity",
    "Confidence",
    "CVSS Score",
    "Database",
    "Tool",
    "CWE ID",
    "Evidence",
    "Remediation",
  ];
  const rows = [headers];

  findings.forEach((finding) => {
    rows.push([
      finding.url || "",
      finding.parameter || "",
      finding.injection_type || finding.sqli_type || "",
      finding.severity || "",
      finding.confidence || "",
      finding.cvss_score || "",
      finding.database_type || "",
      finding.tool || finding.detection_tool || "",
      finding.cwe_id || "",
      finding.evidence || "",
      finding.remediation || "",
    ]);
  });

  return rows
    .map((row) =>
      row.map((field) => `"${String(field).replace(/"/g, '""')}"`).join(","),
    )
    .join("\n");
}

function exportSQLiResultsPDF() {
  if (!allSQLiFindings || allSQLiFindings.length === 0) {
    showNotification("No SQL injection results to export", "warning");
    return;
  }

  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    // Title
    doc.setFontSize(20);
    doc.text("SQL Injection Scan Report", 20, 20);

    // Summary
    doc.setFontSize(12);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 35);
    doc.text(`Total Vulnerabilities: ${allSQLiFindings.length}`, 20, 45);

    // Table data
    const tableData = allSQLiFindings.map((finding) => [
      finding.url || "N/A",
      finding.parameter || "N/A",
      finding.injection_type || finding.sqli_type || "Unknown",
      finding.severity || "Unknown",
      finding.confidence || "Unknown",
      finding.database_type || "Unknown",
      finding.tool || finding.detection_tool || "Unknown",
    ]);

    // Add table
    doc.autoTable({
      head: [
        [
          "URL",
          "Parameter",
          "Type",
          "Severity",
          "Confidence",
          "Database",
          "Tool",
        ],
      ],
      body: tableData,
      startY: 55,
      styles: { fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 40 },
        1: { cellWidth: 20 },
        2: { cellWidth: 25 },
        3: { cellWidth: 20 },
        4: { cellWidth: 20 },
        5: { cellWidth: 20 },
        6: { cellWidth: 20 },
      },
    });

    // Save
    const filename = `sqli_report_${new Date().toISOString().split("T")[0]}.pdf`;
    doc.save(filename);

    showNotification("PDF report generated successfully", "success");
  } catch (error) {
    console.error("PDF export error:", error);
    showNotification("Failed to generate PDF report", "error");
  }
}

function showSQLiLoader(show) {
  const loader = document.getElementById("sqli-loader");
  if (loader) {
    loader.style.display = show ? "flex" : "none";
  }
}

function clearSQLiResults() {
  // Clear polling interval
  if (sqliPollInterval) {
    clearInterval(sqliPollInterval);
    sqliPollInterval = null;
  }

  // Reset current job
  currentSQLiJobId = null;

  // Clear data
  allSQLiFindings = [];
  sqliResults = [];
  sqliCurrentPage = 1;

  // Hide result sections
  const resultsCard = document.getElementById("sqli-results");
  const summaryCard = document.getElementById("sqli-summary");

  if (resultsCard) {
    resultsCard.classList.add("hidden");
  }

  if (summaryCard) {
    summaryCard.classList.add("hidden");
  }

  // Clear table
  const tbody = document.querySelector("#sqliResultsTable tbody");
  if (tbody) {
    tbody.innerHTML = "";
  }

  // Clear search
  const searchInput = document.getElementById("sqliSearch");
  if (searchInput) {
    searchInput.value = "";
  }

  showNotification("SQL injection results cleared", "success");
}

// =============================================
// LFI Scanner Functions
// =============================================
async function handleLFIScan(event) {
  event.preventDefault();

  const urlInput = document.getElementById("lfiUrlInput");
  const url = urlInput.value.trim();

  if (!url) {
    showNotification("Please enter a target URL", "error");
    return;
  }

  // Validate URL format
  if (!isValidURL(url)) {
    showNotification("Please enter a valid URL", "error");
    return;
  }

  // Get selected LFI tools
  const selectedTools = getSelectedLFITools();

  if (selectedTools.length === 0) {
    showNotification("Please select at least one LFI detection tool", "error");
    return;
  }

  // Get parameters (optional)
  const paramsInput = document.getElementById("lfiParams");
  const parameters = paramsInput?.value.trim() || null;

  // Show loader
  showLoader("lfi-loader");
  disableForm("lfiForm");

  // Reset progress bar
  const progressBar = document.getElementById("lfi-progress");
  const progressText = document.getElementById("lfi-progress-text");
  if (progressBar) progressBar.style.width = "0%";
  if (progressText) progressText.textContent = "0%";

  try {
    const requestBody = {
      url: url,
      tools: selectedTools,
      profile: getSelectedProfile("lfiProfile"),
    };

    // Add parameters if provided
    if (parameters) {
      requestBody.parameters = parameters.split(",").map((p) => p.trim());
    }

    const response = await fetch(`${API_BASE_URL}/lfi/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    });

    const data = await response.json();

    if (data.success) {
      currentLFIJobId = data.job_id;
      showNotification(`LFI scan started for ${url}`, "success");
      monitorJobLive({
        streamKey: "lfi",
        eventUrl: data.event_url,
        resultsUrl: data.results_url,
        onProgress: (payload) => {
          const progress = payload.progress || 0;
          const progressBar = document.getElementById("lfi-progress");
          const progressText = document.getElementById("lfi-progress-text");
          if (progressBar) progressBar.style.width = `${progress}%`;
          if (progressText) progressText.textContent = `${progress}%`;
          updateLoaderProgress("lfi-loader", progress, "Running LFI scan");
        },
        onComplete: (results) => {
          hideLoader("lfi-loader");
          enableForm("lfiForm");
          displayLFIResults(results);
          showNotification(
            `LFI scan completed. Found ${results.findings?.length || 0} potential vulnerabilities.`,
            "success",
          );
        },
        onFailed: (errorMessage) => {
          hideLoader("lfi-loader");
          enableForm("lfiForm");
          showNotification(errorMessage, "error");
        },
        fallbackPoll: () => startLFIPollResults(),
      });
    } else {
      showNotification(data.message || "Failed to start LFI scan", "error");
      hideLoader("lfi-loader");
      enableForm("lfiForm");
    }
  } catch (error) {
    console.error("LFI scan error:", error);
    showNotification("Failed to connect to API server", "error");
    hideLoader("lfi-loader");
    enableForm("lfiForm");
  }
}

function getSelectedLFITools() {
  const tools = [];
  const checkboxes = document.querySelectorAll(
    '#lfi-tools-grid input[type="checkbox"]',
  );
  checkboxes.forEach((cb) => {
    if (cb.checked && !cb.disabled) {
      const toolName = cb.id.replace("lfi-", "");
      tools.push(toolName);
    }
  });
  return tools;
}

function startLFIPollResults() {
  if (lfiPollInterval) {
    clearInterval(lfiPollInterval);
  }

  let pollCount = 0;
  const maxPolls = 300; // 10 minutes (300 * 2 seconds)

  lfiPollInterval = setInterval(async () => {
    try {
      pollCount++;

      // Timeout after max polls
      if (pollCount > maxPolls) {
        clearInterval(lfiPollInterval);
        lfiPollInterval = null;
        hideLoader("lfi-loader");
        enableForm("lfiForm");
        showNotification(
          "LFI scan timeout. The scan is taking too long.",
          "error",
        );
        return;
      }

      const response = await fetch(
        `${API_BASE_URL}/lfi/scan/${currentLFIJobId}`,
      );
      const data = await response.json();

      if (data.success && data.job) {
        // Update progress if available
        if (data.job.progress !== undefined) {
          const progressBar = document.getElementById("lfi-progress");
          const progressText = document.getElementById("lfi-progress-text");
          if (progressBar) {
            progressBar.style.width = data.job.progress + "%";
          }
          if (progressText) {
            progressText.textContent = data.job.progress + "%";
          }
        }

        if (data.job.status === "completed") {
          clearInterval(lfiPollInterval);
          lfiPollInterval = null;

          // Get full results
          const resultsResponse = await fetch(
            `${API_BASE_URL}/lfi/scan/${currentLFIJobId}/results`,
          );
          const resultsData = await resultsResponse.json();

          hideLoader("lfi-loader");
          enableForm("lfiForm");

          if (resultsData.success) {
            displayLFIResults(resultsData.results);
            showNotification(
              `LFI scan completed. Found ${resultsData.results.findings?.length || 0} potential vulnerabilities.`,
              "success",
            );
          } else {
            showNotification("Failed to fetch LFI results", "error");
          }
        } else if (data.job.status === "failed") {
          clearInterval(lfiPollInterval);
          lfiPollInterval = null;
          hideLoader("lfi-loader");
          enableForm("lfiForm");
          showNotification(data.job.error || "LFI scan failed", "error");
        }
      }
    } catch (error) {
      console.error("LFI polling error:", error);
      // Don't stop polling on error, might be temporary
    }
  }, 2000); // Poll every 2 seconds
}

function displayLFIResults(results) {
  const findings = results.findings || [];
  allLFIFindings = findings;
  lfiResults = findings;
  lfiCurrentPage = 1;

  // Show results section
  const resultsSection = document.getElementById("lfi-results");
  if (resultsSection) {
    resultsSection.classList.remove("hidden");
  }

  // Show summary stats
  displayLFISummary(results);

  updateLFIResultsTable();

  // Update dashboard overview stats (if applicable)
  updateDashboardLFIStats(results);
  loadRecommendationSummary();
}

function displayLFISummary(results) {
  const summary = results.summary || {};
  const severity = getSeveritySummary(summary);
  const moduleMetrics = summary.module_metrics || {};

  const container = document.getElementById("lfi-summary");
  if (!container) return;
  container.classList.remove("hidden");

  // Severity counts
  const high = severity.high;
  const medium = severity.medium;
  const low = severity.low;
  const payloadsTested = moduleMetrics.payloads_tested || 0;

  // Execution info
  const targetUrl = results.target_url || "-";
  const paramsTested = moduleMetrics.parameters_tested || 0;
  const executionTime = results.scan_info?.execution_time
    ? results.scan_info.execution_time.toFixed(2) + "s"
    : "-";
  const toolsUsed = getToolResultsList(results.tool_results || {}).map(
    (tool) => tool.tool,
  );

  container.innerHTML = `
    <div class="lfi-summary-header">
      <h3><i class="fa-solid fa-chart-simple"></i> Scan Summary</h3>
    </div>
    <div class="lfi-summary-stats">
      <div class="lfi-stat-card lfi-stat-high">
        <span class="lfi-stat-number">${high}</span>
        <span class="lfi-stat-label">High Severity</span>
      </div>
      <div class="lfi-stat-card lfi-stat-medium">
        <span class="lfi-stat-number">${medium}</span>
        <span class="lfi-stat-label">Medium Severity</span>
      </div>
      <div class="lfi-stat-card lfi-stat-low">
        <span class="lfi-stat-number">${low}</span>
        <span class="lfi-stat-label">Low Severity</span>
      </div>
      <div class="lfi-stat-card lfi-stat-payloads">
        <span class="lfi-stat-number">${payloadsTested}</span>
        <span class="lfi-stat-label">Payloads Tested</span>
      </div>
    </div>
    <div class="lfi-scan-meta">
      <div class="lfi-meta-item">
        <span class="lfi-meta-label"><i class="fa-solid fa-globe"></i> Target URL:</span>
        <span class="lfi-meta-value">${escapeHtml(targetUrl)}</span>
      </div>
      <div class="lfi-meta-item">
        <span class="lfi-meta-label"><i class="fa-solid fa-list"></i> Parameters Tested:</span>
        <span class="lfi-meta-value">${paramsTested}</span>
      </div>
      <div class="lfi-meta-item">
        <span class="lfi-meta-label"><i class="fa-solid fa-clock"></i> Execution Time:</span>
        <span class="lfi-meta-value">${executionTime}</span>
      </div>
      <div class="lfi-meta-item">
        <span class="lfi-meta-label"><i class="fa-solid fa-wrench"></i> Tools Used:</span>
        <span class="lfi-meta-value">${toolsUsed.join(", ") || "-"}</span>
      </div>
    </div>
  `;
}

function updateDashboardLFIStats(results) {
  const severity = getSeveritySummary(results.summary || {});
  const lfiStat = document.getElementById("stat-lfi-findings");
  if (lfiStat) {
    lfiStat.textContent = severity.total;
  }
}

function updateLFIResultsTable() {
  const tbody = document.querySelector("#lfiResultsTable tbody");
  if (!tbody) return;

  // Calculate pagination
  lfiTotalPages = Math.ceil(allLFIFindings.length / lfiPageSize);
  const start = (lfiCurrentPage - 1) * lfiPageSize;
  const end = Math.min(start + lfiPageSize, allLFIFindings.length);
  const pageFindings = allLFIFindings.slice(start, end);

  // Clear existing rows
  tbody.innerHTML = "";

  if (pageFindings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 20px; color: #64748b;">
          No LFI vulnerabilities detected
        </td>
      </tr>
    `;
  } else {
    pageFindings.forEach((finding) => {
      const row = document.createElement("tr");

      const severityClass = getSeverityClass(finding.severity);
      const confidenceClass = getConfidenceClass(finding.confidence);

      // Truncate evidence if too long
      const evidenceText = finding.evidence
        ? truncateText(finding.evidence, 50)
        : "-";

      row.innerHTML = `
        <td><code>${escapeHtml(finding.parameter || "-")}</code></td>
        <td><code class="lfi-payload">${escapeHtml(truncateText(finding.payload, 40))}</code></td>
        <td><span class="severity-badge ${severityClass}">${escapeHtml(finding.severity || "Unknown")}</span></td>
        <td><span class="confidence-badge ${confidenceClass}">${escapeHtml(finding.confidence || "Unknown")}</span></td>
        <td><small>${escapeHtml(evidenceText)}</small></td>
        <td><span class="tool-badge">${escapeHtml(finding.tool || "Unknown")}</span></td>
        <td>
          <button class="action-btn" onclick="viewLFIDetails(${JSON.stringify(finding).replace(/"/g, "&quot;")})" title="View Details">
            <i class="fa-solid fa-eye"></i>
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });
  }

  // Update pagination info
  updateLFIPaginationInfo(start + 1, end, allLFIFindings.length);
  updateLFIPaginationControls();
}

function updateLFIPaginationInfo(start, end, total) {
  const info = document.getElementById("lfiPaginationInfo");
  if (info) {
    info.textContent = `Showing ${start}-${end} of ${total} results`;
  }
}

function updateLFIPaginationControls() {
  const prevBtn = document.getElementById("lfiPrevBtn");
  const nextBtn = document.getElementById("lfiNextBtn");

  if (prevBtn) prevBtn.disabled = lfiCurrentPage <= 1;
  if (nextBtn) nextBtn.disabled = lfiCurrentPage >= lfiTotalPages;
}

function previousLFIPage() {
  if (lfiCurrentPage > 1) {
    lfiCurrentPage--;
    updateLFIResultsTable();
  }
}

function nextLFIPage() {
  if (lfiCurrentPage < lfiTotalPages) {
    lfiCurrentPage++;
    updateLFIResultsTable();
  }
}

function changeLFIPageSize() {
  const select = document.getElementById("lfiPageSize");
  if (select) {
    lfiPageSize = parseInt(select.value);
    lfiCurrentPage = 1;
    updateLFIResultsTable();
  }
}

function filterLFIResults() {
  const searchInput = document.getElementById("lfiSearch");
  const searchTerm = searchInput?.value.toLowerCase() || "";

  if (!searchTerm) {
    allLFIFindings = lfiResults;
  } else {
    allLFIFindings = lfiResults.filter(
      (finding) =>
        finding.parameter?.toLowerCase().includes(searchTerm) ||
        finding.payload?.toLowerCase().includes(searchTerm) ||
        finding.severity?.toLowerCase().includes(searchTerm) ||
        finding.tool?.toLowerCase().includes(searchTerm) ||
        finding.evidence?.toLowerCase().includes(searchTerm),
    );
  }

  lfiCurrentPage = 1;
  updateLFIResultsTable();
}

function exportLFIResults(format) {
  if (allLFIFindings.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  if (format === "json") {
    const dataStr = JSON.stringify(allLFIFindings, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `lfi_findings_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showNotification("LFI findings exported as JSON", "success");
  }
}

function exportLFIResultsPDF() {
  if (allLFIFindings.length === 0) {
    showNotification("No results to export", "error");
    return;
  }

  // Create printable HTML
  const printWindow = window.open("", "_blank");
  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>LFI Scan Report</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #1e293b; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }
        th { background-color: #f1f5f9; }
        .severity-high { color: #dc2626; font-weight: bold; }
        .severity-medium { color: #ea580c; }
        .severity-low { color: #16a34a; }
        .report-header { margin-bottom: 20px; }
        .report-date { color: #64748b; }
        code { background: #f1f5f9; padding: 2px 4px; border-radius: 3px; }
      </style>
    </head>
    <body>
      <div class="report-header">
        <h1>LFI Vulnerability Scan Report</h1>
        <p class="report-date">Generated: ${new Date().toLocaleString()}</p>
        <p>Total Findings: ${allLFIFindings.length}</p>
      </div>
      <table>
        <thead>
          <tr>
            <th>Parameter</th>
            <th>Payload</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Evidence</th>
            <th>Tool</th>
          </tr>
        </thead>
        <tbody>
          ${allLFIFindings
            .map(
              (f) => `
            <tr>
              <td><code>${escapeHtml(f.parameter || "-")}</code></td>
              <td><code>${escapeHtml(f.payload || "-")}</code></td>
              <td class="severity-${(f.severity || "").toLowerCase()}">${escapeHtml(f.severity || "Unknown")}</td>
              <td>${escapeHtml(f.confidence || "Unknown")}</td>
              <td>${escapeHtml(truncateText(f.evidence, 60) || "-")}</td>
              <td>${escapeHtml(f.tool || "Unknown")}</td>
            </tr>
          `,
            )
            .join("")}
        </tbody>
      </table>
    </body>
    </html>
  `);
  printWindow.document.close();
  printWindow.print();
  showNotification("Print dialog opened", "success");
}

function clearLFIResults() {
  // Clear polling interval
  if (lfiPollInterval) {
    clearInterval(lfiPollInterval);
    lfiPollInterval = null;
  }

  // Reset current job
  currentLFIJobId = null;

  // Clear data
  allLFIFindings = [];
  lfiResults = [];
  lfiCurrentPage = 1;

  // Hide result sections
  const resultsSection = document.getElementById("lfi-results");
  if (resultsSection) {
    resultsSection.classList.add("hidden");
  }

  const summarySection = document.getElementById("lfi-summary");
  if (summarySection) {
    summarySection.classList.add("hidden");
    summarySection.innerHTML = "";
  }

  const tbody = document.querySelector("#lfiResultsTable tbody");
  if (tbody) {
    tbody.innerHTML = "";
  }

  showNotification("LFI results cleared", "success");
}

function viewLFIDetails(finding) {
  // Create a modal or alert to show full finding details
  const detailsHtml = `
    <strong>Parameter:</strong> ${escapeHtml(finding.parameter || "-")}<br>
    <strong>Payload:</strong> <code>${escapeHtml(finding.payload || "-")}</code><br>
    <strong>Severity:</strong> ${escapeHtml(finding.severity || "Unknown")}<br>
    <strong>Confidence:</strong> ${escapeHtml(finding.confidence || "Unknown")}<br>
    <strong>Tool:</strong> ${escapeHtml(finding.tool || "Unknown")}<br>
    <strong>Evidence:</strong><br><pre>${escapeHtml(finding.evidence || "-")}</pre>
  `;

  const modal = document.createElement("div");
  modal.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; bottom: 0; 
    background: rgba(0,0,0,0.5); display: flex; align-items: center; 
    justify-content: center; z-index: 10000;
  `;
  modal.innerHTML = `
    <div style="background: white; padding: 20px; border-radius: 8px; max-width: 600px; max-height: 80vh; overflow-y: auto;">
      <h3 style="margin-top: 0;">LFI Finding Details</h3>
      <div>${detailsHtml}</div>
      <button onclick="this.closest('div').parentElement.remove()" style="margin-top: 15px; padding: 8px 16px; background: #3b82f6; color: white; border: none; border-radius: 4px; cursor: pointer;">Close</button>
    </div>
  `;
  document.body.appendChild(modal);
  modal.onclick = (e) => {
    if (e.target === modal) modal.remove();
  };
}

function isValidURL(string) {
  try {
    const url = new URL(string);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (_) {
    return false;
  }
}

// Make functions globally available
window.switchTab = switchTab;
window.filterSubdomainResults = filterSubdomainResults;
window.filterPathResults = filterPathResults;
window.exportSubdomainResults = exportSubdomainResults;
window.exportSubdomainResultsPDF = exportSubdomainResultsPDF;
window.exportPathResults = exportPathResults;
window.exportPathResultsPDF = exportPathResultsPDF;
window.clearSubdomainResults = clearSubdomainResults;
window.clearPathResults = clearPathResults;
window.changePathPage = changePathPage;
window.goToPathPage = goToPathPage;
window.changePathPageSize = changePathPageSize;
window.changeSubdomainPage = changeSubdomainPage;
window.goToSubdomainPage = goToSubdomainPage;
window.changeSubdomainPageSize = changeSubdomainPageSize;
window.filterXSSResults = filterXSSResults;
window.exportXSSResults = exportXSSResults;
window.exportXSSResultsPDF = exportXSSResultsPDF;
window.clearXSSResults = clearXSSResults;
// SQL Injection functions
window.filterSQLiResults = filterSQLiResults;
window.previousSQLiPage = previousSQLiPage;
window.nextSQLiPage = nextSQLiPage;
window.changeSQLiPageSize = changeSQLiPageSize;
window.exportSQLiResults = exportSQLiResults;
window.exportSQLiResultsPDF = exportSQLiResultsPDF;
window.clearSQLiResults = clearSQLiResults;
window.showSQLiDetails = showSQLiDetails;
window.closeSQLiModal = closeSQLiModal;
window.copySQLiPayload = copySQLiPayload;
window.changeXSSPage = changeXSSPage;
window.goToXSSPage = goToXSSPage;
window.changeXSSPageSize = changeXSSPageSize;
// LFI functions
window.filterLFIResults = filterLFIResults;
window.previousLFIPage = previousLFIPage;
window.nextLFIPage = nextLFIPage;
window.changeLFIPageSize = changeLFIPageSize;
window.exportLFIResults = exportLFIResults;
window.exportLFIResultsPDF = exportLFIResultsPDF;
window.clearLFIResults = clearLFIResults;
window.viewLFIDetails = viewLFIDetails;
