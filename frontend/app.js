// app.js

// FastAPI serves the frontend, so relative API paths work.
const API_BASE = "";


// ---------- DOM elements ----------
const els = {
  apiStatus: document.getElementById("apiStatus"),

  uploadView: document.getElementById("uploadView"),
  loadingView: document.getElementById("loadingView"),
  resultsView: document.getElementById("resultsView"),

  dropzone: document.getElementById("dropzone"),
  fileInput: document.getElementById("fileInput"),
  fileName: document.getElementById("fileName"),
  manualEntry: document.getElementById("manualEntry"),

  analyzeBtn: document.getElementById("analyzeBtn"),
  analyzeBtnText: document.getElementById("analyzeBtnText"),
  loadingLog: document.getElementById("loadingLog"),
  newScanBtn: document.getElementById("newScanBtn"),

  scoreValue: document.getElementById("scoreValue"),
  ringFill: document.getElementById("ringFill"),
  scoreFile: document.getElementById("scoreFile"),
  scoreTimestamp: document.getElementById("scoreTimestamp"),

  mlClassification: document.getElementById("mlClassification"),
  mlBarFill: document.getElementById("mlBarFill"),
  mlScoreText: document.getElementById("mlScoreText"),
  mlNote: document.getElementById("mlNote"),

  chainStatus: document.getElementById("chainStatus"),
  chainHash: document.getElementById("chainHash"),
  chainBlock: document.getElementById("chainBlock"),
  chainNote: document.getElementById("chainNote"),

  vulnList: document.getElementById("vulnList"),
};


// ---------- State ----------
let selectedFile = null;
let severityChart = null;


// ---------- Safe DOM helpers ----------

function setText(element, value) {
  if (element) {
    element.textContent = value ?? "";
  }
}

function setHTML(element, value) {
  if (element) {
    element.innerHTML = value ?? "";
  }
}


// ---------- View switching ----------

function showView(name) {
  const views = {
    upload: els.uploadView,
    loading: els.loadingView,
    results: els.resultsView,
  };

  Object.values(views).forEach((view) => {
    if (view) {
      view.classList.remove("active");
    }
  });

  if (views[name]) {
    views[name].classList.add("active");
  }
}


// ---------- Health check ----------

async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/health`);

    if (!res.ok) {
      throw new Error("Backend returned an error");
    }

    if (els.apiStatus) {
      els.apiStatus.classList.add("online");
      els.apiStatus.classList.remove("offline");

      els.apiStatus.innerHTML =
        `<span class="dot"></span>backend online`;
    }

  } catch (err) {

    console.error("Health check failed:", err);

    if (els.apiStatus) {
      els.apiStatus.classList.add("offline");
      els.apiStatus.classList.remove("online");

      els.apiStatus.innerHTML =
        `<span class="dot"></span>backend unreachable`;
    }
  }
}

checkHealth();


// ---------- File selection ----------

if (els.dropzone && els.fileInput) {

  els.dropzone.addEventListener("click", () => {
    els.fileInput.click();
  });

  els.fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  });


  ["dragover", "dragenter"].forEach((evt) => {

    els.dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      els.dropzone.classList.add("drag-over");
    });

  });


  ["dragleave", "drop"].forEach((evt) => {

    els.dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      els.dropzone.classList.remove("drag-over");
    });

  });


  els.dropzone.addEventListener("drop", (e) => {

    if (e.dataTransfer &&
        e.dataTransfer.files &&
        e.dataTransfer.files[0]) {

      setSelectedFile(e.dataTransfer.files[0]);
    }

  });

}


function setSelectedFile(file) {

  selectedFile = file;

  setText(els.fileName, file.name);

}


// ---------- Run analysis ----------

if (els.analyzeBtn) {
  els.analyzeBtn.addEventListener("click", runAnalysis);
}


if (els.newScanBtn) {

  els.newScanBtn.addEventListener("click", () => {

    selectedFile = null;

    setText(els.fileName, "");

    if (els.fileInput) {
      els.fileInput.value = "";
    }

    if (els.manualEntry) {
      els.manualEntry.value = "";
    }

    showView("upload");

  });

}


// ---------- Loading animation ----------

const LOG_LINES = [
  "parsing IKE proposals...",
  "checking cipher suite compliance...",
  "running XGBoost traffic classifier...",
  "anchoring report hash on-chain...",
  "finalizing report...",
];


function playLoadingLog() {

  if (!els.loadingLog) {
    return;
  }

  els.loadingLog.innerHTML = "";

  LOG_LINES.forEach((line, i) => {

    const div = document.createElement("div");

    div.textContent = "> " + line;

    els.loadingLog.appendChild(div);

    setTimeout(() => {
      div.classList.add("done");
    }, (i + 1) * 350);

  });

}


// ---------- Start analysis ----------

async function runAnalysis() {

  if (els.analyzeBtn) {
    els.analyzeBtn.disabled = true;
  }

  showView("loading");

  playLoadingLog();


  try {

    const formData = new FormData();


    // PCAP upload
    if (selectedFile) {

      formData.append("file", selectedFile);

    }

    // Manual input
    else if (els.manualEntry &&
             els.manualEntry.value.trim()) {

      const blob = new Blob(
        [els.manualEntry.value],
        { type: "text/plain" }
      );

      formData.append(
        "file",
        blob,
        "manual-entry.conf"
      );

    }

    else {

      throw new Error(
        "Please select a PCAP file or enter configuration data."
      );

    }


    // Send file to FastAPI
    const startRes = await fetch(
      `${API_BASE}/api/analyze`,
      {
        method: "POST",
        body: formData,
      }
    );


    if (!startRes.ok) {

      const errorText = await startRes.text();

      throw new Error(
        `Analysis failed (${startRes.status}): ${errorText}`
      );

    }


        const result = await startRes.json();

        if (result.status !== "complete") {
          throw new Error("Analysis failed.");
        }

        renderResults(result);


  } catch (err) {

    console.error("Analysis error:", err);

    alert(
      "Analysis failed.\n\n" +
      err.message
    );

    showView("upload");


  } finally {

    if (els.analyzeBtn) {
      els.analyzeBtn.disabled = false;
    }

  }

}


// ---------- Poll backend ----------

function pollForResult(jobId) {

  return new Promise((resolve, reject) => {

    const interval = setInterval(async () => {

      try {

        const res = await fetch(
          `${API_BASE}/api/results/${jobId}`
        );


        if (!res.ok) {
          throw new Error("Polling failed.");
        }


        const data = await res.json();
        console.log("RESULT STATUS:", data.status);
        console.log("RESULT DATA:", JSON.stringify(data, null, 2));


        if (data.status === "complete") {

          clearInterval(interval);

          renderResults(data);

          resolve();

        }


        else if (data.status === "not_found") {

          console.log("Result not available yet, retrying...");

        }
      } catch (err) {

        clearInterval(interval);

        reject(err);

      }

    }, 700);

  });

}


// ---------- Render dashboard ----------

function renderResults(data) {

  showView("results");


  // ---------- Analysis data ----------

  const analysis = data.analysis || {};

  const ike = analysis.ike || {};

  const crypto = analysis.crypto || {};

  const esp = analysis.esp || {};



  // ---------- Protocol Intelligence ----------

  setText(
    document.getElementById("protocolValue"),
    analysis.protocol || "Unknown"
  );


  setText(
    document.getElementById("ikeVersionValue"),
    ike.version || "Unknown"
  );


  setText(
    document.getElementById("encryptionValue"),
    crypto.encryption || "Unknown"
  );


  setText(
    document.getElementById("keyLengthValue"),
    crypto.key_length
      ? `${crypto.key_length}-bit`
      : "Unknown"
  );


  setText(
    document.getElementById("integrityValue"),
    crypto.integrity || "Unknown"
  );


  setText(
    document.getElementById("prfValue"),
    crypto.prf || "Unknown"
  );


  setText(
    document.getElementById("dhGroupValue"),
    crypto.dh_group || "Unknown"
  );


  setText(
    document.getElementById("espTrafficValue"),
    esp.packet_count > 0
      ? `Detected (${esp.packet_count})`
      : "Not detected"
  );



  // ---------- Security Score ----------

  const score = Number(data.securityScore ?? 0);

  const circumference = 327;

  const offset =
    circumference -
    (score / 100) * circumference;


  setText(
    els.scoreValue,
    score
  );


  if (els.ringFill) {

    els.ringFill.style.strokeDashoffset = offset;

    els.ringFill.style.stroke =
      score >= 75
        ? "var(--accent)"
        : score >= 45
          ? "var(--warn)"
          : "var(--crit)";

  }


  setText(
    els.scoreFile,
    data.filename || "Unknown"
  );


  setText(
    els.scoreTimestamp,
    data.generatedAt
      ? new Date(data.generatedAt).toLocaleString()
      : "Unknown"
  );



  // ---------- ML Verdict ----------

  const ml = data.mlVerdict || {};


  setText(
    els.mlClassification,
    ml.classification || "Pending"
  );


  if (els.mlClassification) {

    els.mlClassification.className =
      "ml-classification " +
      (ml.classification || "pending");

  }


  if (els.mlBarFill) {

    const confidence =
      Number(ml.confidence ?? 0);

    els.mlBarFill.style.width =
      `${confidence}%`;

  }

  setText(
    els.mlScoreText,
    `${Number(ml.confidence ?? 0).toFixed(1)}%`
  );

  setText(
    els.mlNote,
    ml.modelNote ||
    "XGBoost traffic classification."
  );


  // ---------- Blockchain ----------

  const blockchain =
    data.blockchainProof || {};


  setHTML(
    els.chainStatus,

    `<span class="chain-dot"></span> ` +
    (
      blockchain.verified
        ? "Verified & anchored"
        : "Not verified"
    )
  );


  setText(
    els.chainHash,
    blockchain.txHash || "N/A"
  );


  setText(
    els.chainBlock,
    blockchain.blockNumber ?? 0
  );


  setText(
    els.chainNote,
    blockchain.note ||
    "Blockchain integration pending."
  );



  // ---------- Vulnerabilities ----------

  const vulnerabilities =
    Array.isArray(data.vulnerabilities)
      ? data.vulnerabilities
      : [];


  if (els.vulnList) {

    els.vulnList.innerHTML = "";


    if (vulnerabilities.length === 0) {

      const empty = document.createElement("div");

      empty.className = "vuln-item";

      empty.innerHTML = `
        <div class="vuln-body">
          <div class="vuln-title">
            No security findings
          </div>

          <div class="vuln-detail">
            No vulnerabilities were identified
            by the current security assessment.
          </div>
        </div>
      `;

      els.vulnList.appendChild(empty);

    }


    else {

      vulnerabilities
        .slice()
        .sort(
          (a, b) =>
            sevRank(b.severity) -
            sevRank(a.severity)
        )
        .forEach((v) => {

          const item =
            document.createElement("div");


          item.className =
            "vuln-item";


          const severity =
            String(v.severity || "low")
              .toLowerCase();


          item.innerHTML = `
            <div class="vuln-bar ${severity}"></div>

            <div class="vuln-body">

              <div class="vuln-head">

                <span class="vuln-tag">
                  ${escapeHTML(v.id || "finding")}
                </span>

                <span class="vuln-sev ${severity}">
                  ${escapeHTML(severity)}
                </span>

              </div>

              <div class="vuln-title">
                ${escapeHTML(v.title || "Security finding")}
              </div>

              <div class="vuln-detail">
                ${escapeHTML(v.detail || "")}
              </div>

            </div>
          `;


          els.vulnList.appendChild(item);

        });

    }

  }


  // ---------- Severity chart ----------

  renderSeverityChart(vulnerabilities);

}


// ---------- Escape HTML ----------

function escapeHTML(value) {

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

}


// ---------- Severity ranking ----------

function sevRank(severity) {

  return {
    high: 3,
    medium: 2,
    low: 1,
  }[
    String(severity || "").toLowerCase()
  ] || 0;

}


// ---------- Severity chart ----------

function renderSeverityChart(vulns) {

  const counts = {
    high: 0,
    medium: 0,
    low: 0,
  };


  vulns.forEach((v) => {

    const severity =
      String(v.severity || "low")
        .toLowerCase();


    if (counts[severity] !== undefined) {
      counts[severity]++;
    }

  });


  const ctx =
    document.getElementById("severityChart");


  // Chart element isn't present — don't crash.
  if (!ctx || typeof Chart === "undefined") {
    return;
  }


  if (severityChart) {
    severityChart.destroy();
  }


  severityChart = new Chart(ctx, {

    type: "bar",

    data: {

      labels: [
        "High",
        "Medium",
        "Low"
      ],

      datasets: [

        {

          data: [
            counts.high,
            counts.medium,
            counts.low
          ],

          backgroundColor: [
            "#ef4d68",
            "#f2a340",
            "#5b8def"
          ],

          borderRadius: 4,

          barThickness: 36,

        },

      ],

    },


    options: {

      plugins: {
        legend: {
          display: false
        }
      },


      scales: {

        x: {

          grid: {
            display: false
          },

          ticks: {
            color: "#8a97b3",

            font: {
              family: "IBM Plex Mono",
              size: 11
            }

          }

        },


        y: {

          beginAtZero: true,

          ticks: {

            stepSize: 1,

            color: "#8a97b3",

            font: {
              family: "IBM Plex Mono",
              size: 11
            }

          },

          grid: {
            color: "#24304a"
          }

        }

      }

    }

  });

}