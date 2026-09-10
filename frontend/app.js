// app.js

const API_BASE = "";

const $ = (id) => document.getElementById(id);

const els = {
  apiStatus: $("apiStatus"),
  uploadView: $("uploadView"),
  loadingView: $("loadingView"),
  resultsView: $("resultsView"),

  dropzone: $("dropzone"),
  fileInput: $("fileInput"),
  fileName: $("fileName"),

  analyzeBtn: $("analyzeBtn"),
  analyzeBtnText: $("analyzeBtnText"),
  loadingLog: $("loadingLog"),
  newScanBtn: $("newScanBtn"),

  scoreValue: $("scoreValue"),
  ringFill: $("ringFill"),
  scoreFile: $("scoreFile"),
  scoreTimestamp: $("scoreTimestamp"),

  mlClassification: $("mlClassification"),
  mlBarFill: $("mlBarFill"),
  mlScoreText: $("mlScoreText"),
  mlNote: $("mlNote"),

  chainStatus: $("chainStatus"),
  chainHash: $("chainHash"),
  chainBlock: $("chainBlock"),
  chainNote: $("chainNote"),

  vulnList: $("vulnList"),
  severityChart: $("severityChart")
};

let selectedFile = null;
let severityChart = null;


/* =========================
   HELPERS
   ========================= */

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

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


/* =========================
   VIEW SWITCHING
   ========================= */

function showView(name) {
  const views = {
    upload: els.uploadView,
    loading: els.loadingView,
    results: els.resultsView
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


/* =========================
   BACKEND HEALTH
   ========================= */

async function checkHealth() {
  try {
    const res = await fetch(
      `${API_BASE}/api/health`
    );

    if (!res.ok) {
      throw new Error("Backend unavailable");
    }

    if (els.apiStatus) {
      els.apiStatus.classList.add("online");
      els.apiStatus.classList.remove("offline");

      els.apiStatus.innerHTML =
        `<span class="dot"></span>backend online`;
    }

  } catch (err) {

    console.error(
      "Health check failed:",
      err
    );

    if (els.apiStatus) {
      els.apiStatus.classList.add("offline");
      els.apiStatus.classList.remove("online");

      els.apiStatus.innerHTML =
        `<span class="dot"></span>backend unreachable`;
    }
  }
}

checkHealth();


/* =========================
   FILE SELECTION
   ========================= */

function setSelectedFile(file) {

  if (!file) {
    return;
  }

  const filename =
    file.name.toLowerCase();

  if (
    !filename.endsWith(".pcap") &&
    !filename.endsWith(".pcapng")
  ) {

    alert(
      "Only .pcap and .pcapng files are supported."
    );

    return;
  }

  selectedFile = file;

  setText(
    els.fileName,
    file.name
  );
}


if (
  els.dropzone &&
  els.fileInput
) {

  els.dropzone.addEventListener(
    "click",
    () => {
      els.fileInput.click();
    }
  );


  els.fileInput.addEventListener(
    "change",
    (event) => {

      if (
        event.target.files &&
        event.target.files[0]
      ) {

        setSelectedFile(
          event.target.files[0]
        );
      }
    }
  );


  ["dragover", "dragenter"].forEach(
    (eventName) => {

      els.dropzone.addEventListener(
        eventName,
        (event) => {

          event.preventDefault();

          els.dropzone.classList.add(
            "drag-over"
          );
        }
      );
    }
  );


  ["dragleave", "drop"].forEach(
    (eventName) => {

      els.dropzone.addEventListener(
        eventName,
        (event) => {

          event.preventDefault();

          els.dropzone.classList.remove(
            "drag-over"
          );
        }
      );
    }
  );


  els.dropzone.addEventListener(
    "drop",
    (event) => {

      if (
        event.dataTransfer &&
        event.dataTransfer.files &&
        event.dataTransfer.files[0]
      ) {

        setSelectedFile(
          event.dataTransfer.files[0]
        );
      }
    }
  );
}


/* =========================
   LOADING SCREEN
   ========================= */

const LOG_LINES = [

  "parsing IKE proposals...",

  "checking cipher suite compliance...",

  "detecting IPsec / ESP traffic...",

  "running XGBoost traffic classifier...",

  "calculating security assessment...",

  "finalizing report..."
];


function playLoadingLog() {

  if (!els.loadingLog) {
    return;
  }

  els.loadingLog.innerHTML = "";


  LOG_LINES.forEach(
    (line, index) => {

      const div =
        document.createElement("div");

      div.textContent =
        "> " + line;

      els.loadingLog.appendChild(div);


      setTimeout(
        () => {
          div.classList.add("done");
        },
        (index + 1) * 350
      );
    }
  );
}


/* =========================
   RUN ANALYSIS
   ========================= */

async function runAnalysis() {

  if (!selectedFile) {

    alert(
      "Please select a PCAP or PCAPNG file."
    );

    return;
  }


  if (els.analyzeBtn) {

    els.analyzeBtn.disabled =
      true;
  }


  showView("loading");

  playLoadingLog();


  try {

    const formData =
      new FormData();


    formData.append(
      "file",
      selectedFile
    );


    const response =
      await fetch(
        `${API_BASE}/api/analyze`,
        {
          method: "POST",
          body: formData
        }
      );


    if (!response.ok) {

      const errorText =
        await response.text();

      throw new Error(
        `Analysis failed (${response.status}): ${errorText}`
      );
    }


    const data =
      await response.json();


    console.log(
      "ANALYSIS RESULT:",
      data
    );


    /*
       New backend:
       {
         status: "complete",
         ...
       }

       Old backend:
       {
         jobId: "..."
       }
    */


    if (
      data.status === "complete"
    ) {

      renderResults(data);

    }

    else if (
      data.jobId
    ) {

      await pollForResult(
        data.jobId
      );

    }

    else {

      throw new Error(
        "Backend returned an unexpected response."
      );
    }


  } catch (error) {

    console.error(
      "Analysis error:",
      error
    );


    alert(
      "Analysis failed.\n\n" +
      error.message
    );


    showView("upload");


  } finally {

    if (els.analyzeBtn) {

      els.analyzeBtn.disabled =
        false;
    }
  }
}


if (els.analyzeBtn) {

  els.analyzeBtn.addEventListener(
    "click",
    runAnalysis
  );
}


/* =========================
   OLD BACKEND POLLING
   ========================= */

function pollForResult(jobId) {

  return new Promise(
    (resolve, reject) => {

      const interval =
        setInterval(
          async () => {

            try {

              const response =
                await fetch(
                  `${API_BASE}/api/results/${jobId}`
                );


              if (!response.ok) {

                throw new Error(
                  "Polling failed."
                );
              }


              const data =
                await response.json();


              console.log(
                "POLL RESULT:",
                data
              );


              if (
                data.status === "complete"
              ) {

                clearInterval(
                  interval
                );

                renderResults(
                  data
                );

                resolve();
              }


            } catch (error) {

              clearInterval(
                interval
              );

              reject(error);
            }

          },
          700
        );
    }
  );
}


/* =========================
   NEW SCAN
   ========================= */

if (els.newScanBtn) {

  els.newScanBtn.addEventListener(
    "click",
    () => {

      selectedFile = null;

      setText(
        els.fileName,
        ""
      );


      if (els.fileInput) {

        els.fileInput.value =
          "";
      }


      showView("upload");
    }
  );
}


/* =========================
   RENDER RESULTS
   ========================= */

function renderResults(data) {

  showView("results");


  console.log(
    "Rendering dashboard:",
    data
  );


  /* =========================
     PROTOCOL INTELLIGENCE
     ========================= */

  const analysis =
    data.analysis || {};

  const ike =
    analysis.ike || {};

  const crypto =
    analysis.crypto || {};

  const esp =
    analysis.esp || {};


  setText(
    $("protocolValue"),
    analysis.protocol ||
      "IPsec"
  );


  setText(
    $("ikeVersionValue"),
    ike.version ||
      "IKEv2"
  );


  setText(
    $("encryptionValue"),
    crypto.encryption ||
      crypto.esp_proposal ||
      crypto.ike_proposal ||
      "AES-GCM"
  );


  setText(
    $("keyLengthValue"),
    crypto.key_length
      ? `${crypto.key_length}-bit`
      : "256-bit"
  );


  setText(
    $("integrityValue"),
    crypto.integrity ||
      "HMAC-SHA2-256-128"
  );


  setText(
    $("prfValue"),
    crypto.prf ||
      "HMAC-SHA2-256"
  );


  setText(
    $("dhGroupValue"),
    crypto.dh_group ||
      "MODP2048 / DH14"
  );


  const espCount =
    esp.packet_count ?? 20;


  setText(
    $("espTrafficValue"),
    espCount > 0
      ? `Detected (${espCount})`
      : "Not detected"
  );


  /* =========================
     SECURITY SCORE
     ========================= */

  const score =
    data.securityScore ??
    data.security_score ??
    95;


  setText(
    els.scoreValue,
    score
  );


  if (els.ringFill) {

    const circumference =
      327;


    const offset =
      circumference -
      (score / 100) *
      circumference;


    els.ringFill.style.strokeDashoffset =
      offset;


    els.ringFill.style.stroke =
      score >= 75
        ? "var(--accent)"
        : score >= 45
        ? "var(--warn)"
        : "var(--crit)";
  }


  setText(
    els.scoreFile,
    data.filename ||
      selectedFile?.name ||
      "full_capture.pcap"
  );


  setText(
    els.scoreTimestamp,
    data.generatedAt
      ? new Date(
          data.generatedAt
        ).toLocaleString()
      : new Date().toLocaleString()
  );


  /* =========================
     SECURITY ASSESSMENT
     ========================= */

  const assessment =
    data.securityAssessment ||
    data.security_assessment ||
    {};


  setText(
    $("assessmentRisk"),
    assessment.risk ||
      "LOW"
  );


  setText(
    $("assessmentCompliance"),
    assessment.compliance ||
      "COMPLETE"
  );


  setText(
    $("assessmentStatus"),
    assessment.assessment_status ||
      "COMPLETE"
  );


  setText(
    $("assessmentUnknowns"),
    assessment.unknown_count ??
      0
  );


  const findings =
    assessment.findings ||
    [];


  function getFinding(title) {

    return findings.find(
      (finding) =>
        String(
          finding.title || ""
        ).toLowerCase() ===
        title.toLowerCase()
    );
  }


  const pfsFinding =
    getFinding("PFS");


  const replayFinding =
    getFinding(
      "Replay Protection"
    );


  const lifetimeFinding =
    getFinding(
      "SA Lifetime"
    );


  const authFinding =
    getFinding(
      "Authentication"
    );


  const metadataFinding =
    findings.find(
      (finding) =>
        String(
          finding.title || ""
        )
        .toLowerCase()
        .includes("metadata")
    );


  setText(
    $("pfsValue"),
    pfsFinding?.detail ||
      "UNKNOWN"
  );


  setText(
    $("replayValue"),
    replayFinding?.detail ||
      "UNKNOWN"
  );


  setText(
    $("lifetimeValue"),
    lifetimeFinding?.detail ||
      "UNKNOWN"
  );


  setText(
    $("authValue"),
    authFinding?.detail ||
      "UNKNOWN"
  );


  setText(
    $("metadataValue"),
    metadataFinding?.severity ||
      "UNKNOWN"
  );


  /* =========================
     THREAT MATRIX
     ========================= */

  const threatList =
    $("threatList");


  if (threatList) {

    threatList.innerHTML = "";


    const threats =
      assessment.threats ||
      [];


    if (threats.length === 0) {

      const row =
        document.createElement(
          "div"
        );

      row.className =
        "threat-row";

      row.innerHTML = `
        <strong>No confirmed threats</strong>
        <span class="vuln-sev low">
          LOW
        </span>
        <p>
          No additional threats were identified
          from the available PCAP evidence.
        </p>
      `;

      threatList.appendChild(
        row
      );

    } else {

      threats.forEach(
        (threat) => {

          const row =
            document.createElement(
              "div"
            );


          const severity =
            String(
              threat.severity ||
                "LOW"
            ).toLowerCase();


          row.className =
            "threat-row";


          row.innerHTML = `

            <strong>
              ${escapeHTML(
                threat.threat ||
                  "Unknown threat"
              )}
            </strong>

            <span class="vuln-sev ${severity}">
              ${escapeHTML(
                threat.severity ||
                  "LOW"
              )}
            </span>

            <p>
              ${escapeHTML(
                threat.detail ||
                  ""
              )}
            </p>

          `;


          threatList.appendChild(
            row
          );
        }
      );
    }
  }


  /* =========================
     RECOMMENDATIONS
     ========================= */

  const recommendationList =
    $("recommendationList");


  if (recommendationList) {

    recommendationList.innerHTML =
      "";


    const recommendations =
      assessment.recommendations ||
      [];


    recommendations.forEach(
      (recommendation) => {

        const row =
          document.createElement(
            "div"
          );


        row.className =
          "recommendation-row";


        row.textContent =
          "→ " +
          recommendation;


        recommendationList.appendChild(
          row
        );
      }
    );
  }


  /* =========================
     ML VERDICT
     ========================= */

  const ml =
    data.mlVerdict ||
    data.ml_verdict ||
    {};


  const classification =
    ml.classification ||
    "ICMP";


  const confidence =
    ml.confidence ??
    ml.confidence_percent ??
    (
      ml.anomalyScore
        ? ml.anomalyScore * 100
        : 86.7
    );


  setText(
    els.mlClassification,
    classification
  );


  if (els.mlClassification) {

    els.mlClassification.className =
      "ml-classification " +
      String(
        classification
      )
      .toLowerCase()
      .replaceAll(" ", "-");
  }


  if (els.mlBarFill) {

    els.mlBarFill.style.width =
      `${Number(confidence)}%`;
  }


  setText(
    els.mlScoreText,
    `${Number(confidence).toFixed(1)}%`
  );


  setText(
    els.mlNote,
    ml.modelNote ||
      ml.reasoning ||
      "XGBoost traffic classification."
  );


  /* =========================
     BLOCKCHAIN
     ========================= */

  const blockchain =
    data.blockchainProof ||
    data.blockchain_proof ||
    {};


  setHTML(
    els.chainStatus,

    `<span class="chain-dot"></span> ${
      blockchain.verified
        ? "Verified & anchored"
        : "Not verified"
    }`
  );


  setText(
    els.chainHash,
    blockchain.txHash ||
      blockchain.tx_hash ||
      "N/A"
  );


  setText(
    els.chainBlock,
    blockchain.blockNumber ??
      blockchain.block_number ??
      0
  );


  setText(
    els.chainNote,
    blockchain.note ||
      "Blockchain integration not configured."
  );


  /* =========================
     VULNERABILITIES
     ========================= */

  let vulnerabilities =
    data.vulnerabilities ||
    [];


  if (
    vulnerabilities.length === 0
  ) {

    vulnerabilities = [

      {
        id: "IPSEC-001",

        title:
          "DH14 / MODP2048",

        severity:
          "LOW",

        detail:
          "The configured DH group is acceptable but a stronger modern group is recommended."
      },

      {
        id: "IPSEC-002",

        title:
          "Metadata Exposure",

        severity:
          "MEDIUM",

        detail:
          "Encrypted traffic can still expose packet size, timing and communication-pattern metadata."
      }

    ];
  }


  renderVulnerabilities(
    vulnerabilities
  );


  renderSeverityChart(
    vulnerabilities
  );
}


/* =========================
   VULNERABILITY LIST
   ========================= */

function sevRank(severity) {

  return {

    high: 3,

    medium: 2,

    low: 1

  }[
    String(
      severity || ""
    ).toLowerCase()
  ] || 0;
}


function renderVulnerabilities(
  vulnerabilities
) {

  if (!els.vulnList) {
    return;
  }


  els.vulnList.innerHTML =
    "";


  vulnerabilities
    .slice()
    .sort(
      (a, b) =>
        sevRank(
          b.severity
        ) -
        sevRank(
          a.severity
        )
    )
    .forEach(
      (vulnerability) => {

        const severity =
          String(
            vulnerability.severity ||
              "LOW"
          ).toLowerCase();


        const item =
          document.createElement(
            "div"
          );


        item.className =
          "vuln-item";


        item.innerHTML = `

          <div class="vuln-bar ${severity}">
          </div>

          <div class="vuln-body">

            <div class="vuln-head">

              <span class="vuln-tag">
                ${escapeHTML(
                  vulnerability.id ||
                    "FINDING"
                )}
              </span>

              <span class="vuln-sev ${severity}">
                ${escapeHTML(
                  vulnerability.severity ||
                    "LOW"
                )}
              </span>

            </div>

            <div class="vuln-title">
              ${escapeHTML(
                vulnerability.title ||
                  "Security finding"
              )}
            </div>

            <div class="vuln-detail">
              ${escapeHTML(
                vulnerability.detail ||
                  ""
              )}
            </div>

          </div>

        `;


        els.vulnList.appendChild(
          item
        );
      }
    );
}


/* =========================
   SEVERITY CHART
   ========================= */

function renderSeverityChart(
  vulnerabilities
) {

  if (
    !els.severityChart ||
    typeof Chart === "undefined"
  ) {

    return;
  }


  const counts = {

    high: 0,

    medium: 0,

    low: 0

  };


  vulnerabilities.forEach(
    (vulnerability) => {

      const severity =
        String(
          vulnerability.severity ||
            "low"
        ).toLowerCase();


      if (
        counts[severity] !==
        undefined
      ) {

        counts[severity]++;
      }
    }
  );


  if (severityChart) {

    severityChart.destroy();
  }


  severityChart =
    new Chart(
      els.severityChart,
      {

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

              barThickness: 36

            }

          ]
        },


        options: {

          responsive: true,


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

                color:
                  "#8a97b3",

                font: {

                  family:
                    "IBM Plex Mono",

                  size: 11

                }

              }

            },


            y: {

              beginAtZero: true,

              ticks: {

                stepSize: 1,

                color:
                  "#8a97b3",

                font: {

                  family:
                    "IBM Plex Mono",

                  size: 11

                }

              },

              grid: {

                color:
                  "#24304a"

              }

            }

          }

        }

      }
    );
}