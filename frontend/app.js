const scanButton = document.getElementById("scanButton");
const projectPath = document.getElementById("projectPath");
const scanStatus = document.getElementById("scanStatus");

const securityScore = document.getElementById("securityScore");
const riskLevel = document.getElementById("riskLevel");

const criticalCount = document.getElementById("criticalCount");
const highCount = document.getElementById("highCount");
const mediumCount = document.getElementById("mediumCount");
const lowCount = document.getElementById("lowCount");

const findingsTable = document.getElementById("findingsTable");
const recommendation = document.getElementById("recommendation");

const showAllFindings = document.getElementById("showAllFindings");
const findingsTitle = document.getElementById("findingsTitle");
const findingsSubtitle = document.getElementById("findingsSubtitle");

const secretScannerCount =
    document.getElementById("secretScannerCount");

const fileScannerCount =
    document.getElementById("fileScannerCount");

const dependencyScannerCount =
    document.getElementById("dependencyScannerCount");

const scannerCards =
    document.querySelectorAll(".scanner-filter");

let allFindings = [];


/*
 * Calculate security score from real findings.
 */
function calculateScore(findings) {
    let score = 100;

    findings.forEach((finding) => {
        switch (String(finding.severity).toUpperCase()) {
            case "CRITICAL":
                score -= 30;
                break;

            case "HIGH":
                score -= 15;
                break;

            case "MEDIUM":
                score -= 7;
                break;

            case "LOW":
                score -= 2;
                break;
        }
    });

    return Math.max(score, 0);
}


/*
 * Determine risk level.
 */
function getRiskLevel(score) {
    if (score >= 90) {
        return "LOW RISK";
    }

    if (score >= 70) {
        return "MEDIUM RISK";
    }

    if (score >= 40) {
        return "HIGH RISK";
    }

    return "CRITICAL RISK";
}


/*
 * Update severity counts.
 */
function updateSeverityCounts(findings) {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    findings.forEach((finding) => {
        switch (String(finding.severity).toUpperCase()) {
            case "CRITICAL":
                critical++;
                break;

            case "HIGH":
                high++;
                break;

            case "MEDIUM":
                medium++;
                break;

            case "LOW":
                low++;
                break;
        }
    });

    criticalCount.textContent = critical;
    highCount.textContent = high;
    mediumCount.textContent = medium;
    lowCount.textContent = low;
}


/*
 * Identify scanner category from finding rule.
 */
function getScannerType(finding) {
    const rule = String(finding.rule || "").toUpperCase();

    if (
        rule.includes("SECRET") ||
        rule.includes("TOKEN") ||
        rule.includes("PRIVATE_KEY") ||
        rule.includes("API_KEY") ||
        rule.includes("PASSWORD")
    ) {
        return "secret";
    }

    if (
        rule.includes("SENSITIVE_FILE") ||
        rule.includes("FILE_RISK")
    ) {
        return "file";
    }

    if (
        rule.includes("DEPENDENCY") ||
        rule.includes("MANIFEST")
    ) {
        return "dependency";
    }

    return "other";
}


/*
 * Update scanner card counts.
 */
function updateScannerCounts(findings) {
    let secret = 0;
    let file = 0;
    let dependency = 0;

    findings.forEach((finding) => {
        const scanner = getScannerType(finding);

        if (scanner === "secret") {
            secret++;
        } else if (scanner === "file") {
            file++;
        } else if (scanner === "dependency") {
            dependency++;
        }
    });

    secretScannerCount.textContent = secret;
    fileScannerCount.textContent = file;
    dependencyScannerCount.textContent = dependency;
}


/*
 * Create severity badge.
 */
function createSeverityBadge(severity) {
    const badge = document.createElement("span");

    badge.classList.add("badge");

    const normalizedSeverity =
        String(severity).toUpperCase();

    badge.classList.add(
        `badge-${normalizedSeverity.toLowerCase()}`
    );

    badge.textContent = normalizedSeverity;

    return badge;
}


/*
 * Display findings.
 */
function displayFindings(findings) {
    findingsTable.innerHTML = "";

    if (findings.length === 0) {
        const row = document.createElement("tr");

        const cell = document.createElement("td");
        cell.colSpan = 5;
        cell.className = "empty";
        cell.textContent = "No security issues found.";

        row.appendChild(cell);
        findingsTable.appendChild(row);

        return;
    }

    findings.forEach((finding) => {
        const row = document.createElement("tr");

        const severityCell = document.createElement("td");
        severityCell.appendChild(
            createSeverityBadge(finding.severity)
        );

        const fileCell = document.createElement("td");
        fileCell.textContent = finding.file || "-";

        const lineCell = document.createElement("td");
        lineCell.textContent =
            finding.line === null ||
            finding.line === undefined
                ? "-"
                : finding.line;

        const ruleCell = document.createElement("td");
        ruleCell.textContent = finding.rule || "-";

        const messageCell = document.createElement("td");
        messageCell.textContent =
            finding.message || "-";

        row.appendChild(severityCell);
        row.appendChild(fileCell);
        row.appendChild(lineCell);
        row.appendChild(ruleCell);
        row.appendChild(messageCell);

        findingsTable.appendChild(row);
    });
}


/*
 * Display recommendation.
 */
function displayRecommendation(findings) {
    if (findings.length === 0) {
        recommendation.textContent =
            "No immediate security actions are required.";
        return;
    }

    const critical = findings.some(
        (finding) =>
            String(finding.severity).toUpperCase() ===
            "CRITICAL"
    );

    const secret = findings.some(
        (finding) => {
            const rule =
                String(finding.rule || "").toUpperCase();

            return (
                rule.includes("SECRET") ||
                rule.includes("TOKEN") ||
                rule.includes("PRIVATE_KEY") ||
                rule.includes("API_KEY")
            );
        }
    );

    if (critical) {
        recommendation.textContent =
            "Critical security issues were detected. " +
            "Remove sensitive files or credentials and " +
            "rescan the project.";
        return;
    }

    if (secret) {
        recommendation.textContent =
            "Move hardcoded credentials to environment " +
            "variables and avoid storing secrets directly " +
            "in source code.";
        return;
    }

    recommendation.textContent =
        "Review the reported findings and apply the " +
        "recommended security improvements.";
}


/*
 * Update complete dashboard.
 */
function updateDashboard(findings) {
    const score = calculateScore(findings);
    const risk = getRiskLevel(score);

    securityScore.textContent = score;
    riskLevel.textContent = risk;

    updateSeverityCounts(findings);
    updateScannerCounts(findings);
    displayFindings(findings);
    displayRecommendation(findings);
}


/*
 * Filter findings by scanner.
 */
function filterByScanner(scannerType) {
    const filteredFindings = allFindings.filter(
        (finding) =>
            getScannerType(finding) === scannerType
    );

    const scannerNames = {
        secret: "Secret Scanner",
        file: "File Risk Scanner",
        dependency: "Dependency Scanner"
    };

    const scannerName =
        scannerNames[scannerType] || "Scanner";

    findingsTitle.textContent =
        `${scannerName} Findings`;

    findingsSubtitle.textContent =
        `${filteredFindings.length} finding(s) detected by ${scannerName}.`;

    displayFindings(filteredFindings);

    scannerCards.forEach((card) => {
        card.classList.toggle(
            "active",
            card.dataset.scanner === scannerType
        );
    });
}


/*
 * Show all findings.
 */
function showAll() {
    findingsTitle.textContent = "Security Findings";

    findingsSubtitle.textContent =
        "Issues detected during the latest scan.";

    displayFindings(allFindings);

    scannerCards.forEach((card) => {
        card.classList.remove("active");
    });
}


/*
 * Connect scanner cards.
 */
scannerCards.forEach((card) => {
    card.addEventListener("click", () => {
        filterByScanner(card.dataset.scanner);
    });
});


/*
 * View all findings.
 */
showAllFindings.addEventListener("click", showAll);


/*
 * Scan project using real backend.
 */
async function scanProject(path) {
    const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            path: path
        })
    });

    let data;

    try {
        data = await response.json();
    } catch (error) {
        throw new Error(
            "Invalid response received from DevGuard server."
        );
    }

    if (!response.ok || !data.success) {
        throw new Error(
            data.error || "DevGuard scan failed."
        );
    }

    return data;
}


/*
 * Scan button.
 */
scanButton.addEventListener("click", async () => {
    const path = projectPath.value.trim();

    if (!path) {
        scanStatus.textContent =
            "Please enter a project path.";
        return;
    }

    scanStatus.textContent =
        "Scanning project...";

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    try {
        const data = await scanProject(path);

        allFindings = Array.isArray(data.findings)
            ? data.findings
            : [];

        updateDashboard(allFindings);
        showAll();

        scanStatus.textContent =
            `Scan completed for: ${path} (${data.total} findings)`;

    } catch (error) {
        console.error(
            "DevGuard scan error:",
            error
        );

        scanStatus.textContent =
            `Scan failed: ${error.message}`;

    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan Project";
    }
});