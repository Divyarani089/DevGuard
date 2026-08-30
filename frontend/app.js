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


/*
 * Temporary demo data.
 *
 * This will later be replaced by real results
 * from the DevGuard Python scanner.
 */
const demoFindings = [
    {
        severity: "HIGH",
        file: "app.py",
        line: 24,
        rule: "HARDCODED_SECRET",
        message: "Possible hardcoded secret detected"
    },
    {
        severity: "CRITICAL",
        file: ".env",
        line: null,
        rule: "SENSITIVE_FILE",
        message: "Sensitive environment file detected"
    },
    {
        severity: "LOW",
        file: "requirements.txt",
        line: 1,
        rule: "DEPENDENCY_MANIFEST",
        message: "Dependency manifest detected"
    }
];


/*
 * Calculate a simple security score.
 *
 * This is only temporary UI logic.
 * The final scoring engine will come from
 * the backend/risk-scoring module.
 */
function calculateDemoScore(findings) {
    let score = 100;

    findings.forEach((finding) => {
        switch (finding.severity) {
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
 * Determine risk level from score.
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
 * Count findings by severity.
 */
function updateSeverityCounts(findings) {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    findings.forEach((finding) => {
        switch (finding.severity) {
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
 * Create a severity badge.
 */
function createSeverityBadge(severity) {
    const badge = document.createElement("span");

    badge.classList.add("badge");

    const className = `badge-${severity.toLowerCase()}`;
    badge.classList.add(className);

    badge.textContent = severity;

    return badge;
}


/*
 * Display findings in the table.
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
        fileCell.textContent = finding.file;

        const lineCell = document.createElement("td");
        lineCell.textContent =
            finding.line === null ? "-" : finding.line;

        const ruleCell = document.createElement("td");
        ruleCell.textContent = finding.rule;

        const messageCell = document.createElement("td");
        messageCell.textContent = finding.message;

        row.appendChild(severityCell);
        row.appendChild(fileCell);
        row.appendChild(lineCell);
        row.appendChild(ruleCell);
        row.appendChild(messageCell);

        findingsTable.appendChild(row);
    });
}


/*
 * Display recommendation based on the findings.
 */
function displayRecommendation(findings) {
    if (findings.length === 0) {
        recommendation.textContent =
            "No immediate security actions are required.";
        return;
    }

    const critical = findings.some(
        (finding) => finding.severity === "CRITICAL"
    );

    const secret = findings.some(
        (finding) =>
            finding.rule === "HARDCODED_SECRET" ||
            finding.rule === "PRIVATE_KEY"
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
 * Update the complete dashboard.
 */
function updateDashboard(findings) {
    const score = calculateDemoScore(findings);
    const risk = getRiskLevel(score);

    securityScore.textContent = score;
    riskLevel.textContent = risk;

    updateSeverityCounts(findings);
    displayFindings(findings);
    displayRecommendation(findings);
}


/*
 * Scan button.
 *
 * For now this displays demo data.
 * In the next step we will replace this
 * with the real Python DevGuard backend.
 */
scanButton.addEventListener("click", () => {
    const path = projectPath.value.trim();

    if (!path) {
        scanStatus.textContent =
            "Please enter a project path.";

        return;
    }

    scanStatus.textContent = "Scanning project...";

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    setTimeout(() => {
        updateDashboard(demoFindings);

        scanStatus.textContent =
            `Scan completed for: ${path}`;

        scanButton.disabled = false;
        scanButton.textContent = "Scan Project";
    }, 700);
});