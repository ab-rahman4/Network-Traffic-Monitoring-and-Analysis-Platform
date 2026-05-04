const startBtn = document.getElementById("start-btn");
const stopBtn  = document.getElementById("stop-btn");
const clearBtn = document.getElementById("clear-btn");
const applyBtn = document.getElementById("apply-filter");
const resetBtn = document.getElementById("reset-filter");

const statusDot  = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const packetBody = document.getElementById("packet-body");
const filterInfo = document.getElementById("filter-info");
const logBox     = document.getElementById("log-box");

const detailsCard    = document.getElementById("details-card");
const detailsContent = document.getElementById("details-content");

let refreshTimer = null;

let lastShownCount = 0;


startBtn.onclick = async () => {
    await fetch("/start", { method: "POST" });
    statusDot.className = "dot-running";
    statusText.textContent = "Monitoring";
    startAutoRefresh();
};

stopBtn.onclick = async () => {
    await fetch("/stop", { method: "POST" });
    statusDot.className = "dot-stopped";
    statusText.textContent = "Stopped";
    stopAutoRefresh();
    updateLogs();
};

clearBtn.onclick = async () => {
    await fetch("/clear", { method: "POST" });
    packetBody.innerHTML = "";
    lastShownCount = 0;
    updateStats();
    updateLogs();
};

applyBtn.onclick = () => {
    lastShownCount = 0;
    packetBody.innerHTML = "";
    updatePackets();
};

resetBtn.onclick = () => {
    document.getElementById("filter-protocol").value = "ALL";
    document.getElementById("filter-src").value = "";
    document.getElementById("filter-dst").value = "";
    lastShownCount = 0;
    packetBody.innerHTML = "";
    updatePackets();
};


function startAutoRefresh() {
    if (refreshTimer !== null) return;
    refreshTimer = setInterval(() => {
        updatePackets();
        updateStats();
        updateLogs();
    }, 2000);
}

function stopAutoRefresh() {
    if (refreshTimer !== null) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}


async function updatePackets() {
    const protocol = document.getElementById("filter-protocol").value;
    const src = document.getElementById("filter-src").value;
    const dst = document.getElementById("filter-dst").value;

    const url = `/packets?protocol=${protocol}&source_ip=${src}&destination_ip=${dst}`;
    const response = await fetch(url);
    const data = await response.json();

    filterInfo.textContent = `Showing ${data.showing} of ${data.total_captured} packets`;

    const recent = data.packets.slice(-100);

    if (recent.length < lastShownCount) {
        packetBody.innerHTML = "";
        lastShownCount = 0;
    }

    const newOnes = recent.slice(lastShownCount);
    newOnes.forEach(p => {
        const row = document.createElement("tr");
        row.className = "new-row";
        row.innerHTML = `
            <td>${p.time}</td>
            <td>${p.source_ip}</td>
            <td>${p.destination_ip}</td>
            <td><span class="badge badge-${p.protocol.toLowerCase()}">${p.protocol}</span></td>
            <td>${p.source_port}</td>
            <td>${p.destination_port}</td>
            <td>${p.website}</td>
            <td>${p.size}</td>
        `;
        row.onclick = () => showDetails(p);
        packetBody.insertBefore(row, packetBody.firstChild);
    });

    lastShownCount = recent.length;
}

async function updateStats() {
    const response = await fetch("/stats");
    const s = await response.json();
    document.getElementById("stat-total").textContent = s.total;
    document.getElementById("stat-tcp").textContent   = s.tcp;
    document.getElementById("stat-udp").textContent   = s.udp;
    document.getElementById("stat-icmp").textContent  = s.icmp;
    document.getElementById("stat-avg").textContent   = s.avg_size;
    document.getElementById("stat-max").textContent   = s.max_size;
    document.getElementById("stat-top-src").textContent = s.top_source;
    document.getElementById("stat-top-dst").textContent = s.top_destination;
}

async function updateLogs() {
    const response = await fetch("/logs");
    const data = await response.json();
    logBox.innerHTML = data.logs.map(l => `<div>${l}</div>`).join("");
    logBox.scrollTop = logBox.scrollHeight;
}

function showDetails(p) {
    detailsCard.style.display = "block";
    detailsContent.textContent =
`========== PACKET DETAILS ==========

Time:                ${p.time}
Size:                ${p.size} bytes

----- IP LAYER -----
Source IP:           ${p.source_ip}
Destination IP:      ${p.destination_ip}

----- TRANSPORT LAYER -----
Protocol:            ${p.protocol}
Source Port:         ${p.source_port}
Destination Port:    ${p.destination_port}

----- APPLICATION LAYER -----
Website / Host:      ${p.website}

----- RAW SUMMARY (from Scapy) -----
${p.summary}
`;
    detailsCard.scrollIntoView({ behavior: "smooth" });
}

updatePackets();
updateStats();
updateLogs();
