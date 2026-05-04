from flask import Flask, render_template, jsonify, request, Response
from datetime import datetime
import threading
import csv
import io

import sniffer
from stats import calculate_stats

app = Flask(__name__)

sniff_thread = None

event_logs = []


def add_log(message):
    """Add a message to the event log with a timestamp."""
    time_now = datetime.now().strftime("%H:%M:%S")
    event_logs.append(f"[{time_now}] {message}")

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start():
    global sniff_thread

    if sniffer.is_capturing:
        return jsonify({"status": "already running"})

    sniff_thread = threading.Thread(target=sniffer.start_sniffing, daemon=True)
    sniff_thread.start()

    add_log("Monitoring started")
    return jsonify({"status": "started"})


@app.route("/stop", methods=["POST"])
def stop():
    sniffer.stop_sniffing()
    add_log("Monitoring stopped")
    return jsonify({"status": "stopped"})


@app.route("/clear", methods=["POST"])
def clear():
    sniffer.clear_packets()
    add_log("Packet list cleared")
    return jsonify({"status": "cleared"})


@app.route("/packets")
def get_packets():
    protocol = request.args.get("protocol", "ALL")
    source_ip = request.args.get("source_ip", "").strip()
    destination_ip = request.args.get("destination_ip", "").strip()

    result = sniffer.captured_packets

    if protocol != "ALL":
        result = [p for p in result if p["protocol"] == protocol]
    if source_ip:
        result = [p for p in result if source_ip in p["source_ip"]]
    if destination_ip:
        result = [p for p in result if destination_ip in p["destination_ip"]]

    return jsonify({
        "packets": result,
        "total_captured": len(sniffer.captured_packets),
        "showing": len(result)
    })


@app.route("/stats")
def get_stats():
    return jsonify(calculate_stats(sniffer.captured_packets))


@app.route("/logs")
def get_logs():
    return jsonify({"logs": event_logs})


@app.route("/download/packets")
def download_packets():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Time", "Source IP", "Destination IP", "Protocol",
                     "Source Port", "Destination Port", "Website", "Size"])

    for p in sniffer.captured_packets:
        writer.writerow([p["time"], p["source_ip"], p["destination_ip"],
                         p["protocol"], p["source_port"], p["destination_port"],
                         p["website"], p["size"]])

    add_log("Packets downloaded as CSV")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packets.csv"}
    )


@app.route("/download/logs")
def download_logs():
    text = "\n".join(event_logs)
    add_log("Logs downloaded")
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=logs.txt"}
    )


if __name__ == "__main__":
    print("Starting Network Monitor on http://127.0.0.1:5000")
    app.run(debug=False)
