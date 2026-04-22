from flask import Flask, render_template, request, send_file
import pandas as pd
import os
import re
from Evtx.Evtx import Evtx
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =========================================================
# 🔥 EVTX READER
# =========================================================
def read_evtx(file_path):

    logs = []

    with Evtx(file_path) as log:
        for record in log.records():

            xml = record.xml()

            if "4625" not in xml and "4624" not in xml:
                continue

            ip_match = re.search(r'IpAddress">([\d\.]+)', xml)
            if not ip_match:
                continue
            ip = ip_match.group(1)

            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            timestamp = time_match.group(1) if time_match else None
            if not timestamp:
                continue

            if "4625" in xml:
                logs.append(f"{timestamp} | Failed password for user from {ip}")
            elif "4624" in xml:
                logs.append(f"{timestamp} | Accepted password for user from {ip}")

    return "\n".join(logs)


# =========================================================
# 🔥 SSH LOG DETECTION
# =========================================================
def detect_bruteforce_from_logs(text):

    lines = text.split("\n")

    ip_fail_counts = {}
    brute_ips = set()
    success_ips = set()
    ip_logs = {}

    for line in lines:

        if "|" in line:
            _, line = line.split("|", 1)
            line = line.strip()

        if "from" not in line:
            continue

        parts = line.split()

        try:
            ip = parts[parts.index("from") + 1]
        except:
            continue

        ip_logs.setdefault(ip, []).append(line)

        if "Failed password" in line:
            ip_fail_counts[ip] = ip_fail_counts.get(ip, 0) + 1
            if ip_fail_counts[ip] >= 5:
                brute_ips.add(ip)

        if "Accepted password" in line:
            success_ips.add(ip)

    attack_logs = []
    for ip in brute_ips:
        attack_logs.extend(ip_logs.get(ip, []))

    if not brute_ips:
        return "✅ Normal Activity", 70.0, []

    if any(ip in success_ips for ip in brute_ips):
        return "🚨 Brute Force Attack Detected!", 99.0, attack_logs
    else:
        return "⚠️ Possible Brute Force Attempt", 85.0, attack_logs


# =========================================================
# 🆕 NETWORK CSV DETECTION
# =========================================================
def detect_bruteforce_from_network(df):

    attempt_counts = {}
    brute_keys = set()

    for _, row in df.iterrows():

        src_ip = str(row.get("IPV4_SRC_ADDR", "")).strip()
        dst_ip = str(row.get("IPV4_DST_ADDR", "")).strip()
        dst_port = str(row.get("L4_DST_PORT", "")).strip()

        if not src_ip or not dst_ip or not dst_port:
            continue

        key = (src_ip, dst_ip, dst_port)

        attempt_counts[key] = attempt_counts.get(key, 0) + 1

        if attempt_counts[key] >= 5:
            brute_keys.add(key)

    attack_logs = []

    for key in brute_keys:
        src_ip, dst_ip, dst_port = key

        filtered = df[
            (df["IPV4_SRC_ADDR"] == src_ip) &
            (df["IPV4_DST_ADDR"] == dst_ip) &
            (df["L4_DST_PORT"].astype(str) == dst_port)
        ]

        attack_logs.extend(filtered.to_dict(orient="records"))

    if not brute_keys:
        return "✅ Normal Activity", 70.0, []

    return "🚨 Brute Force Attack Detected!", 95.0, attack_logs


# =========================================================
# 🚀 MAIN ROUTE
# =========================================================
@app.route("/", methods=["GET", "POST"])
def index():

    prediction = None
    confidence = None
    attack_logs = []

    if request.method == "POST":

        file = request.files.get("file")
        text_input = request.form.get("text_input")

        if file and file.filename != "":

            filename = file.filename.lower()

            try:

                # ===== CSV FILE =====
                if filename.endswith(".csv"):
                    df = pd.read_csv(file)

                    df.columns = df.columns.str.strip().str.upper()

                    if all(col in df.columns for col in [
                        "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_DST_PORT"
                    ]):
                        prediction, confidence, attack_logs = detect_bruteforce_from_network(df)
                    else:
                        log_data = df.astype(str).apply(lambda x: " ".join(x), axis=1).str.cat(sep="\n")
                        prediction, confidence, attack_logs = detect_bruteforce_from_logs(log_data)

                # ===== EVTX FILE =====
                elif filename.endswith(".evtx"):
                    filename = secure_filename(file.filename)
                    filepath = os.path.abspath(os.path.join(UPLOAD_FOLDER, filename))
                    file.save(filepath)

                    log_data = read_evtx(filepath)
                    prediction, confidence, attack_logs = detect_bruteforce_from_logs(log_data)

                # ===== TXT / LOG FILE =====
                else:
                    log_data = file.read().decode("utf-8", errors="ignore")
                    prediction, confidence, attack_logs = detect_bruteforce_from_logs(log_data)

            except Exception as e:
                return render_template(
                    "index1.html",
                    prediction=f"❌ Error: {str(e)}",
                    confidence=0,
                    attack_logs=[]
                )

        elif text_input and text_input.strip() != "":
            prediction, confidence, attack_logs = detect_bruteforce_from_logs(text_input)

        else:
            return render_template("index1.html")

        # =========================================================
        # ✅ SAVE CSV FILE FOR DOWNLOAD (FIX FOR 413 ERROR)
        # =========================================================
        if attack_logs:

            with open("attack_logs.csv", "w") as f:
                f.write("Timestamp,Status,IP\n")

                for line in attack_logs:

                    if "|" in line:
                        timestamp, rest = line.split("|", 1)
                    else:
                        timestamp = "unknown"
                        rest = line

                    status = "Unknown"
                    if "Failed password" in rest:
                        status = "Failed"
                    elif "Accepted password" in rest:
                        status = "Success"

                    parts = rest.split()
                    ip = "unknown"
                    if "from" in parts:
                        try:
                            ip = parts[parts.index("from") + 1]
                        except:
                            pass

                    f.write(f"{timestamp.strip()},{status},{ip}\n")

    return render_template(
        "index1.html",
        prediction=prediction,
        confidence=confidence,
        attack_logs=attack_logs
    )


# =========================================================
# 🚀 DOWNLOAD ROUTE (FIXED)
# =========================================================
@app.route("/download")
def download():
    return send_file("attack_logs.csv", as_attachment=True)


# =========================================================
# 🚀 RUN APP
# =========================================================
if __name__ == "__main__":
    app.run(debug=True)
