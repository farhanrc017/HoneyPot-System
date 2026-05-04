#!/usr/bin/env python3
"""
HoneyTrap v2 — Flask Dashboard Backend
"""
from flask import Flask, render_template, jsonify, request
import sqlite3, os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "logs", "attacks.db")
app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    conn = get_db(); c = conn.cursor()
    total    = c.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
    unique   = c.execute("SELECT COUNT(DISTINCT ip) FROM attacks").fetchone()[0]
    critical = c.execute("SELECT COUNT(*) FROM attacks WHERE severity IN ('high','critical')").fetchone()[0]
    today    = (datetime.utcnow().replace(hour=0,minute=0,second=0)).isoformat()
    today_n  = c.execute("SELECT COUNT(*) FROM attacks WHERE timestamp>=?", (today,)).fetchone()[0]
    countries= c.execute("SELECT COUNT(DISTINCT country) FROM attacks WHERE country!='Unknown'").fetchone()[0]
    conn.close()
    return jsonify({"total":total,"unique_ips":unique,"critical":critical,
                    "today":today_n,"countries":countries})

@app.route("/api/attacks")
def api_attacks():
    limit  = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    ip_f   = request.args.get("ip","")
    svc_f  = request.args.get("service","")
    cat_f  = request.args.get("cat","")
    sev_f  = request.args.get("severity","")
    conn = get_db(); c = conn.cursor()
    q = "SELECT * FROM attacks WHERE 1=1"
    p = []
    if ip_f:  q += " AND ip LIKE ?";        p.append(f"%{ip_f}%")
    if svc_f: q += " AND service=?";        p.append(svc_f)
    if cat_f: q += " AND attack_cat=?";     p.append(cat_f)
    if sev_f: q += " AND severity=?";       p.append(sev_f)
    q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    p += [limit, offset]
    rows = c.execute(q, p).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/timeline")
def api_timeline():
    conn = get_db(); c = conn.cursor()
    cutoff = (datetime.utcnow()-timedelta(hours=24)).isoformat()
    rows = c.execute(
        "SELECT strftime('%Y-%m-%dT%H:00',timestamp) as hour, COUNT(*) as cnt "
        "FROM attacks WHERE timestamp>=? GROUP BY hour ORDER BY hour", (cutoff,)
    ).fetchall()
    conn.close()
    return jsonify([{"hour":r["hour"],"count":r["cnt"]} for r in rows])

@app.route("/api/top_ips")
def api_top_ips():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT ip, total_attempts, risk_score, country, country_code, "
        "flag_emoji, isp, first_seen, last_seen "
        "FROM ip_stats ORDER BY total_attempts DESC LIMIT 15"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/attack_cats")
def api_attack_cats():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT attack_cat, COUNT(*) as cnt FROM attacks GROUP BY attack_cat ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return jsonify([{"cat":r["attack_cat"],"count":r["cnt"]} for r in rows])

@app.route("/api/attack_types")
def api_attack_types():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT attack_type, COUNT(*) as cnt FROM attacks GROUP BY attack_type ORDER BY cnt DESC LIMIT 12"
    ).fetchall()
    conn.close()
    return jsonify([{"type":r["attack_type"],"count":r["cnt"]} for r in rows])

@app.route("/api/services")
def api_services():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT service, COUNT(*) as cnt FROM attacks GROUP BY service ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return jsonify([{"service":r["service"],"count":r["cnt"]} for r in rows])

@app.route("/api/severity")
def api_severity():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT severity, COUNT(*) as cnt FROM attacks GROUP BY severity"
    ).fetchall()
    conn.close()
    return jsonify([{"severity":r["severity"],"count":r["cnt"]} for r in rows])

@app.route("/api/countries")
def api_countries():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT country, country_code, flag_emoji, COUNT(*) as cnt "
        "FROM attacks WHERE country!='Unknown' AND country!='Local' "
        "GROUP BY country ORDER BY cnt DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/mitre")
def api_mitre():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT mitre_tactic, mitre_tech, COUNT(*) as cnt FROM attacks "
        "WHERE mitre_tactic!='' GROUP BY mitre_tech ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/recent")
def api_recent():
    conn = get_db(); c = conn.cursor()
    rows = c.execute("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 15").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/ip/<ip>")
def api_ip(ip):
    conn = get_db(); c = conn.cursor()
    profile = c.execute("SELECT * FROM ip_stats WHERE ip=?", (ip,)).fetchone()
    attacks = c.execute(
        "SELECT * FROM attacks WHERE ip=? ORDER BY timestamp DESC LIMIT 50", (ip,)
    ).fetchall()
    cats = c.execute(
        "SELECT attack_cat, COUNT(*) as cnt FROM attacks WHERE ip=? GROUP BY attack_cat", (ip,)
    ).fetchall()
    conn.close()
    return jsonify({
        "profile": dict(profile) if profile else {},
        "attacks": [dict(a) for a in attacks],
        "cat_breakdown": [dict(c) for c in cats],
    })

@app.route("/api/hourly_heatmap")
def api_heatmap():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT CAST(strftime('%H',timestamp) AS INTEGER) as hour, COUNT(*) as cnt "
        "FROM attacks GROUP BY hour ORDER BY hour"
    ).fetchall()
    conn.close()
    result = [0]*24
    for r in rows:
        result[r["hour"]] = r["cnt"]
    return jsonify(result)

@app.route("/api/risk_ips")
def api_risk_ips():
    conn = get_db(); c = conn.cursor()
    rows = c.execute(
        "SELECT ip, risk_score, total_attempts, country, flag_emoji "
        "FROM ip_stats WHERE risk_score>=40 ORDER BY risk_score DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)