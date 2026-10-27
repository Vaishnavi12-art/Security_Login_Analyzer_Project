from importlib import import_module

_flask = import_module("flask")
Flask = _flask.Flask
jsonify = _flask.jsonify
render_template_string = _flask.render_template_string
from pathlib import Path
from collections import Counter
from datetime import datetime
import csv
import os

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "security_log.txt"
FAILED_LIMIT = 5

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel | Security Operations</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0b1120;color:#e5e7eb;
font-family:Arial,sans-serif}
header{padding:24px 5%;background:#111827;
border-bottom:1px solid #263247;display:flex;
justify-content:space-between;align-items:center;gap:12px}
h1{font-size:24px;margin:0}
small,.muted{color:#94a3b8}
.status{color:#4ade80;font-size:13px}
main{max-width:1250px;margin:auto;padding:28px 5%}
.cards{display:grid;grid-template-columns:repeat(4,1fr);
gap:16px}
.card,.panel{background:#111827;border:1px solid #263247;
border-radius:12px;padding:20px}
.card p{color:#94a3b8;margin:0 0 14px}
.metric{font-size:30px;font-weight:bold}
section{margin-top:22px}
h2{font-size:17px;margin-top:0}
.alert{padding:12px;margin:10px 0;border-radius:8px;
background:#3b1722;border:1px solid #7f1d1d;color:#fca5a5}
.ok{padding:12px;background:#123126;color:#86efac;
border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:13px 10px;
border-bottom:1px solid #263247}
th{color:#94a3b8}
.bad{color:#f87171}.good{color:#4ade80}
.tablewrap{overflow-x:auto}
footer{padding:22px;text-align:center;color:#64748b}
@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}}
@media(max-width:460px){.cards{grid-template-columns:1fr}
header{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body>
<header>
 <div>
  <h1>◈ SENTINEL</h1>
  <small>Security Operations Dashboard</small>
 </div>
 <div>
  <div class="status">● MONITORING ACTIVE</div>
  <small id="updated">Loading...</small>
 </div>
</header>
<main>
 <h2>Security Overview</h2>
 <p class="muted">Security event monitoring and login analysis</p>
 <div class="cards">
  <div class="card"><p>Total Events</p><div class="metric" id="total">0</div></div>
  <div class="card"><p>Successful Logins</p><div class="metric good" id="success">0</div></div>
  <div class="card"><p>Failed Logins</p><div class="metric bad" id="failed">0</div></div>
  <div class="card"><p>Threat Alerts</p><div class="metric bad" id="alertsCount">0</div></div>
 </div>
 <section class="panel">
  <h2>⚠ Security Alerts</h2>
  <div id="alerts">Loading alerts...</div>
 </section>
 <section class="panel">
  <h2>Recent Security Events</h2>
  <div class="tablewrap">
   <table>
    <thead><tr><th>Timestamp</th><th>Level</th>
    <th>IP Address</th><th>Event</th><th>User</th></tr></thead>
    <tbody id="events"></tbody>
   </table>
  </div>
 </section>
 <p class="muted">Refresh interval: 5 seconds · Data source: security_log.txt</p>
</main>
<footer>Sentinel Security Monitor · Educational project</footer>
<script>
async function refreshDashboard(){
 try{
  const response=await fetch('/api/data',{cache:'no-store'});
  if(!response.ok) throw new Error('API unavailable');
  const data=await response.json();
  document.getElementById('total').textContent=data.total;
  document.getElementById('success').textContent=data.success;
  document.getElementById('failed').textContent=data.failed;
  document.getElementById('alertsCount').textContent=data.alerts.length;
  document.getElementById('updated').textContent='Updated: '+data.time;

  const alertBox=document.getElementById('alerts');
  alertBox.replaceChildren();
  if(data.alerts.length===0){
   const div=document.createElement('div');
   div.className='ok';
   div.textContent='No threshold-based alerts detected.';
   alertBox.appendChild(div);
  }else{
   data.alerts.forEach(item=>{
    const div=document.createElement('div');
    div.className='alert';
    div.textContent=item;
    alertBox.appendChild(div);
   });
  }

  const tbody=document.getElementById('events');
  tbody.replaceChildren();
  data.events.forEach(e=>{
   const tr=document.createElement('tr');
   [e.timestamp,e.level,e.ip,e.event,e.username].forEach((value,i)=>{
    const td=document.createElement('td');
    td.textContent=value;
    if(i===3) td.className=value==='LOGIN_FAILED'?'bad':'good';
    tr.appendChild(td);
   });
   tbody.appendChild(tr);
  });
 }catch(error){
  document.getElementById('updated').textContent='Connection error';
 }
}
refreshDashboard();
setInterval(refreshDashboard,5000);
</script>
</body>
</html>
"""


def read_logs():
    events = []
    if not LOG_FILE.exists():
        return events

    with LOG_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        for row in csv.reader(file):
            if len(row) != 5:
                continue

            timestamp, level, ip, event, username = [
                value.strip() for value in row
            ]

            if event not in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
                continue

            events.append({
                "timestamp": timestamp,
                "level": level,
                "ip": ip,
                "event": event,
                "username": username
            })

    return events


def build_dashboard_payload(events=None):
    events = read_logs() if events is None else list(events)
    failed_ips = Counter(
        e["ip"] for e in events if e["event"] == "LOGIN_FAILED"
    )

    alerts = [
        f"High failed-login activity: {ip} ({count} attempts)"
        for ip, count in failed_ips.items()
        if count >= FAILED_LIMIT
    ]

    return {
        "total": len(events),
        "success": sum(e["event"] == "LOGIN_SUCCESS" for e in events),
        "failed": sum(e["event"] == "LOGIN_FAILED" for e in events),
        "alerts": alerts,
        "events": list(reversed(events[-50:])),
        "time": datetime.now().strftime("%H:%M:%S")
    }


@app.route("/")
def dashboard():
    return render_template_string(HTML)


@app.route("/api/data")
def api_data():
    return jsonify(build_dashboard_payload())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
