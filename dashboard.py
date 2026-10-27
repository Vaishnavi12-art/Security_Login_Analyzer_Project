import json
import csv
import io
import subprocess
from collections import Counter
from datetime import datetime, timedelta

import streamlit as st  # type: ignore[reportMissingImports]

try:
    from streamlit_autorefresh import st_autorefresh  # type: ignore[reportMissingImports]
except ImportError:
    def st_autorefresh(*, interval: int, key: str) -> int:
        """Disable automatic refresh if the optional helper is unavailable."""
        return 0

st.set_page_config(page_title="Live Windows HIDS", page_icon="🛡️", layout="wide")

POLL_MS = 5000
FAILED_LOGIN_THRESHOLD = 5
WINDOW_MINUTES = 5

POWERSHELL = "powershell.exe"

def run_powershell(script: str, timeout: int = 15) -> str:
    """Run a local read-only PowerShell query."""
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "PowerShell command failed").strip()
        raise RuntimeError(message)
    return completed.stdout.strip()

def get_latest_record_id() -> int:
    script = (
        "$e = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop; "
        "if ($null -eq $e) { '0' } else { [string]$e.RecordId }"
    )
    output = run_powershell(script)
    return int(output.strip() or "0")

def fetch_new_events(last_record_id: int):
    # Read only Security log authentication events created after our last seen record.
    xpath = (
        "*[System[(EventID=4624 or EventID=4625) "
        f"and (EventRecordID > {int(last_record_id)})]]"
    )
    # PowerShell single-quoted XPath avoids interpolation of the query.
    script = r"""
$ErrorActionPreference = 'Stop'
$xpath = '""" + xpath + r"""'
$events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue | Sort-Object RecordId)
if ($events.Count -eq 0) {
    '[]'
} else {
    $result = foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $fields = @()
        foreach ($d in $xml.Event.EventData.Data) {
            $fields += [pscustomobject]@{
                Name = [string]$d.Name
                Value = [string]$d.InnerText
            }
        }
        [pscustomobject]@{
            Id = [int]$e.Id
            RecordId = [long]$e.RecordId
            Time = $e.TimeCreated.ToString('o')
            Data = @($fields)
        }
    }
    ConvertTo-Json -InputObject @($result) -Depth 5 -Compress
}
"""
    output = run_powershell(script)
    if not output:
        return []
    parsed = json.loads(output)
    if isinstance(parsed, dict):
        parsed = [parsed]
    rows = []
    for event in parsed:
        data = {}
        for field in event.get("Data", []) or []:
            if isinstance(field, dict):
                data[field.get("Name", "")] = field.get("Value", "")
        rows.append({
            "time": event.get("Time", ""),
            "event_id": int(event.get("Id", 0)),
            "record_id": int(event.get("RecordId", 0)),
            "username": data.get("TargetUserName", "(unknown)"),
            "source_ip": data.get("IpAddress", "-"),
            "logon_type": data.get("LogonType", "-"),
            "workstation": data.get("WorkstationName", "-"),
            "status": data.get("Status", "-"),
            "sub_status": data.get("SubStatus", "-"),
            "event": "Failed login" if int(event.get("Id", 0)) == 4625 else "Successful login",
        })
    return rows

def classify_alerts(rows):
    """Flag 5+ failed logons for the same username in a rolling 5-minute window."""
    now = datetime.now().astimezone()
    recent_cutoff = now - timedelta(minutes=WINDOW_MINUTES)
    recent_failures = []
    for row in rows:
        if row["event_id"] != 4625:
            continue
        try:
            event_time = datetime.fromisoformat(row["time"].replace("Z", "+00:00"))
            if event_time >= recent_cutoff:
                recent_failures.append(row)
        except (ValueError, TypeError):
            continue

    counts = Counter((r["username"], r["source_ip"]) for r in recent_failures)
    alerts = []
    for (username, source_ip), count in counts.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "alert": f"{count} failed login events for user '{username}' from {source_ip} in {WINDOW_MINUTES} minutes",
                "count": count,
                "username": username,
                "source_ip": source_ip,
            })
    return alerts

st.title("🛡️ Live Windows Host-Based Intrusion Detection System")
st.caption("Local Windows Security log monitoring • Refreshes every 5 seconds • Read-only log access")

with st.sidebar:
    st.header("Monitoring status")
    st.write("**Log:** Windows Security")
    st.write("**Events:** 4624 (success), 4625 (failure)")
    st.write(f"**Alert rule:** {FAILED_LOGIN_THRESHOLD}+ failures for the same user/IP within {WINDOW_MINUTES} minutes")
    st.caption("A detection is a signal to investigate, not proof of an attack.")
    if st.button("Clear dashboard history"):
        st.session_state.events = []
        st.session_state.last_record_id = get_latest_record_id()
        st.rerun()

if "events" not in st.session_state:
    st.session_state.events = []
if "last_record_id" not in st.session_state:
    try:
        st.session_state.last_record_id = get_latest_record_id()
        st.session_state.monitor_error = None
    except Exception as exc:
        st.session_state.last_record_id = 0
        st.session_state.monitor_error = str(exc)

st_autorefresh(interval=POLL_MS, key="hids_autorefresh")

try:
    new_rows = fetch_new_events(st.session_state.last_record_id)
    if new_rows:
        st.session_state.events.extend(new_rows)
        st.session_state.last_record_id = max(
            [st.session_state.last_record_id] + [r["record_id"] for r in new_rows]
        )
    st.session_state.monitor_error = None
except Exception as exc:
    st.session_state.monitor_error = str(exc)

if st.session_state.get("monitor_error"):
    st.error("Windows Security log वाचता येत नाही. खालील तपासणी करा.")
    st.code(st.session_state.monitor_error)
    st.markdown(
        "1. VS Code/Terminal बंद करा.  \n"
        "2. Start menu मध्ये PowerShell शोधा → **Run as administrator**.  \n"
        "3. त्या PowerShell मध्ये project folder उघडून `python -m streamlit run dashboard.py` चालवा.  \n"
        "4. संस्थेच्या/शाळेच्या managed PC वर policy मुळे access बंद असू शकतो."
    )
else:
    rows = st.session_state.events[-500:]
    failed = sum(1 for r in rows if r["event_id"] == 4625)
    successful = sum(1 for r in rows if r["event_id"] == 4624)
    alerts = classify_alerts(rows)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("New events captured", len(rows))
    c2.metric("Failed logins (4625)", failed)
    c3.metric("Successful logins (4624)", successful)
    c4.metric("Active high alerts", len(alerts))

    st.subheader("🚨 Suspicious activity alerts")
    if alerts:
        for alert in alerts:
            st.error(f"**{alert['severity']}** — {alert['alert']}")
    else:
        st.success("No threshold-based failed-login alert in the captured dashboard history.")

    st.subheader("Recent authentication events")
    if rows:
        display = []
        for r in reversed(rows):
            display.append({
                "Time": r["time"],
                "Event": r["event"],
                "Event ID": r["event_id"],
                "Username": r["username"],
                "Source IP": r["source_ip"],
                "Logon type": r["logon_type"],
                "Workstation": r["workstation"],
                "Status": r["status"],
            })
        st.dataframe(display, use_container_width=True, hide_index=True)

        csv_buffer = io.StringIO()
        writer = csv.DictWriter(csv_buffer, fieldnames=display[0].keys())
        writer.writeheader()
        writer.writerows(display)
        csv_bytes = ("\ufeff" + csv_buffer.getvalue()).encode("utf-8")
        st.download_button(
            "Download captured events as CSV",
            data=csv_bytes,
            file_name="windows_hids_events.csv",
            mime="text/csv",
        )
    else:
        st.info("Dashboard चालू आहे. नवीन Windows login event आल्यावर तो इथे दिसेल.")

st.caption("Privacy: this app queries only the local Security log and keeps captured events in this Streamlit session. It does not send logs to any external service.")
    