import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

BASE_DIR = Path(__file__).parent
PUBLIC_DIR = BASE_DIR / "public"
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "harborlog.db"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "3000"))
SECRET = os.environ.get("HARBORLOG_SECRET", "harborlog-dev-secret-change-me")
SINGLE_VESSEL_MODE = os.environ.get("SINGLE_VESSEL_MODE", "true").lower() == "true"
HOME_VESSEL_NAME = os.environ.get("HOME_VESSEL_NAME", "Blue Sea")

_db_local = threading.local()
VALID_CATEGORIES = {"Weather", "Operations", "Safety", "Issue/Delay"}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def valid_day(day: str) -> bool:
    try:
        datetime.strptime(day, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def get_db() -> sqlite3.Connection:
    conn = getattr(_db_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _db_local.conn = conn
    return conn




def ensure_home_vessel(conn: sqlite3.Connection):
    now = now_iso()
    vessel = conn.execute("SELECT * FROM vessels WHERE name = ?", (HOME_VESSEL_NAME,)).fetchone()
    if vessel:
        return vessel
    vessel_id = str(uuid4())
    conn.execute("INSERT INTO vessels (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)", (vessel_id, HOME_VESSEL_NAME, now, now))
    conn.commit()
    return conn.execute("SELECT * FROM vessels WHERE id = ?", (vessel_id,)).fetchone()


def assign_user_to_home_vessel(conn: sqlite3.Connection, user_id: str):
    home = ensure_home_vessel(conn)
    now = now_iso()
    existing = conn.execute("SELECT id FROM vessel_assignments WHERE user_id = ?", (user_id,)).fetchone()
    if existing:
        conn.execute("UPDATE vessel_assignments SET vessel_id = ?, updated_at = ? WHERE user_id = ?", (home["id"], now, user_id))
    else:
        conn.execute("INSERT INTO vessel_assignments (id, user_id, vessel_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (str(uuid4()), user_id, home["id"], now, now))
    conn.commit()
    return home


def ensure_default_tanks(conn: sqlite3.Connection, vessel_id: str) -> None:
    defaults = [
        ("#1 Port", "Main", "Port", 2000.0),
        ("#1 Starboard", "Main", "Starboard", 2000.0),
        ("#3 Port", "Main", "Port", 2000.0),
        ("#3 Starboard", "Main", "Starboard", 2000.0),
        ("#4 Port", "Main", "Port", 2000.0),
        ("#4 Starboard", "Main", "Starboard", 2000.0),
        ("Port Day Tank", "Day", "Port", 500.0),
        ("Starboard Day Tank", "Day", "Starboard", 500.0),
    ]
    ts = now_iso()
    for tank_name, tank_group, side, capacity in defaults:
        exists = conn.execute(
            "SELECT id FROM tanks WHERE vessel_id=? AND tank_name=?",
            (vessel_id, tank_name),
        ).fetchone()
        if exists:
            continue
        conn.execute(
            """
            INSERT INTO tanks (id, vessel_id, tank_name, tank_group, side, capacity_gallons, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid4()), vessel_id, tank_name, tank_group, side, capacity, ts),
        )


def vessel_tank_balances(conn: sqlite3.Connection, vessel_id: str) -> list[dict]:
    tanks = [dict(r) for r in conn.execute(
        "SELECT * FROM tanks WHERE vessel_id=? ORDER BY tank_group ASC, tank_name ASC", (vessel_id,)
    ).fetchall()]
    balances = {t["id"]: 0.0 for t in tanks}
    events = conn.execute(
        "SELECT * FROM fuel_events WHERE vessel_id=? ORDER BY timestamp ASC, created_at ASC",
        (vessel_id,),
    ).fetchall()
    for row in events:
        e = dict(row)
        g = float(e["gallons"] or 0)
        src = e.get("source_tank_id")
        dst = e.get("destination_tank_id")
        event_type = e["event_type"]
        if event_type == "transfer_internal":
            if src in balances:
                balances[src] -= g
            if dst in balances:
                balances[dst] += g
        elif event_type in {"bunker_received", "receive_external"}:
            if dst in balances:
                balances[dst] += g
        elif event_type == "offload_external":
            if src in balances:
                balances[src] -= g
        elif event_type == "sounding":
            tank_id = dst or src
            if tank_id in balances:
                balances[tank_id] = g
        elif event_type == "correction":
            if src in balances:
                balances[src] -= g
            if dst in balances:
                balances[dst] += g

    for tank in tanks:
        tank["balance_gallons"] = round(balances.get(tank["id"], 0.0), 3)
    return tanks

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('ADMIN','CREW','ENGINEER','BRIDGE_OFFICER','READ_ONLY')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vessels (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vessel_assignments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL UNIQUE,
            vessel_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(vessel_id) REFERENCES vessels(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS log_entries (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            vessel_id TEXT NOT NULL,
            crew_user_id TEXT NOT NULL,
            category TEXT NOT NULL CHECK (category IN ('Weather','Operations','Safety','Issue/Delay')),
            notes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(vessel_id) REFERENCES vessels(id) ON DELETE CASCADE,
            FOREIGN KEY(crew_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS daily_reports (
            id TEXT PRIMARY KEY,
            vessel_id TEXT NOT NULL,
            crew_user_id TEXT NOT NULL,
            report_day TEXT NOT NULL,
            fuel_burned REAL NOT NULL,
            water_onboard REAL NOT NULL,
            pob_count INTEGER NOT NULL,
            meal_count INTEGER NOT NULL,
            jsa_count INTEGER NOT NULL,
            preventers_checked INTEGER NOT NULL CHECK (preventers_checked IN (0,1)),
            master_remarks TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(vessel_id, report_day),
            FOREIGN KEY(vessel_id) REFERENCES vessels(id) ON DELETE CASCADE,
            FOREIGN KEY(crew_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS daily_ops_reports (
            id TEXT PRIMARY KEY,
            vessel_id TEXT NOT NULL,
            crew_user_id TEXT NOT NULL,
            report_day TEXT NOT NULL,
            report_timestamp TEXT NOT NULL,
            position_type TEXT NOT NULL CHECK (position_type IN ('LatLon','Block')),
            position_text TEXT NOT NULL,
            status TEXT NOT NULL,
            status_notes TEXT NOT NULL,
            destination_location TEXT NOT NULL,
            eta TEXT,
            wind TEXT NOT NULL,
            seas TEXT NOT NULL,
            visibility TEXT NOT NULL,
            fuel_onboard REAL NOT NULL,
            fuel_used_24h REAL NOT NULL,
            water_onboard REAL NOT NULL,
            lube_oil_onboard REAL NOT NULL,
            fuel_ticket_number TEXT NOT NULL,
            fuel_ticket_attachment_path TEXT,
            pob INTEGER NOT NULL,
            next_crew_change_date TEXT,
            jsa_count INTEGER,
            jsa_breakdown TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(vessel_id, report_day),
            FOREIGN KEY(vessel_id) REFERENCES vessels(id) ON DELETE CASCADE,
            FOREIGN KEY(crew_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tanks (
            id TEXT PRIMARY KEY,
            vessel_id TEXT NOT NULL,
            tank_name TEXT NOT NULL,
            tank_group TEXT NOT NULL CHECK (tank_group IN ('Main','Day')),
            side TEXT NOT NULL CHECK (side IN ('Port','Starboard')),
            capacity_gallons REAL NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(vessel_id, tank_name),
            FOREIGN KEY(vessel_id) REFERENCES vessels(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS fuel_events (
            id TEXT PRIMARY KEY,
            vessel_id TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK (event_type IN ('transfer_internal','bunker_received','offload_external','receive_external','sounding','charter_on','charter_off','correction')),
            timestamp TEXT NOT NULL,
            source_tank_id TEXT,
            destination_tank_id TEXT,
            gallons REAL NOT NULL,
            operational_mode TEXT NOT NULL CHECK (operational_mode IN ('Dockside','Underway','On DP')),
            reference_number TEXT,
            notes TEXT NOT NULL,
            correction_of_event_id TEXT,
            reason TEXT,
            entered_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(vessel_id) REFERENCES vessels(id) ON DELETE CASCADE,
            FOREIGN KEY(source_tank_id) REFERENCES tanks(id) ON DELETE SET NULL,
            FOREIGN KEY(destination_tank_id) REFERENCES tanks(id) ON DELETE SET NULL,
            FOREIGN KEY(correction_of_event_id) REFERENCES fuel_events(id) ON DELETE RESTRICT,
            FOREIGN KEY(entered_by) REFERENCES users(id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_log_entries_crew_ts ON log_entries (crew_user_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_daily_reports_crew_day ON daily_reports (crew_user_id, report_day DESC);
        CREATE INDEX IF NOT EXISTS idx_daily_ops_reports_crew_day ON daily_ops_reports (crew_user_id, report_day DESC);
        """
    )

    if SINGLE_VESSEL_MODE:
        hv = ensure_home_vessel(conn)
        ensure_default_tanks(conn, hv["id"])

    has_admin = conn.execute("SELECT id FROM users WHERE role='ADMIN' LIMIT 1").fetchone()
    if not has_admin:
        ts = now_iso()
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, 'ADMIN', ?, ?)",
            (str(uuid4()), "admin", hash_password("admin123"), ts, ts),
        )
        print("Seeded default admin user: admin / admin123")

    for vr in conn.execute("SELECT id FROM vessels").fetchall():
        ensure_default_tanks(conn, vr[0])
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 130000)
    return f"{base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, digest_b64 = stored.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
    except Exception:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 130000)
    return hmac.compare_digest(candidate, expected)


def issue_token(payload: dict) -> str:
    body = payload.copy()
    body["exp"] = int((datetime.now(timezone.utc) + timedelta(hours=8)).timestamp())
    body_b64 = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(SECRET.encode(), body_b64.encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{body_b64}.{sig_b64}"


def verify_token(token: str):
    try:
        body_b64, sig_b64 = token.split(".", 1)
        expected = hmac.new(SECRET.encode(), body_b64.encode(), hashlib.sha256).digest()
        provided = base64.urlsafe_b64decode(sig_b64 + "==")
        if not hmac.compare_digest(expected, provided):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body_b64 + "==").decode())
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            return None
        return payload
    except Exception:
        return None


def render_entries_pdf(entries: list, crew_username: str, vessel_name: str, day: str) -> bytes:
    lines = [
        "HarborLog - Daily Entries",
        f"Day: {day}",
        f"Crew: {crew_username}",
        f"Vessel: {vessel_name}",
        f"Generated at: {now_iso()}",
        "",
    ]
    if not entries:
        lines.append("No entries for this day.")
    for idx, item in enumerate(entries, start=1):
        lines.extend(
            [
                f"Entry {idx}",
                f"Timestamp: {item['timestamp']}",
                f"Category: {item['category']}",
                f"Notes: {item['notes']}",
                f"Record ID: {item['id']}",
                "----------------------------------------",
            ]
        )
    return render_simple_pdf(lines)


def render_daily_report_pdf(report: dict, vessel_name: str, day: str, crew_username: str) -> bytes:
    lines = [
        "HarborLog - Daily Vessel Report",
        f"Day: {day}",
        f"Vessel: {vessel_name}",
        f"Submitted by: {crew_username}",
        f"Generated at: {now_iso()}",
        "",
        f"Fuel burned: {report['fuel_burned']}",
        f"Water onboard: {report['water_onboard']}",
        f"POB count: {report['pob_count']}",
        f"Meal count: {report['meal_count']}",
        f"JSA count: {report['jsa_count']}",
        f"Preventers checked: {'Yes' if report['preventers_checked'] else 'No'}",
        f"Master remarks: {report['master_remarks']}",
        "",
        f"Report ID: {report['id']}",
        f"Created at: {report['created_at']}",
        f"Updated at: {report['updated_at']}",
    ]
    return render_simple_pdf(lines)


def render_simple_pdf(lines: list[str]) -> bytes:
    text = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 10 Tf 40 780 Td 12 TL ({text.replace(chr(10), ') Tj T* (')}) Tj ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(stream.encode())} >> stream\n{stream}\nendstream endobj",
    ]
    pdf = [b"%PDF-1.4\n"]
    offsets = [0]
    cursor = len(pdf[0])
    for obj in objects:
        encoded = (obj + "\n").encode()
        offsets.append(cursor)
        pdf.append(encoded)
        cursor += len(encoded)
    xref_pos = cursor
    xref = [f"xref\n0 {len(offsets)}\n0000000000 65535 f \n"]
    for off in offsets[1:]:
        xref.append(f"{off:010d} 00000 n \n")
    trailer = f"trailer << /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    pdf.append("".join(xref).encode())
    pdf.append(trailer.encode())
    return b"".join(pdf)


def format_daily_ops_view(report: dict, vessel_name: str, day: str, mode: str) -> str:
    eta_text = report['eta'] or '-'
    nccd = report['next_crew_change_date'] or '-'
    jsa_count = report['jsa_count'] if report['jsa_count'] is not None else '-'
    jsa_breakdown = report['jsa_breakdown'] or '-'
    attach = report['fuel_ticket_attachment_path'] or '(none stored)'
    ticket_ref = f"/api/daily-ops-report/fuel-ticket?report_id={report['id']}" if report.get('fuel_ticket_attachment_path') else '(none attached)'

    if mode == "office":
        return "\n".join([
            f"OFFICE DAILY OPS REPORT - {day}",
            f"Vessel: {vessel_name}",
            f"Report Timestamp: {report['report_timestamp']}",
            f"Position ({report['position_type']}): {report['position_text']}",
            f"Status: {report['status']} | {report['status_notes']}",
            f"Destination/Location: {report['destination_location']}",
            f"ETA: {eta_text}",
            f"Weather: Wind {report['wind']} | Seas {report['seas']} | Visibility {report['visibility']}",
            f"Fuel OB: {report['fuel_onboard']} | Fuel 24h: {report['fuel_used_24h']}",
            f"Water OB: {report['water_onboard']} | Lube OB: {report['lube_oil_onboard']}",
            f"Fuel Ticket: {report['fuel_ticket_number']} (PDF) - {ticket_ref}",
            f"Fuel Ticket Stored Path: {attach}",
            f"POB: {report['pob']} | Next Crew Change: {nccd}",
            f"JSA Count: {jsa_count}",
            f"JSA Breakdown: {jsa_breakdown}",
        ])

    return "\n".join([
        f"OM NIGHTLY SUMMARY - {day}",
        f"Vessel {vessel_name}",
        f"Position ({report['position_type']}): {report['position_text']}",
        f"Status: {report['status']} | Notes: {report['status_notes']}",
        f"Destination/Location: {report['destination_location']} | ETA: {eta_text}",
        f"Weather: {report['wind']}, Seas {report['seas']}, Visibility {report['visibility']}",
        f"Consumables: Fuel OB {report['fuel_onboard']} (24h used {report['fuel_used_24h']}), Water OB {report['water_onboard']}, Lube OB {report['lube_oil_onboard']}",
        f"Fuel Ticket: {report['fuel_ticket_number']} (PDF) | Download: {ticket_ref}",
        f"Fuel Ticket Stored Path: {attach}",
        f"POB {report['pob']} | Next crew change {nccd}",
        f"JSA count {jsa_count} | Breakdown {jsa_breakdown}",
    ])


def render_daily_ops_pdf(report: dict, vessel_name: str, day: str, view: str) -> bytes:
    text = format_daily_ops_view(report, vessel_name, day, view)
    lines = [
        f"HarborLog - Daily Ops Report ({view.upper()} View)",
        f"Day: {day}",
        f"Vessel: {vessel_name}",
        f"Generated at: {now_iso()}",
        "",
        text,
    ]
    return render_simple_pdf(lines)


class HarborLogHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            return self.handle_api("GET", parsed)
        return self.serve_static(parsed.path)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            return self.handle_api("POST", parsed)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size) if size else b"{}"
        try:
            return json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            return None

    def json_response(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        target = (PUBLIC_DIR / path.lstrip("/")).resolve()
        if not str(target).startswith(str(PUBLIC_DIR.resolve())) or not target.exists() or not target.is_file():
            target = PUBLIC_DIR / "index.html"
        content = target.read_bytes()
        content_type = "text/plain"
        if target.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif target.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif target.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def auth_user(self, query):
        auth = self.headers.get("Authorization", "")
        token = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
        elif "token" in query:
            token = query["token"][0]
        if not token:
            return None
        return verify_token(token)

    def require_role(self, role, query):
        user = self.auth_user(query)
        if not user:
            self.json_response(HTTPStatus.UNAUTHORIZED, {"error": "Missing or invalid token."})
            return None
        if user.get("role") != role:
            self.json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden."})
            return None
        return user

    def require_auth(self, query):
        user = self.auth_user(query)
        if not user:
            self.json_response(HTTPStatus.UNAUTHORIZED, {"error": "Missing or invalid token."})
            return None
        return user

    def crew_assigned_vessel(self, conn, user_id):
        assigned = conn.execute(
            "SELECT v.id, v.name FROM vessel_assignments va JOIN vessels v ON v.id = va.vessel_id WHERE va.user_id = ?",
            (user_id,),
        ).fetchone()
        if assigned:
            return assigned
        if SINGLE_VESSEL_MODE:
            home = assign_user_to_home_vessel(conn, user_id)
            return {"id": home["id"], "name": home["name"]}
        return None

    def handle_api(self, method, parsed):
        conn = get_db()
        path = parsed.path
        query = parse_qs(parsed.query)

        if method == "POST" and path == "/api/auth/login":
            body = self.read_json()
            if body is None:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON."})
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            if not username or not password:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Username and password are required."})
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                return self.json_response(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials."})
            token = issue_token({"id": user["id"], "username": user["username"], "role": user["role"]})
            return self.json_response(HTTPStatus.OK, {"token": token, "user": {k: user[k] for k in ["id", "username", "role", "created_at", "updated_at"]}})

        if method == "GET" and path == "/api/me":
            user = self.auth_user(query)
            if not user:
                return self.json_response(HTTPStatus.UNAUTHORIZED, {"error": "Missing or invalid token."})
            row = conn.execute("SELECT id, username, role, created_at, updated_at FROM users WHERE id=?", (user["id"],)).fetchone()
            if not row:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "User not found."})
            return self.json_response(HTTPStatus.OK, dict(row))

        if method == "GET" and path == "/api/fuel/tanks":
            user = self.require_auth(query)
            if not user:
                return
            vessel_id = (query.get("vessel_id") or [""])[0]
            if user.get("role") != "ADMIN":
                vessel = self.crew_assigned_vessel(conn, user["id"])
                if not vessel:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "No vessel assigned."})
                vessel_id = vessel["id"]
            if not vessel_id:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "vessel_id required for admin."})
            ensure_default_tanks(conn, vessel_id)
            conn.commit()
            return self.json_response(HTTPStatus.OK, vessel_tank_balances(conn, vessel_id))

        if method == "GET" and path == "/api/fuel/events":
            user = self.require_auth(query)
            if not user:
                return
            vessel_id = (query.get("vessel_id") or [""])[0]
            if user.get("role") != "ADMIN":
                vessel = self.crew_assigned_vessel(conn, user["id"])
                if not vessel:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "No vessel assigned."})
                vessel_id = vessel["id"]
            if not vessel_id:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "vessel_id required for admin."})
            rows = [dict(r) for r in conn.execute("SELECT * FROM fuel_events WHERE vessel_id=? ORDER BY timestamp DESC, created_at DESC", (vessel_id,)).fetchall()]
            return self.json_response(HTTPStatus.OK, rows)

        if method == "POST" and path == "/api/fuel/events":
            user = self.require_auth(query)
            if not user:
                return
            if user.get("role") not in {"ENGINEER", "BRIDGE_OFFICER"}:
                return self.json_response(HTTPStatus.FORBIDDEN, {"error": "Only ENGINEER and BRIDGE_OFFICER can create fuel events."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "No vessel assigned."})

            body = self.read_json() or {}
            event_type = body.get("event_type")
            valid_types = {"transfer_internal", "bunker_received", "offload_external", "receive_external", "sounding", "charter_on", "charter_off", "correction"}
            if event_type not in valid_types:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid event_type."})
            mode = body.get("operational_mode")
            if mode not in {"Dockside", "Underway", "On DP"}:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid operational_mode."})
            try:
                gallons = float(body.get("gallons"))
                if gallons < 0:
                    raise ValueError
            except Exception:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "gallons must be a non-negative number."})

            src = body.get("source_tank_id") or None
            dst = body.get("destination_tank_id") or None
            tank_ids = {r["id"] for r in conn.execute("SELECT id FROM tanks WHERE vessel_id=?", (vessel["id"],)).fetchall()}
            if src and src not in tank_ids:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "source_tank_id is invalid for vessel."})
            if dst and dst not in tank_ids:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "destination_tank_id is invalid for vessel."})

            if event_type == "transfer_internal" and (not src or not dst or src == dst):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "transfer_internal requires distinct source and destination tanks."})
            if event_type in {"bunker_received", "receive_external"} and not dst:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "destination_tank_id is required."})
            if event_type == "offload_external" and not src:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "source_tank_id is required."})
            if event_type == "sounding" and not (src or dst):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "sounding requires source_tank_id or destination_tank_id."})

            correction_of_event_id = body.get("correction_of_event_id") or None
            reason = (body.get("reason") or "").strip() or None
            if event_type == "correction":
                if not correction_of_event_id or not reason:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "correction requires correction_of_event_id and reason."})
                original = conn.execute(
                    "SELECT id, event_type FROM fuel_events WHERE id=? AND vessel_id=?",
                    (correction_of_event_id, vessel["id"]),
                ).fetchone()
                if not original:
                    return self.json_response(HTTPStatus.NOT_FOUND, {"error": "Original event not found."})
                if original["event_type"] in {"charter_on", "charter_off"}:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "charter_on/charter_off events are locked."})

            ts = now_iso()
            event = {
                "id": str(uuid4()),
                "vessel_id": vessel["id"],
                "event_type": event_type,
                "timestamp": body.get("timestamp") or ts,
                "source_tank_id": src,
                "destination_tank_id": dst,
                "gallons": gallons,
                "operational_mode": mode,
                "reference_number": (body.get("reference_number") or "").strip() or None,
                "notes": (body.get("notes") or "").strip(),
                "correction_of_event_id": correction_of_event_id,
                "reason": reason,
                "entered_by": user["id"],
                "created_at": ts,
            }
            conn.execute(
                """
                INSERT INTO fuel_events (
                    id, vessel_id, event_type, timestamp, source_tank_id, destination_tank_id,
                    gallons, operational_mode, reference_number, notes, correction_of_event_id,
                    reason, entered_by, created_at
                ) VALUES (
                    :id, :vessel_id, :event_type, :timestamp, :source_tank_id, :destination_tank_id,
                    :gallons, :operational_mode, :reference_number, :notes, :correction_of_event_id,
                    :reason, :entered_by, :created_at
                )
                """,
                event,
            )
            conn.commit()
            return self.json_response(HTTPStatus.CREATED, event)

        if method == "GET" and path == "/api/fuel/summary-24h":
            user = self.require_auth(query)
            if not user:
                return
            vessel_id = (query.get("vessel_id") or [""])[0]
            if user.get("role") != "ADMIN":
                vessel = self.crew_assigned_vessel(conn, user["id"])
                if not vessel:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "No vessel assigned."})
                vessel_id = vessel["id"]
            if not vessel_id:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "vessel_id required for admin."})
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            rows = conn.execute(
                "SELECT event_type, COALESCE(SUM(gallons),0) AS g FROM fuel_events WHERE vessel_id=? AND timestamp>=? GROUP BY event_type",
                (vessel_id, since),
            ).fetchall()
            return self.json_response(HTTPStatus.OK, {"since": since, "totals": {r["event_type"]: float(r["g"]) for r in rows}})

        if method == "POST" and path == "/api/admin/vessels":
            if not self.require_role("ADMIN", query):
                return
            body = self.read_json() or {}
            name = (body.get("name") or "").strip()
            if not name:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Vessel name is required."})
            ts = now_iso()
            vessel = {"id": str(uuid4()), "name": name, "created_at": ts, "updated_at": ts}
            try:
                conn.execute("INSERT INTO vessels (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)", (vessel["id"], vessel["name"], vessel["created_at"], vessel["updated_at"]))
                ensure_default_tanks(conn, vessel["id"])
                conn.commit()
            except sqlite3.IntegrityError:
                return self.json_response(HTTPStatus.CONFLICT, {"error": "Vessel name must be unique."})
            return self.json_response(HTTPStatus.CREATED, vessel)

        if method == "GET" and path == "/api/admin/vessels":
            if not self.require_role("ADMIN", query):
                return
            return self.json_response(HTTPStatus.OK, [dict(r) for r in conn.execute("SELECT * FROM vessels ORDER BY name ASC").fetchall()])

        if method == "POST" and path == "/api/admin/users":
            if not self.require_role("ADMIN", query):
                return
            body = self.read_json() or {}
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            role = body.get("role")
            if not username or not password or role not in {"ADMIN", "CREW", "ENGINEER", "BRIDGE_OFFICER", "READ_ONLY"}:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Username, password, and valid role are required."})
            ts = now_iso()
            row = {"id": str(uuid4()), "username": username, "role": role, "created_at": ts, "updated_at": ts}
            try:
                conn.execute("INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (row["id"], row["username"], hash_password(password), row["role"], row["created_at"], row["updated_at"]))
                conn.commit()
                if SINGLE_VESSEL_MODE and row["role"] != "ADMIN":
                    home = assign_user_to_home_vessel(conn, row["id"])
                    row["auto_assigned_vessel"] = {"id": home["id"], "name": home["name"]}
            except sqlite3.IntegrityError:
                return self.json_response(HTTPStatus.CONFLICT, {"error": "Username already exists."})
            return self.json_response(HTTPStatus.CREATED, row)

        if method == "GET" and path == "/api/admin/users":
            if not self.require_role("ADMIN", query):
                return
            rows = [dict(r) for r in conn.execute("SELECT id, username, role, created_at, updated_at FROM users ORDER BY username ASC").fetchall()]
            return self.json_response(HTTPStatus.OK, rows)

        if method == "POST" and path == "/api/admin/assignments":
            if not self.require_role("ADMIN", query):
                return
            if SINGLE_VESSEL_MODE:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Manual assignments are disabled in SINGLE_VESSEL_MODE."})
            body = self.read_json() or {}
            user_id = body.get("user_id")
            vessel_id = body.get("vessel_id")
            if not user_id or not vessel_id:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "user_id and vessel_id are required."})
            crew = conn.execute("SELECT id, role FROM users WHERE id=?", (user_id,)).fetchone()
            vessel = conn.execute("SELECT id FROM vessels WHERE id=?", (vessel_id,)).fetchone()
            if not crew:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "User not found."})
            if crew["role"] != "CREW":
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Only CREW users can be assigned."})
            if not vessel:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "Vessel not found."})
            ts = now_iso()
            existing = conn.execute("SELECT id FROM vessel_assignments WHERE user_id=?", (user_id,)).fetchone()
            if existing:
                conn.execute("UPDATE vessel_assignments SET vessel_id=?, updated_at=? WHERE user_id=?", (vessel_id, ts, user_id))
                conn.commit()
                row = conn.execute("SELECT * FROM vessel_assignments WHERE user_id=?", (user_id,)).fetchone()
                return self.json_response(HTTPStatus.OK, dict(row))
            row = {"id": str(uuid4()), "user_id": user_id, "vessel_id": vessel_id, "created_at": ts, "updated_at": ts}
            conn.execute("INSERT INTO vessel_assignments (id, user_id, vessel_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", (row["id"], row["user_id"], row["vessel_id"], row["created_at"], row["updated_at"]))
            conn.commit()
            return self.json_response(HTTPStatus.CREATED, row)

        if method == "GET" and path == "/api/admin/assignments":
            if not self.require_role("ADMIN", query):
                return
            if SINGLE_VESSEL_MODE:
                return self.json_response(HTTPStatus.OK, [])
            rows = [dict(r) for r in conn.execute("""
                SELECT va.id, va.user_id, u.username, va.vessel_id, v.name AS vessel_name, va.created_at, va.updated_at
                FROM vessel_assignments va JOIN users u ON u.id = va.user_id JOIN vessels v ON v.id = va.vessel_id
                ORDER BY u.username ASC
            """).fetchall()]
            return self.json_response(HTTPStatus.OK, rows)

        if method == "GET" and path == "/api/crew/assigned-vessel":
            user = self.require_role("CREW", query)
            if not user:
                return
            row = self.crew_assigned_vessel(conn, user["id"])
            if not row:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "No vessel assigned yet."})
            return self.json_response(HTTPStatus.OK, dict(row))

        if method == "POST" and path == "/api/crew/entries":
            user = self.require_role("CREW", query)
            if not user:
                return
            body = self.read_json() or {}
            category = body.get("category")
            notes = (body.get("notes") or "").strip()
            if category not in VALID_CATEGORIES:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid category."})
            if not notes:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Notes are required."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            ts = now_iso()
            row = {
                "id": str(uuid4()), "timestamp": ts, "vessel_id": vessel["id"], "crew_user_id": user["id"],
                "category": category, "notes": notes, "created_at": ts, "updated_at": ts,
            }
            conn.execute("""
                INSERT INTO log_entries (id, timestamp, vessel_id, crew_user_id, category, notes, created_at, updated_at)
                VALUES (:id, :timestamp, :vessel_id, :crew_user_id, :category, :notes, :created_at, :updated_at)
            """, row)
            conn.commit()
            row["vessel_name"] = vessel["name"]
            return self.json_response(HTTPStatus.CREATED, row)

        if method == "GET" and path == "/api/crew/entries":
            user = self.require_role("CREW", query)
            if not user:
                return
            rows = [dict(r) for r in conn.execute("""
                SELECT e.*, v.name AS vessel_name
                FROM log_entries e JOIN vessels v ON v.id = e.vessel_id
                WHERE e.crew_user_id = ? ORDER BY e.timestamp DESC
            """, (user["id"],)).fetchall()]
            return self.json_response(HTTPStatus.OK, rows)

        if method == "GET" and path == "/api/crew/entries/daily-summary":
            user = self.require_role("CREW", query)
            if not user:
                return
            rows = conn.execute("""
                SELECT substr(e.timestamp,1,10) AS day, e.category, e.timestamp, e.notes, e.id, v.name AS vessel_name
                FROM log_entries e JOIN vessels v ON v.id = e.vessel_id
                WHERE e.crew_user_id = ? ORDER BY e.timestamp DESC
            """, (user["id"],)).fetchall()
            grouped = {}
            for row in rows:
                day = row["day"]
                if day not in grouped:
                    grouped[day] = {"day": day, "vessel_name": row["vessel_name"], "count": 0, "entries": []}
                grouped[day]["count"] += 1
                grouped[day]["entries"].append({"id": row["id"], "timestamp": row["timestamp"], "category": row["category"], "notes": row["notes"]})
            summary = list(grouped.values())
            summary.sort(key=lambda x: x["day"], reverse=True)
            return self.json_response(HTTPStatus.OK, summary)

        if method == "GET" and path == "/api/crew/entries/export.pdf":
            user = self.require_role("CREW", query)
            if not user:
                return
            day = (query.get("day") or [""])[0]
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "day query parameter is required in YYYY-MM-DD format."})
            rows = [dict(r) for r in conn.execute("""
                SELECT e.*, v.name AS vessel_name
                FROM log_entries e JOIN vessels v ON v.id = e.vessel_id
                WHERE e.crew_user_id = ? AND substr(e.timestamp,1,10) = ? ORDER BY e.timestamp ASC
            """, (user["id"], day)).fetchall()]
            vessel_name = rows[0]["vessel_name"] if rows else "N/A"
            payload = render_entries_pdf(rows, user["username"], vessel_name, day)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=harborlog-entries-{day}.pdf")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if method == "GET" and path == "/api/crew/daily-report":
            user = self.require_role("CREW", query)
            if not user:
                return
            day = (query.get("day") or [today_utc()])[0]
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid day format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            row = conn.execute("""
                SELECT * FROM daily_reports WHERE vessel_id = ? AND report_day = ?
            """, (vessel["id"], day)).fetchone()
            since_24h = (datetime.now(timezone.utc)-timedelta(hours=24)).replace(microsecond=0).isoformat().replace("+00:00","Z")
            tr = conn.execute("SELECT COALESCE(SUM(gallons),0) AS t FROM fuel_events WHERE vessel_id=? AND event_type='transfer_internal' AND timestamp>=?", (vessel["id"], since_24h)).fetchone()["t"]
            return self.json_response(HTTPStatus.OK, {
                "day": day,
                "vessel": {"id": vessel["id"], "name": vessel["name"]},
                "report": dict(row) if row else None,
                "fuel_transfer_24h_gallons": float(tr or 0),
            })

        if method == "POST" and path == "/api/crew/daily-report":
            user = self.require_role("CREW", query)
            if not user:
                return
            body = self.read_json() or {}
            day = (body.get("day") or today_utc()).strip()
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid day format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            try:
                fuel_burned = float(body.get("fuel_burned"))
                water_onboard = float(body.get("water_onboard"))
                pob_count = int(body.get("pob_count"))
                meal_count = int(body.get("meal_count"))
                jsa_count = int(body.get("jsa_count"))
            except (TypeError, ValueError):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Numeric fields must be valid numbers."})
            preventers_checked = 1 if bool(body.get("preventers_checked")) else 0
            master_remarks = (body.get("master_remarks") or "").strip()
            if not master_remarks:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Master remarks are required."})

            ts = now_iso()
            existing = conn.execute(
                "SELECT * FROM daily_reports WHERE vessel_id = ? AND report_day = ?",
                (vessel["id"], day),
            ).fetchone()
            if existing:
                conn.execute("""
                    UPDATE daily_reports
                    SET crew_user_id=?, fuel_burned=?, water_onboard=?, pob_count=?, meal_count=?,
                        jsa_count=?, preventers_checked=?, master_remarks=?, updated_at=?
                    WHERE id=?
                """, (user["id"], fuel_burned, water_onboard, pob_count, meal_count, jsa_count, preventers_checked, master_remarks, ts, existing["id"]))
                conn.commit()
                updated = conn.execute("SELECT * FROM daily_reports WHERE id = ?", (existing["id"],)).fetchone()
                return self.json_response(HTTPStatus.OK, dict(updated))

            report = {
                "id": str(uuid4()), "vessel_id": vessel["id"], "crew_user_id": user["id"], "report_day": day,
                "fuel_burned": fuel_burned, "water_onboard": water_onboard, "pob_count": pob_count,
                "meal_count": meal_count, "jsa_count": jsa_count, "preventers_checked": preventers_checked,
                "master_remarks": master_remarks, "created_at": ts, "updated_at": ts,
            }
            conn.execute("""
                INSERT INTO daily_reports (id, vessel_id, crew_user_id, report_day, fuel_burned, water_onboard, pob_count,
                    meal_count, jsa_count, preventers_checked, master_remarks, created_at, updated_at)
                VALUES (:id, :vessel_id, :crew_user_id, :report_day, :fuel_burned, :water_onboard, :pob_count,
                    :meal_count, :jsa_count, :preventers_checked, :master_remarks, :created_at, :updated_at)
            """, report)
            conn.commit()
            return self.json_response(HTTPStatus.CREATED, report)

        if method == "GET" and path == "/api/crew/daily-report/export.pdf":
            user = self.require_role("CREW", query)
            if not user:
                return
            day = (query.get("day") or [today_utc()])[0]
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid day format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            report = conn.execute("SELECT * FROM daily_reports WHERE vessel_id = ? AND report_day = ?", (vessel["id"], day)).fetchone()
            if not report:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "No daily report found for selected day."})
            payload = render_daily_report_pdf(dict(report), vessel["name"], day, user["username"])
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=harborlog-daily-report-{day}.pdf")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return


        if method == "GET" and path == "/api/admin/daily-ops-reports":
            if not self.require_role("ADMIN", query):
                return
            day = (query.get("day") or [""])[0]
            vessel_id = (query.get("vessel_id") or [""])[0]
            q = """
                SELECT r.*, v.name AS vessel_name, u.username AS crew_username
                FROM daily_ops_reports r
                JOIN vessels v ON v.id = r.vessel_id
                JOIN users u ON u.id = r.crew_user_id
                WHERE 1=1
            """
            args = []
            if day:
                q += " AND r.report_day = ?"
                args.append(day)
            if vessel_id:
                q += " AND r.vessel_id = ?"
                args.append(vessel_id)
            q += " ORDER BY r.report_day DESC, vessel_name ASC"
            rows = [dict(r) for r in conn.execute(q, tuple(args)).fetchall()]
            return self.json_response(HTTPStatus.OK, rows)

        if method == "GET" and path == "/api/crew/daily-ops-report":
            user = self.require_role("CREW", query)
            if not user:
                return
            day = (query.get("day") or [today_utc()])[0]
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid day format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            report = conn.execute("SELECT * FROM daily_ops_reports WHERE vessel_id=? AND report_day=?", (vessel["id"], day)).fetchone()
            last_report = conn.execute("SELECT * FROM daily_ops_reports WHERE vessel_id=? ORDER BY report_day DESC LIMIT 1", (vessel["id"],)).fetchone()
            return self.json_response(HTTPStatus.OK, {
                "report_date": day,
                "vessel": {"id": vessel["id"], "name": vessel["name"]},
                "report": dict(report) if report else None,
                "last_report": dict(last_report) if last_report else None,
            })

        if method == "POST" and path == "/api/crew/daily-ops-report":
            user = self.require_role("CREW", query)
            if not user:
                return
            body = self.read_json() or {}
            day = (body.get("report_date") or body.get("day") or today_utc()).strip()
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid report_date format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})

            required_text = ["position_type", "position_text", "status", "status_notes", "destination_location", "wind", "seas", "visibility", "fuel_ticket_number"]
            for key in required_text:
                if not str(body.get(key, "")).strip():
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": f"{key} is required."})
            if body.get("position_type") not in {"LatLon", "Block"}:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "position_type must be LatLon or Block."})

            eta_val = body.get("eta")
            eta = None
            if eta_val:
                try:
                    eta = datetime.fromisoformat(str(eta_val).replace("Z", "+00:00")).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                except Exception:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "eta is invalid."})

            next_cc = (body.get("next_crew_change_date") or "").strip() or None
            if next_cc and not valid_day(next_cc):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "next_crew_change_date must be YYYY-MM-DD."})

            try:
                vals = {
                    "fuel_onboard": float(body.get("fuel_onboard")),
                    "fuel_used_24h": float(body.get("fuel_used_24h")),
                    "water_onboard": float(body.get("water_onboard")),
                    "lube_oil_onboard": float(body.get("lube_oil_onboard")),
                    "pob": int(body.get("pob")),
                }
                jsa_count = None if body.get("jsa_count") in (None, "") else int(body.get("jsa_count"))
            except Exception:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Numeric fields are invalid."})

            attachment_path = None
            attachment = body.get("fuel_ticket_attachment") or {}
            if attachment and isinstance(attachment, dict) and attachment.get("content_base64") and attachment.get("filename"):
                original_name = Path(str(attachment['filename'])).name
                if not original_name.lower().endswith('.pdf'):
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Fuel ticket attachment must be a .pdf file."})
                safe_name = f"{uuid4()}.pdf"
                out = UPLOAD_DIR / safe_name
                try:
                    raw = base64.b64decode(attachment["content_base64"])
                except Exception:
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid fuel_ticket_attachment payload."})
                if not raw.startswith(b"%PDF-"):
                    return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Fuel ticket attachment content must be a valid PDF."})
                out.write_bytes(raw)
                attachment_path = str(Path('data') / 'uploads' / safe_name)

            ts = now_iso()
            existing = conn.execute("SELECT * FROM daily_ops_reports WHERE vessel_id=? AND report_day=?", (vessel["id"], day)).fetchone()
            payload = {
                "vessel_id": vessel["id"], "crew_user_id": user["id"], "report_day": day, "report_timestamp": ts,
                "position_type": str(body.get("position_type")).strip(),
                "position_text": str(body.get("position_text")).strip(),
                "status": str(body.get("status")).strip(),
                "status_notes": str(body.get("status_notes")).strip(),
                "destination_location": str(body.get("destination_location")).strip(),
                "eta": eta,
                "wind": str(body.get("wind")).strip(),
                "seas": str(body.get("seas")).strip(),
                "visibility": str(body.get("visibility")).strip(),
                "fuel_onboard": vals["fuel_onboard"], "fuel_used_24h": vals["fuel_used_24h"],
                "water_onboard": vals["water_onboard"], "lube_oil_onboard": vals["lube_oil_onboard"],
                "fuel_ticket_number": str(body.get("fuel_ticket_number")).strip(),
                "fuel_ticket_attachment_path": attachment_path,
                "pob": vals["pob"],
                "next_crew_change_date": next_cc,
                "jsa_count": jsa_count,
                "jsa_breakdown": str(body.get("jsa_breakdown") or "").strip() or None,
                "updated_at": ts,
            }

            if existing:
                if not payload["fuel_ticket_attachment_path"]:
                    payload["fuel_ticket_attachment_path"] = existing["fuel_ticket_attachment_path"]
                conn.execute("""
                    UPDATE daily_ops_reports SET
                    crew_user_id=:crew_user_id, report_timestamp=:report_timestamp,
                    position_type=:position_type, position_text=:position_text,
                    status=:status, status_notes=:status_notes,
                    destination_location=:destination_location, eta=:eta,
                    wind=:wind, seas=:seas, visibility=:visibility,
                    fuel_onboard=:fuel_onboard, fuel_used_24h=:fuel_used_24h,
                    water_onboard=:water_onboard, lube_oil_onboard=:lube_oil_onboard,
                    fuel_ticket_number=:fuel_ticket_number, fuel_ticket_attachment_path=:fuel_ticket_attachment_path,
                    pob=:pob, next_crew_change_date=:next_crew_change_date,
                    jsa_count=:jsa_count, jsa_breakdown=:jsa_breakdown,
                    updated_at=:updated_at
                    WHERE id=:id
                """, {**payload, "id": existing["id"]})
                conn.commit()
                row = conn.execute("SELECT * FROM daily_ops_reports WHERE id=?", (existing["id"],)).fetchone()
                return self.json_response(HTTPStatus.OK, dict(row))

            row = {"id": str(uuid4()), "created_at": ts, **payload}
            conn.execute("""
                INSERT INTO daily_ops_reports (
                    id, vessel_id, crew_user_id, report_day, report_timestamp,
                    position_type, position_text, status, status_notes,
                    destination_location, eta, wind, seas, visibility,
                    fuel_onboard, fuel_used_24h, water_onboard, lube_oil_onboard,
                    fuel_ticket_number, fuel_ticket_attachment_path,
                    pob, next_crew_change_date, jsa_count, jsa_breakdown,
                    created_at, updated_at
                ) VALUES (
                    :id, :vessel_id, :crew_user_id, :report_day, :report_timestamp,
                    :position_type, :position_text, :status, :status_notes,
                    :destination_location, :eta, :wind, :seas, :visibility,
                    :fuel_onboard, :fuel_used_24h, :water_onboard, :lube_oil_onboard,
                    :fuel_ticket_number, :fuel_ticket_attachment_path,
                    :pob, :next_crew_change_date, :jsa_count, :jsa_breakdown,
                    :created_at, :updated_at
                )
            """, row)
            conn.commit()
            return self.json_response(HTTPStatus.CREATED, row)

        if method == "GET" and path == "/api/crew/daily-ops-report/view":
            user = self.require_role("CREW", query)
            if not user:
                return
            day = (query.get("day") or [today_utc()])[0]
            view = (query.get("view") or ["om"])[0].lower()
            if view not in {"om", "office"}:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "view must be om or office."})
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid day format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            report = conn.execute("SELECT * FROM daily_ops_reports WHERE vessel_id=? AND report_day=?", (vessel["id"], day)).fetchone()
            if not report:
                return self.json_response(HTTPStatus.OK, {"text": "No Daily Ops Report for selected day."})
            report_dict = dict(report)
            text = format_daily_ops_view(report_dict, vessel["name"], day, view)
            fuel_ticket_url = None
            if report_dict.get("fuel_ticket_attachment_path"):
                fuel_ticket_url = f"/api/daily-ops-report/fuel-ticket?report_id={report_dict['id']}"
            return self.json_response(HTTPStatus.OK, {"text": text, "fuel_ticket_number": report_dict["fuel_ticket_number"], "fuel_ticket_url": fuel_ticket_url})

        if method == "GET" and path == "/api/crew/daily-ops-report/export.pdf":
            user = self.require_role("CREW", query)
            if not user:
                return
            day = (query.get("day") or [today_utc()])[0]
            view = (query.get("view") or ["om"])[0].lower()
            if view not in {"om", "office"}:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "view must be om or office."})
            if not valid_day(day):
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid day format. Use YYYY-MM-DD."})
            vessel = self.crew_assigned_vessel(conn, user["id"])
            if not vessel:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "Crew member is not assigned to a vessel."})
            report = conn.execute("SELECT * FROM daily_ops_reports WHERE vessel_id = ? AND report_day = ?", (vessel["id"], day)).fetchone()
            if not report:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "No daily ops report found for selected day."})
            payload = render_daily_ops_pdf(dict(report), vessel["name"], day, view)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=harborlog-daily-ops-{view}-{day}.pdf")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return


        if method == "GET" and path == "/api/daily-ops-report/fuel-ticket":
            user = self.require_auth(query)
            if not user:
                return
            report_id = (query.get("report_id") or [""])[0]
            if not report_id:
                return self.json_response(HTTPStatus.BAD_REQUEST, {"error": "report_id is required."})
            report = conn.execute("SELECT * FROM daily_ops_reports WHERE id = ?", (report_id,)).fetchone()
            if not report:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "Report not found."})
            if user.get("role") == "CREW":
                vessel = self.crew_assigned_vessel(conn, user["id"])
                if not vessel or vessel["id"] != report["vessel_id"]:
                    return self.json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden."})
            elif user.get("role") != "ADMIN":
                return self.json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden."})

            attachment_path = report["fuel_ticket_attachment_path"]
            if not attachment_path:
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "No fuel ticket PDF attached for this report."})
            full = BASE_DIR / attachment_path
            if not full.exists() or not full.is_file():
                return self.json_response(HTTPStatus.NOT_FOUND, {"error": "Attached fuel ticket file not found."})
            payload = full.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=fuel-ticket-{report_id}.pdf")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        return self.json_response(HTTPStatus.NOT_FOUND, {"error": "Not found."})


def main():
    init_db()
    httpd = ThreadingHTTPServer((HOST, PORT), HarborLogHandler)
    print(f"HarborLog running on http://localhost:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
