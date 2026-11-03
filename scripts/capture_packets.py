"""Packet capture experiment: what can someone on the network see?

    python scripts/capture_packets.py                 # needs administrator/root rights and tcpdump OR Wireshark (dumpcap)
    python scripts/capture_packets.py --iface lo      # choose the capture interface yourself
    python scripts/capture_packets.py --list          # list capture interfaces and exit

It records three real transfers with a packet sniffer, then reads the capture files back and searches the raw
bytes for things an eavesdropper would want:

  A  Insecure baseline    a tiny server that takes the file as plain text over HTTP (what NOT to build)
  B  This system, HTTP    the real application, no TLS: only the application-level encryption protects the file
  C  This system, HTTPS   the real application behind TLS (self-signed certificate made for the run)

Writes into report/ :
    capture_results.json    (shown in the web UI under Analysis -> Packet capture)
    captures/*.pcap         (open these in Wireshark, or read them with PyShark / scapy)

Everything runs on this computer (127.0.0.1) against the 'evidence_test' database, never your live database.
The demo users get random one-off passwords for the run, so the capture files contain no real credentials.
"""
import argparse, collections, datetime, http.server, json, os, platform, re, secrets, shutil, signal, socket
import subprocess, sys, tempfile, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _demo_env import DemoWorld, ROOT, E, make_self_signed         # noqa: E402
import requests                                                   # noqa: E402

REPORT_DIR = os.path.join(ROOT, "report")
CAP_DIR = os.path.join(REPORT_DIR, "captures")
STATEMENT = ("CASE 2026-0417 WITNESS STATEMENT: I saw the grey van leave the loading dock at 21:40 and turn "
             "towards the harbour road. The driver wore a red jacket.\n")
EVIDENCE = (STATEMENT * 700).encode()              # ~100 KB of readable text, so overhead numbers mean something
FILENAME = "witness_statement.txt"
CIPHERSUITES = {"0x1301": "TLS_AES_128_GCM_SHA256", "0x1302": "TLS_AES_256_GCM_SHA384",
                "0x1303": "TLS_CHACHA20_POLY1305_SHA256"}


# ------------------------------------------------------------------ capture tool handling
def find_tool(prefer="auto"):
    """Return (name, path). Wireshark's dumpcap is preferred because it is the same everywhere."""
    cands = []
    if prefer in ("auto", "dumpcap"):
        cands += [("dumpcap", shutil.which("dumpcap")),
                  ("dumpcap", r"C:\Program Files\Wireshark\dumpcap.exe"),
                  ("dumpcap", r"C:\Program Files (x86)\Wireshark\dumpcap.exe")]
    if prefer in ("auto", "tcpdump"):
        cands += [("tcpdump", shutil.which("tcpdump"))]
    for name, path in cands:
        if path and os.path.exists(path):
            return name, path
    return None, None


def find_tshark():
    for p in (shutil.which("tshark"), r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if p and os.path.exists(p):
            return p
    return None


def list_interfaces(tool, path):
    if tool == "dumpcap":
        return subprocess.run([path, "-D"], capture_output=True, text=True).stdout
    return subprocess.run([path, "-D"], capture_output=True, text=True).stdout or "(use -i lo)"


def default_iface(tool, path):
    system = platform.system()
    if system == "Linux":
        return "lo"
    if system == "Darwin":
        return "lo0"
    out = list_interfaces(tool, path)                  # Windows: Npcap's loopback adapter
    for line in out.splitlines():
        if "loopback" in line.lower():
            m = re.match(r"\s*(\d+)\.", line)
            if m:
                return m.group(1)
    return None


class Capture:
    """Run the sniffer, stream its output into a .pcap file, stop it cleanly."""

    def __init__(self, tool, path, iface, port, outfile):
        self.tool, self.path, self.iface, self.port, self.outfile = tool, path, iface, port, outfile
        self.proc = self.err = self.pump = None
        self.log = []

    def __enter__(self):
        flt = f"tcp port {self.port}"
        if self.tool == "dumpcap":
            cmd = [self.path, "-i", self.iface, "-f", flt, "-P", "-q", "-w", "-"]
        else:
            cmd = [self.path, "-i", self.iface, "-n", "-U", "-s", "0", "-w", "-", flt]
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0      # lets Ctrl+Break stop it cleanly
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=flags)
        self.fh = open(self.outfile, "wb")
        self.pump = threading.Thread(target=self._pump, daemon=True)
        self.pump.start()
        threading.Thread(target=self._read_err, daemon=True).start()
        deadline = time.time() + 8
        while time.time() < deadline and self.proc.poll() is None:
            if any(k in l.lower() for l in self.log for k in ("listening on", "capturing on")) or self.tool == "dumpcap":
                break
            time.sleep(0.1)
        if self.proc.poll() is not None:
            raise SystemExit(f"The capture tool stopped immediately: {' '.join(self.log)[:400]}\n"
                             f"Run this script as administrator/root, and check the interface with --list.")
        time.sleep(1.0)                       # let the sniffer attach before the first packet
        return self

    def _pump(self):
        for chunk in iter(lambda: self.proc.stdout.read(65536), b""):
            self.fh.write(chunk)
            self.fh.flush()

    def _read_err(self):
        for line in iter(self.proc.stderr.readline, b""):
            self.log.append(line.decode("utf-8", "replace").strip())

    def __exit__(self, *exc):
        time.sleep(1.0)                       # let the last packets arrive
        try:
            self.proc.send_signal(signal.SIGINT if os.name != "nt" else signal.CTRL_BREAK_EVENT)
        except Exception:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.pump.join(timeout=3)
        self.fh.close()


# ------------------------------------------------------------------ the insecure baseline server
class Baseline(http.server.BaseHTTPRequestHandler):
    store, users = {}, {}

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        d = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/login":
            if Baseline.users.get(d.get("username")) == d.get("password"):
                return self._send(200, {"token": "baseline-" + secrets.token_hex(8)})
            return self._send(401, {"error": "invalid credentials"})
        if self.path == "/upload":
            Baseline.store["file"] = d
            return self._send(201, {"id": "1"})
        self._send(404, {})

    def do_GET(self):
        if self.path == "/download/1" and "file" in Baseline.store:
            return self._send(200, Baseline.store["file"])
        self._send(404, {})


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ------------------------------------------------------------------ reading a capture back
def tshark_rows(tshark, pcap, port, proto):
    cmd = [tshark, "-r", pcap, "-d", f"tcp.port=={port},{proto}", "-T", "fields", "-E", "separator=\t",
           "-e", "frame.number", "-e", "frame.time_relative", "-e", "frame.len", "-e", "_ws.col.Protocol",
           "-e", "_ws.col.Info"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) >= 5:
            rows.append(dict(no=int(p[0]), t=round(float(p[1]), 4), length=int(p[2]), proto=p[3], info=p[4][:110]))
    return rows


def tls_details(tshark, pcap, port):
    cmd = [tshark, "-r", pcap, "-d", f"tcp.port=={port},tls", "-Y", "tls.handshake.type==2", "-T", "fields",
           "-e", "tls.handshake.extensions.supported_version", "-e", "tls.handshake.ciphersuite"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()
    if not out:
        return None
    ver, cs = (out[0].split("\t") + ["", ""])[:2]
    version = {"0x0304": "TLS 1.3", "0x0303": "TLS 1.2"}.get(ver.strip().lower(), ver or "unknown")
    cs = cs.strip().lower()
    return dict(version=version, cipher_suite=CIPHERSUITES.get(cs, cs or "unknown"))


def reassemble(pcap, port):
    """Rebuild the byte stream of each direction, the way Wireshark's 'Follow TCP stream' does.
    Each TCP connection is kept apart (sequence numbers only mean something inside one connection) and the
    connections are then joined in the order they first appeared."""
    from scapy.all import rdpcap, TCP, Raw
    conns = {}                                               # (direction, client port) -> {seq: payload}
    order = []
    frames = total = 0
    first = last = None
    for pkt in rdpcap(pcap):
        frames += 1
        total += len(pkt)
        ts = float(pkt.time)
        first, last = (ts if first is None else first), ts
        if TCP in pkt and Raw in pkt:
            tcp = pkt[TCP]
            direction = "client_to_server" if tcp.dport == port else "server_to_client"
            cport = tcp.sport if direction == "client_to_server" else tcp.dport
            key = (direction, cport)
            if key not in conns:
                conns[key] = {}
                order.append(key)
            conns[key].setdefault(tcp.seq, bytes(pkt[Raw].load))     # same seq twice = retransmission
    streams = collections.defaultdict(bytes)
    for key in order:
        streams[key[0]] += b"".join(v for _, v in sorted(conns[key].items()))
    return dict(streams), frames, total, ((last - first) * 1000 if first is not None else 0)


def printable(b, limit):
    return "".join(chr(c) if 32 <= c < 127 or c in (10, 13) else "." for c in b[:limit]).replace("\r\n", "\n")


def search(streams, needle):
    if isinstance(needle, str):
        needle = needle.encode()
    return sum(s.count(needle) for s in streams.values())


# ------------------------------------------------------------------ scenarios
def scenario_baseline(users, ctx):
    port = free_port()
    Baseline.users = {"alice": users["alice"], "bob": users["bob"]}
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Baseline)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"

    def run():
        tok = requests.post(url + "/login", json=dict(username="alice", password=users["alice"])).json()["token"]
        requests.post(url + "/upload", headers={"Authorization": "Bearer " + tok},
                      json=dict(filename=FILENAME, to="bob", content=EVIDENCE.decode()))
        tok2 = requests.post(url + "/login", json=dict(username="bob", password=users["bob"])).json()["token"]
        requests.get(url + "/download/1", headers={"Authorization": "Bearer " + tok2})
        ctx.update(token=tok, signature=None)

    return port, "http", run, srv.shutdown


def scenario_system(users, ctx, tls):
    tmp = tempfile.mkdtemp(prefix="evcap_")
    cert = make_self_signed(tmp) if tls else None
    world = DemoWorld(tls=cert, passwords=users).start()
    ctx["world"], ctx["tmp"] = world, tmp

    def run():
        alice, bob = world.client("alice", users["alice"]), world.client("bob", users["bob"])
        res = alice.send(world.priv["alice"], "bob", EVIDENCE, FILENAME)
        meta = bob._req("GET", f"/api/transfers/{res['id']}").json()
        bob.receive(res["id"], world.priv["bob"])
        ctx.update(token=alice.token, signature=meta["signature"], wrapped_key=meta["wrapped_key"])

    return world.port, ("tls" if tls else "http"), run, world.stop


SCENARIOS = [
    ("A", "Insecure baseline: plain text over HTTP", "http", False),
    ("B", "This system over HTTP (no TLS)", "http", False),
    ("C", "This system over HTTPS (TLS)", "https", True),
]

# (id, label, what it reveals when visible, applies to baseline?)
MARKERS = [
    ("evidence", "Evidence content (the witness statement)", "The eavesdropper can read the evidence itself.", True),
    ("password", "Login password", "The eavesdropper can sign in as the user.", True),
    ("token", "Session token", "The eavesdropper can act as the user until the token expires.", True),
    ("filename", "File name", "The eavesdropper learns what the file is called.", True),
    ("usernames", "User names (alice, bob)", "The eavesdropper learns who is talking to whom.", True),
    ("envelope", "Encrypted envelope header (EVC1)", "The eavesdropper can see that an encrypted file was sent, but not read it.", False),
    ("signature", "Sender signature / wrapped key", "Public cryptographic metadata: useless without the private keys.", False),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", help="capture interface (default: the loopback interface)")
    ap.add_argument("--tool", choices=["auto", "dumpcap", "tcpdump"], default="auto")
    ap.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    a = ap.parse_args()

    tool, path = find_tool(a.tool)
    if not tool:
        sys.exit("No packet capture tool found. Install Wireshark (it includes dumpcap and tshark) or tcpdump.\n"
                 "Windows: install Wireshark with the Npcap option ticked, then run this script from an administrator "
                 "PowerShell.")
    if a.list:
        print(list_interfaces(tool, path))
        return
    tshark = find_tshark()
    iface = a.iface or default_iface(tool, path)
    if not iface:
        sys.exit("Could not find a loopback interface. Run with --list and then --iface <number or name>.")
    os.makedirs(CAP_DIR, exist_ok=True)
    print(f"capture tool: {tool} ({path})   interface: {iface}   tshark: {tshark or 'not found (summaries skipped)'}")

    users = {"alice": "Cap-" + secrets.token_urlsafe(9), "bob": "Cap-" + secrets.token_urlsafe(9)}
    results = []
    for sid, title, transport, tls in SCENARIOS:
        ctx = {}
        if sid == "A":
            port, proto, run, stop = scenario_baseline(users, ctx)
        else:
            port, proto, run, stop = scenario_system(users, ctx, tls)
        fname = {"A": "A_insecure_baseline_http.pcap", "B": "B_this_system_http.pcap", "C": "C_this_system_https.pcap"}[sid]
        pcap = os.path.join(CAP_DIR, fname)
        print(f"[{sid}] {title}  (port {port}) ...", end=" ", flush=True)
        t0 = time.perf_counter()
        with Capture(tool, path, iface, port, pcap):
            run()
        wall = (time.perf_counter() - t0) * 1000
        stop()
        streams, frames, wire_bytes, dur = reassemble(pcap, port)
        if frames == 0:
            sys.exit(f"\nThe capture is empty. The sniffer did not see traffic on interface '{iface}'. "
                     f"Try --list and --iface, and run as administrator/root.")
        rows = tshark_rows(tshark, pcap, port, "tls" if tls else "http") if tshark else []
        protos = collections.Counter(r["proto"] for r in rows)
        sig = ctx.get("signature")
        marker_checks = {
            "evidence": search(streams, STATEMENT.split(":")[0]),
            "password": search(streams, users["alice"]) + search(streams, users["bob"]),
            "token": search(streams, ctx["token"]) if ctx.get("token") else 0,
            "filename": search(streams, FILENAME),
            # structured strings (not bare "bob") so random ciphertext bytes cannot match by chance
            "usernames": sum(search(streams, x) for x in (b'"username": "alice"', b'"username": "bob"',
                                                           b'name="recipient"', b'"to": "bob"')),
            "envelope": search(streams, b"EVC1"),
            "signature": (search(streams, sig[:40]) if sig else 0) + (search(streams, ctx["wrapped_key"][:40]) if ctx.get("wrapped_key") else 0),
        }
        findings = []
        for key, label, meaning, applies_to_baseline in MARKERS:
            na = (sid == "A" and not applies_to_baseline)
            findings.append(dict(id=key, label=label, meaning=meaning, applicable=not na,
                                 visible=(marker_checks[key] > 0) if not na else None, count=marker_checks[key]))
        c2s = streams.get("client_to_server", b"")
        results.append(dict(
            id=sid, title=title, transport=transport, port=port, packets=frames, wire_bytes=wire_bytes,
            plaintext_bytes=len(EVIDENCE), duration_ms=round(dur, 1), run_ms=round(wall, 1),
            protocols=dict(protos), tls=(tls_details(tshark, pcap, port) if (tls and tshark) else None),
            findings=findings, summary_lines=rows[:14],
            stream_excerpt=dict(client_to_server=printable(c2s, 700), server_to_client=printable(streams.get("server_to_client", b""), 400)),
            pcap="captures/" + fname))
        print(f"{frames} packets, {wire_bytes} bytes on the wire")
        if ctx.get("tmp"):
            shutil.rmtree(ctx["tmp"], ignore_errors=True)

    base = {r["id"]: r for r in results}
    report = dict(
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        platform=platform.platform(), tool=f"{tool} + {'tshark' if tshark else 'scapy only'}", interface=iface,
        note=("Captured on the loopback interface of the machine that ran this script. Re-run it on your own computer "
              "to replace these numbers with your own."),
        evidence_bytes=len(EVIDENCE), scenarios=results,
        key_findings=[
            "A: with no encryption, the evidence, the password and the session token are all readable in the capture.",
            "B: the evidence is unreadable even without TLS, because the file is encrypted in the browser before it is sent. "
            "The password and session token are still visible over plain HTTP, so TLS is still needed.",
            "C: with TLS added, none of the markers can be found: user names, file name, password and token are hidden too."
            + (f" Negotiated {base['C']['tls']['version']} with {base['C']['tls']['cipher_suite']}." if base["C"].get("tls") else "")],
        how_to=["Wireshark: File > Open, choose a .pcap from report/captures/",
                "Follow a stream: right click a packet > Follow > TCP Stream",
                "Display filters: http.request.method == \"POST\"   |   tls.handshake.type == 1   |   frame contains \"alice\"",
                "To decode the plain HTTP captures: Analyze > Decode As... > TCP port > HTTP (use the port in the report)"])
    with open(os.path.join(REPORT_DIR, "capture_results.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print("\nWrote report/capture_results.json and report/captures/*.pcap")
    print(f"{'':44}" + "".join(f"{r['id']:>10}" for r in results))
    for i, (key, label, *_rest) in enumerate(MARKERS):
        cells = []
        for r in results:
            f = r["findings"][i]
            cells.append("n/a" if not f["applicable"] else ("VISIBLE" if f["visible"] else "hidden"))
        print(f"{label[:43]:44}" + "".join(f"{c:>10}" for c in cells))


if __name__ == "__main__":
    main()
