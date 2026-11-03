"""Performance benchmark of the cryptography used by the system (Python / OpenSSL).

    python scripts/benchmark.py            # sizes 1 KB .. 64 MB, about a minute
    python scripts/benchmark.py --quick    # sizes 1 KB .. 1 MB, a few seconds

Measures, for each plaintext length:  encryption (AES-256-CBC + HMAC-SHA256), decryption (MAC check + AES),
SHA-256 of the ciphertext, and throughput.  Also measures the size-independent public-key operations:
RSA-2048 signature generation and verification, RSA-OAEP key wrap / unwrap, RSA key generation.

Each number is the MEDIAN of several repeated measurements (each repeat averages many iterations for small
inputs so timer resolution does not matter).  Writes into report/:
    benchmark_results.json   (also displayed by the web UI, Performance tab)
    benchmark_results.csv
    figures/encryption_time_vs_size.png, throughput_vs_size.png, signature_times.png
"""
import argparse, csv, datetime, hashlib, json, os, platform, statistics, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from client import envelope as E                               # noqa: E402

SIZES_FULL = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20]
SIZES_QUICK = [1 << 10, 16 << 10, 256 << 10, 1 << 20]
pc = time.perf_counter


def measure(fn, min_time=0.05, repeats=5):
    """Median / min / max milliseconds per call. Iterations are scaled until one repeat lasts >= min_time."""
    n = 1
    while True:
        t = pc()
        for _ in range(n):
            fn()
        el = pc() - t
        if el >= min_time or n >= 1 << 20:
            break
        n = max(n * 2, int(n * min_time / max(el, 1e-9)))
    samples = []
    for _ in range(repeats):
        t = pc()
        for _ in range(n):
            fn()
        samples.append((pc() - t) / n * 1000)
    return dict(median=statistics.median(samples), min=min(samples), max=max(samples), n=n * repeats)


def human(n):
    return f"{n // (1 << 20)} MB" if n >= 1 << 20 else f"{n // 1024} KB"


def run(sizes, repeats):
    series = {"encrypt_ms": [], "decrypt_ms": [], "hash_ms": []}
    spread = {k: {"min": [], "max": []} for k in series}
    for size in sizes:
        plain = os.urandom(size)
        blob, keymat = E.encrypt(plain)
        big = size >= 4 << 20
        reps, mt = (3 if big else repeats), (0.0 if big else 0.05)
        for key, fn in (("encrypt_ms", lambda: E.encrypt(plain)), ("decrypt_ms", lambda: E.decrypt(blob, keymat)),
                        ("hash_ms", lambda: hashlib.sha256(blob).digest())):
            m = measure(fn, mt, reps)
            series[key].append(m["median"]); spread[key]["min"].append(m["min"]); spread[key]["max"].append(m["max"])
        print(f"  {human(size):>6}: encrypt {series['encrypt_ms'][-1]:9.3f} ms   decrypt {series['decrypt_ms'][-1]:9.3f} ms   "
              f"sha256 {series['hash_ms'][-1]:8.3f} ms", flush=True)
    priv = E.generate_rsa()
    pub = priv.public_key()
    km = os.urandom(64)
    wk = E.wrap_key(pub, km)
    msg = E.transfer_message("alice", "bob", "f" * 64, "evidence.bin", "application/octet-stream", 1234567,
                             "a" * 64, "b" * 64, 1700000000, "c" * 32)
    sig = E.sign(priv, msg)
    ops = {
        "rsa2048_sign_ms": measure(lambda: E.sign(priv, msg), 0.1, repeats),
        "rsa2048_verify_ms": measure(lambda: E.verify(pub, msg, sig), 0.1, repeats),
        "rsa_oaep_wrap_ms": measure(lambda: E.wrap_key(pub, km), 0.1, repeats),
        "rsa_oaep_unwrap_ms": measure(lambda: E.unwrap_key(priv, wk), 0.1, repeats),
        "rsa2048_keygen_ms": measure(E.generate_rsa, 0.0, 5),
    }
    for k, v in ops.items():
        print(f"  {k:<22} median {v['median']:9.3f} ms  (min {v['min']:.3f}, max {v['max']:.3f})")
    return series, spread, ops


def write_outputs(sizes, series, spread, ops, out):
    import cryptography
    rep = dict(generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               engine="Python " + platform.python_version() + " / cryptography " + cryptography.__version__ + " (OpenSSL)",
               host=dict(platform=platform.platform(), machine=platform.machine(), processor=platform.processor() or "n/a"),
               scheme="AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC); RSA-2048 OAEP key wrap and PSS signatures",
               sizes_bytes=sizes, series=series, spread=spread, ops=ops)
    os.makedirs(os.path.join(out, "figures"), exist_ok=True)
    json.dump(rep, open(os.path.join(out, "benchmark_results.json"), "w", encoding="utf-8"), indent=2)
    with open(os.path.join(out, "benchmark_results.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["plaintext_bytes", "encrypt_ms", "decrypt_ms", "sha256_ms", "encrypt_MB_per_s", "decrypt_MB_per_s"])
        for i, s in enumerate(sizes):
            w.writerow([s, f"{series['encrypt_ms'][i]:.4f}", f"{series['decrypt_ms'][i]:.4f}", f"{series['hash_ms'][i]:.4f}",
                        f"{s / 1048576 / (series['encrypt_ms'][i] / 1000):.1f}", f"{s / 1048576 / (series['decrypt_ms'][i] / 1000):.1f}"])
    return rep


# ------------------------------------------------------------------ figures (palette validated with the dataviz validator)
SURF, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"


def figures(rep, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter

    plt.rcParams.update({"font.family": "DejaVu Sans", "axes.edgecolor": AXIS, "axes.labelcolor": INK2,
                         "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK, "figure.facecolor": SURF,
                         "axes.facecolor": SURF, "axes.spines.top": False, "axes.spines.right": False})
    sizes, s, ops = rep["sizes_bytes"], rep["series"], rep["ops"]
    fmt_size = FuncFormatter(lambda v, _: human(int(v)) if v >= 1024 else f"{int(v)} B")

    def style(ax):
        ax.grid(True, color=GRID, linewidth=1, linestyle="-")
        ax.set_axisbelow(True)

    def line(ax, ys, color, marker, label, dy=0):
        ax.plot(sizes, ys, color=color, linewidth=2, marker=marker, markersize=7, markeredgecolor=SURF,
                markeredgewidth=1.5, solid_capstyle="round", label=label)
        ax.annotate(label, (sizes[-1], ys[-1]), xytext=(8, dy), textcoords="offset points", va="center", color=INK2, fontsize=9)

    # 1. time vs plaintext length
    fig, ax = plt.subplots(figsize=(8.2, 4.8), dpi=140)
    style(ax)
    line(ax, s["encrypt_ms"], BLUE, "o", "Encrypt", 6)
    line(ax, s["decrypt_ms"], ORANGE, "s", "Decrypt", -6)
    line(ax, s["hash_ms"], AQUA, "^", "SHA-256 of ciphertext")
    ax.set_xscale("log", base=2); ax.set_yscale("log")
    ax.set_xticks(sizes); ax.xaxis.set_major_formatter(fmt_size)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    ax.set_xlabel("Plaintext length"); ax.set_ylabel("Time per operation (ms, log scale)")
    ax.set_title("Encryption time grows linearly with plaintext length", loc="left", fontsize=12, color=INK, pad=12)
    ax.legend(frameon=False, loc="upper left", fontsize=9, labelcolor=INK2)
    ax.margins(x=0.22)
    fig.text(0.01, 0.01, rep["engine"] + " - median of repeated runs", fontsize=7.5, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 1)); fig.savefig(os.path.join(out, "figures", "encryption_time_vs_size.png")); plt.close(fig)

    # 2. throughput
    fig, ax = plt.subplots(figsize=(8.2, 4.4), dpi=140)
    style(ax)
    mbps = lambda ms: [sz / 1048576 / (t / 1000) for sz, t in zip(sizes, ms)]
    line(ax, mbps(s["encrypt_ms"]), BLUE, "o", "Encrypt", 6)
    line(ax, mbps(s["decrypt_ms"]), ORANGE, "s", "Decrypt", -6)
    ax.set_xscale("log", base=2); ax.set_xticks(sizes); ax.xaxis.set_major_formatter(fmt_size)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    ax.set_xlabel("Plaintext length"); ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("Throughput rises with length: fixed costs are amortised", loc="left", fontsize=12, color=INK, pad=12)
    ax.legend(frameon=False, loc="lower right", fontsize=9, labelcolor=INK2); ax.margins(x=0.22)
    fig.tight_layout(); fig.savefig(os.path.join(out, "figures", "throughput_vs_size.png")); plt.close(fig)

    # 3. public-key operations (single series, one colour)
    names = [("rsa2048_verify_ms", "RSA-2048 verify signature"), ("rsa_oaep_wrap_ms", "RSA-OAEP wrap key"),
             ("rsa2048_sign_ms", "RSA-2048 generate signature"), ("rsa_oaep_unwrap_ms", "RSA-OAEP unwrap key")]
    names.sort(key=lambda kv: ops[kv[0]]["median"])
    fig, ax = plt.subplots(figsize=(8.2, 3.2), dpi=140)
    style(ax)
    ax.grid(False, axis="y")
    for i, (k, label) in enumerate(names):
        v = ops[k]["median"]
        ax.barh(i, v, height=0.5, color=BLUE, edgecolor=SURF)
        ax.text(v * 1.08, i, f"{v:.3f} ms", va="center", fontsize=9, color=INK2)
    ax.set_yticks(range(len(names))); ax.set_yticklabels([n for _, n in names], color=INK2)
    ax.set_xscale("log"); ax.set_xlabel("Median time per operation (ms, log scale)")
    ax.set_title("Signature and key-wrap cost does not depend on file size", loc="left", fontsize=12, color=INK, pad=12)
    ax.margins(x=0.3)
    kg = ops["rsa2048_keygen_ms"]["median"]
    fig.text(0.01, 0.01, f"RSA-2048 key generation (one-off): {kg:.0f} ms", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(os.path.join(out, "figures", "signature_times.png")); plt.close(fig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="small sizes only")
    ap.add_argument("--out", default=os.path.join(ROOT, "report"), help="output directory")
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args()
    sizes = SIZES_QUICK if a.quick else SIZES_FULL
    print("Benchmarking", "(quick)" if a.quick else "(full)", "...")
    series, spread, ops = run(sizes, 3 if a.quick else 5)
    rep = write_outputs(sizes, series, spread, ops, a.out)
    if not a.no_plots:
        figures(rep, a.out)
    print("Wrote", os.path.join(a.out, "benchmark_results.json"), "and figures/*.png")
