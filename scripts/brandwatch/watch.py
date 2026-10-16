#!/usr/bin/env python3
"""brandwatch - enumera clones/typosquat de una marca con dnstwist y los
centraliza en SQLite; con --report emite candidatos (Markdown) para revision.

Uso:
  python3 watch.py                 # enumera seeds.txt -> ledger.sqlite
  python3 watch.py --report        # imprime candidatos (Markdown)
  python3 watch.py --seeds seeds.txt --db ledger.sqlite --top 200

Requiere dnstwist:  pip install dnstwist
No auto-bloquea: los candidatos son para revision humana; luego se pasan a
data/custom/malware-hosts (o blacklist.txt) y `update.py --curated`.
"""
import argparse, datetime, json, shutil, sqlite3, subprocess, sys
from pathlib import Path

HERE = Path(__file__).parent
DEFAULT_SEEDS = HERE / "seeds.txt"
DEFAULT_DB = HERE / "ledger.sqlite"


def run_dnstwist(seed, timeout=300):
    exe = shutil.which("dnstwist")
    if not exe:
        sys.exit("error: dnstwist no instalado (pip install dnstwist)")
    cmd = [exe, "--registered", "--whois", "--mxcheck",
           "--format", "json", "--threads", "5", seed]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
        return json.loads(out or "[]")
    except Exception as e:
        print(f"  !! {seed}: {e}", file=sys.stderr)
        return []


def field(r, *names):
    for n in names:
        v = r.get(n)
        if v:
            return v if isinstance(v, str) else str(v)
    return ""


def init_db(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS domains(
        domain TEXT PRIMARY KEY, source TEXT, first_seen TEXT, seed TEXT,
        dns_a TEXT, dns_mx TEXT, whois_created TEXT, verdict TEXT DEFAULT 'nuevo')""")
    conn.commit()


def upsert(conn, rows, seed):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    for r in rows:
        d = field(r, "domain-name", "domain")
        if not d:
            continue
        conn.execute(
            """INSERT INTO domains(domain,source,first_seen,seed,dns_a,dns_mx,whois_created)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET
                 dns_a=excluded.dns_a, dns_mx=excluded.dns_mx,
                 whois_created=excluded.whois_created""",
            (d.lower(), "dnstwist", now, seed,
             field(r, "dns-a", "dns_a"), field(r, "dns-mx", "dns_mx"),
             field(r, "whois-created", "whois_created")))
    conn.commit()


def report(conn, top):
    rows = conn.execute(
        """SELECT domain, seed, dns_mx, whois_created FROM domains
           WHERE dns_a!=''
           ORDER BY (dns_mx!='') DESC, whois_created DESC LIMIT ?""",
        (top,)).fetchall()
    print(f"# brandwatch - candidatos typosquat/clones "
          f"({datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d})\n")
    if not rows:
        print("_Sin candidatos registrados en esta corrida._")
        return
    print("| dominio | seed | MX | WHOIS creado |")
    print("|---|---|---|---|")
    for d, s, mx, wc in rows:
        print(f"| `{d}` | {s} | {'si' if mx else ''} | {wc} |")
    print("\n> Revisar y, si aplica, agregar a `data/custom/malware-hosts` "
          "(lista TV Box) y correr `update.py --curated`.")


def main():
    ap = argparse.ArgumentParser(description="brandwatch (dnstwist -> SQLite)")
    ap.add_argument("--seeds", default=str(DEFAULT_SEEDS))
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--report", action="store_true", help="imprime candidatos (Markdown)")
    ap.add_argument("--top", type=int, default=200)
    args = ap.parse_args()

    seeds = [s.strip() for s in Path(args.seeds).read_text().splitlines()
             if s.strip() and not s.startswith("#")]
    conn = sqlite3.connect(args.db)
    init_db(conn)
    total = 0
    for s in seeds:
        rows = run_dnstwist(s)
        upsert(conn, rows, s)
        total += len(rows)
        print(f"  -> {s}: {len(rows)} permutaciones")
    print(f"[ok] {total} permutaciones -> {args.db}")
    if args.report:
        report(conn, args.top)


if __name__ == "__main__":
    main()
