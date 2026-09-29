#!/usr/bin/env python3
"""Generador minimalista estilo StevenBlack/hosts.
Uso:
  python3 update.py --auto        # fetch + genera hosts
  python3 update.py --noupdate    # solo usa archivos locales en data/
"""
import argparse, re, urllib.request, pathlib, datetime

ROOT = pathlib.Path(__file__).parent
SOURCES = {
    # nombre: url  (puedes añadir/quitar a gusto)
    "StevenBlack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "AdAway": "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "URLHaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "yoyo": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext&useip=0.0.0.0",
}
DOMAIN_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)", re.I)

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "centinela-threatlist/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def parse_domains(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = DOMAIN_RE.match(line)
        if m:
            d = m.group(1).lower().strip()
            # ignora localhost y broadcasthost
            if d in ("localhost", "localhost.localdomain", "local", "broadcasthost",
                     "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
                     "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"):
                continue
            out.add(d)
        # también acepta línea con solo dominio (tu lista custom)
        elif re.match(r"^[a-z0-9_.-]+\.[a-z]{2,}$", line, re.I):
            out.add(line.lower())
    return out

def load_list(path):
    p = ROOT / path
    if not p.exists():
        return set()
    return parse_domains(p.read_text(encoding="utf-8", errors="ignore"))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auto", action="store_true", help="fetch fuentes remotas")
    ap.add_argument("--noupdate", action="store_true", help="no fetchear, usa cache local")
    ap.add_argument("--ip", default="0.0.0.0", help="IP objetivo (default 0.0.0.0)")
    ap.add_argument("--output", default="hosts")
    args = ap.parse_args()

    all_domains = set()

    # 1. fuentes remotas
    if args.auto and not args.noupdate:
        for name, url in SOURCES.items():
            cache = ROOT / f"data/{name}/hosts"
            try:
                print(f"[fetch] {name} ...")
                text = fetch(url)
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(text, encoding="utf-8")
                all_domains |= parse_domains(text)
                print(f"  -> {len(parse_domains(text))} dominios")
            except Exception as e:
                print(f"  !! fallo {name}: {e}, uso cache local")
                if cache.exists():
                    all_domains |= parse_domains(cache.read_text(encoding="utf-8", errors="ignore"))
    else:
        # usa lo que haya en data/*/hosts
        for f in (ROOT / "data").rglob("hosts"):
            all_domains |= parse_domains(f.read_text(encoding="utf-8", errors="ignore"))

    # 2. lista custom local (curaduria propia: va en encabezado)
    custom_domains = load_list("data/custom/hosts")
    all_domains |= custom_domains
    print(f"[total sin filtrar] {len(all_domains)}")

    # 3. whitelist (partial match como StevenBlack)
    wl_path = ROOT / "whitelist.txt"
    whitelist = [l.strip().lower() for l in wl_path.read_text().splitlines()
                 if l.strip() and not l.strip().startswith("#")] if wl_path.exists() else []
    def whitelisted(d):
        return any(d == w or d.endswith("." + w) for w in whitelist)
    all_domains = {d for d in all_domains if not whitelisted(d)}

    # 4. blacklist (siempre entran, tambien curaduria propia)
    custom_domains |= load_list("blacklist.txt")
    all_domains |= custom_domains

    domains = sorted(all_domains)
    own = sorted(custom_domains)
    bulk = sorted(all_domains - custom_domains)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y %H:%M:%S (UTC)")

    header = f"""# Title: Centinela ThreatList - by Jesus Ruiz
#
# Feed curado de threat intelligence: phishing / OAuth-abuse / malware / tracking,
# mas agregacion de fuentes reputadas (estilo StevenBlack/hosts).
#
# Curador: Jesus Ruiz, asesor de cyberseguridad
# Date: {now}
# Number of unique domains: {len(domains):,} ({len(own)} curaduria propia + {len(bulk):,} agregados)
#
# Fetch the latest version of this file: https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/hosts
# Pi-hole Adlist version: https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/adlist.txt
# Project home page: https://github.com/contacto-jruizh/centinela-threatlist
# Inspirado en: https://github.com/StevenBlack/hosts
#
# ===============================================================

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
::1 localhost
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
0.0.0.0 0.0.0.0

# ===============================================================
# BLOQUE 1 - CURADURIA CENTINELA (Jesus Ruiz)
# Amenazas detectadas en campo: van primero para que se vean.
# ===============================================================
"""
    myhosts_path = ROOT / "myhosts"
    myhosts = myhosts_path.read_text(encoding="utf-8").strip() if myhosts_path.exists() and myhosts_path.read_text().strip() else ""
    own_body = "\n".join(f"{args.ip} {d}" for d in own)
    bulk_body = "\n".join(f"{args.ip} {d}" for d in bulk)

    out = (header
           + (myhosts + "\n\n" if myhosts else "")
           + (own_body + "\n" if own_body else "")
           + "\n# ===============================================================\n"
           + "# BLOQUE 2 - FUENTES AGREGADAS (StevenBlack + AdAway + URLHaus + yoyo)\n"
           + "# ===============================================================\n\n"
           + bulk_body + "\n")
    out_path = (ROOT / args.output).resolve()
    if ROOT.resolve() not in out_path.parents and out_path != (ROOT.resolve() / args.output):
        raise SystemExit("error: --output debe quedar dentro del repo")
    out_path.write_text(out, encoding="utf-8")
    print(f"[ok] {args.output}: {len(domains)} dominios")

    # adlist.txt formato Pi-hole (las lineas # son comentarios, Pi-hole las ignora)
    adlist_head = f"""# Title: Centinela ThreatList - by Jesus Ruiz
#
# Feed curado de threat intelligence: phishing / OAuth-abuse / malware / tracking,
# mas agregacion de fuentes reputadas (estilo StevenBlack/hosts).
#
# Curador: Jesus Ruiz, asesor de cyberseguridad
# Date: {now}
# Number of unique domains: {len(domains):,} ({len(own)} curaduria propia + {len(bulk):,} agregados)
#
# Fetch the latest version of this file: https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/adlist.txt
# Project home page: https://github.com/contacto-jruizh/centinela-threatlist
#
# ===============================================================
# BLOQUE 1 - CURADURIA CENTINELA (Jesus Ruiz)
# Amenazas detectadas en campo: van primero para que se vean.
# ===============================================================
"""
    adlist = (adlist_head
              + ("\n".join(own) + "\n" if own else "")
              + "\n# ===============================================================\n"
              + "# BLOQUE 2 - FUENTES AGREGADAS (StevenBlack + AdAway + URLHaus + yoyo)\n"
              + "# ===============================================================\n"
              + "\n".join(bulk) + "\n")
    (ROOT / "adlist.txt").write_text(adlist, encoding="utf-8")
    print(f"[ok] adlist.txt: {len(domains)} dominios (Pi-hole Adlist)")

if __name__ == "__main__":
    main()
