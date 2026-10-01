#!/usr/bin/env python3
"""Generador Centinela ThreatList - salidas separadas para control y velocidad.

Archivos generados:
  adlist.txt -> SOLO curaduria manual (Pi-hole, ligero, actualizacion inmediata)
  hosts      -> SOLO curaduria manual (formato /etc/hosts, ligero)
  dist/*.txt -> fuentes agregadas POR CATEGORIA (Pi-hole, mensual):
                ads-trackers.txt, malware.txt, phishing.txt, threat-intel.txt

Uso:
  python3 update.py --curated              # curaduria (rapido, sin red) -> adlist.txt + hosts
  python3 update.py --auto                 # fetch fuentes + dist/*.txt (por categoria)
  python3 update.py --noupdate             # usa cache local en data/ + dist/*.txt
  python3 update.py --curated --noupdate   # ambos
  python3 update.py                        # por defecto: curaduria (seguro, sin red)
"""
import argparse, re, gzip, io, zipfile, urllib.request, pathlib, datetime
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).parent
REPO = "https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main"
SOURCES = {
    # nombre: url  (puedes añadir/quitar a gusto)
    "StevenBlack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "AdAway": "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "URLHaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
    "yoyo": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext&useip=0.0.0.0",
    # --- anti-phishing (URLhaus NO cubre phishing: solo malware) ---
    "HaGeZi-TIF": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "PhishingArmy": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "BlocklistProject-phishing": "https://blocklistproject.github.io/Lists/phishing.txt",
    # --- phishing activo por URL (formato URL crudo) ---
    "OpenPhish": "https://openphish.com/feed.txt",
    "PhishTank": "https://data.phishtank.com/data/online-valid.json.gz",
}

# Fuentes sin curar manualmente: NO pueden bloquear nada del Tranco Top-1M
# (evita FP tipo absa.co.za / uvm.edu / vkontakte.ru). Si un dominio popular
# es malicioso de verdad, se anade explicitamente en blacklist.txt (gana siempre).
GUARDED = {"HaGeZi-TIF", "PhishingArmy", "BlocklistProject-phishing",
            "OpenPhish", "PhishTank"}

# Agrupacion de fuentes por categoria -> un archivo dist/<categoria>.txt.
CATEGORIES = {
    "ads-trackers": ["StevenBlack", "AdAway", "yoyo"],
    "malware": ["URLHaus"],
    "phishing": ["PhishingArmy", "BlocklistProject-phishing", "OpenPhish", "PhishTank"],
    "threat-intel": ["HaGeZi-TIF"],
}
TRANCAN_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCAN_CACHE = ROOT / "data/tranco/top-1m.csv.zip"
DOMAIN_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)", re.I)
ABP_RE = re.compile(r"^\|\|([A-Za-z0-9_.-]+\.[A-Za-z]{2,})(\^.*)?$")

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "centinela-threatlist/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    # PhishTank sirve .gz
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
    return raw.decode("utf-8", errors="ignore")

def load_tranco(allow_fetch=True):
    """Tranco Top-1M como set de dominios. Devuelve None si no hay guard
    disponible (sin red y sin cache): el caller debe abortar para no publicar
    fuentes sin curar sin proteccion anti-FP."""
    raw = None
    if allow_fetch:
        try:
            print("[fetch] Tranco Top-1M (guard anti-FP) ...")
            req = urllib.request.Request(TRANCAN_URL,
                                         headers={"User-Agent": "centinela-threatlist/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
            TRANCAN_CACHE.parent.mkdir(parents=True, exist_ok=True)
            TRANCAN_CACHE.write_bytes(raw)
        except Exception as e:
            print(f"  !! fallo Tranco remoto: {e}")
    if raw is None and TRANCAN_CACHE.exists():
        raw = TRANCAN_CACHE.read_bytes()
        print("[guard] Tranco: usando cache local")
    if raw is None:
        return None
    try:
        out = set()
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            with z.open(z.namelist()[0]) as fh:
                for line in io.TextIOWrapper(fh, encoding="utf-8", errors="ignore"):
                    _, _, dom = line.partition(",")
                    dom = dom.strip().lower()
                    if dom:
                        out.add(dom)
        return out
    except Exception as e:
        print(f"  !! cache Tranco ilegible: {e}")
        return None

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
        # formato Adblock Plus (HaGeZi TIF): ||dominio^
        elif ABP_RE.match(line):
            out.add(ABP_RE.match(line).group(1).lower())
        # también acepta línea con solo dominio (tu lista custom)
        elif re.match(r"^[a-z0-9_.-]+\.[a-z]{2,}$", line, re.I):
            out.add(line.lower())
        # formato URL crudo (OpenPhish)
        elif re.match(r"^https?://", line, re.I):
            h = urlparse(line).hostname
            if h:
                out.add(h.lower())
        # formato JSON PhishTank (array en 1 línea, slashes escapados "https:\/\/")
        elif line[0] in "{[" and '"url"' in line:
            for m2 in re.finditer(r'"url"\s*:\s*"((?:https?:)?(?:\\?/){2}[^"]+)"', line):
                u = m2.group(1).replace("\\/", "/")
                h = urlparse(u).hostname
                if h:
                    out.add(h.lower())
    return out

def load_list(path):
    p = ROOT / path
    if not p.exists():
        return set()
    return parse_domains(p.read_text(encoding="utf-8", errors="ignore"))

def load_whitelist():
    wl_path = ROOT / "whitelist.txt"
    if not wl_path.exists():
        return []
    return [l.strip().lower() for l in wl_path.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")]

def collect_by_source(args):
    """Ingesta cada fuente (con guard Tranco en las no curadas).
    Devuelve dict: nombre_fuente -> set(dominios)."""
    by_source = {}

    guard = load_tranco(allow_fetch=bool(args.auto and not args.noupdate))
    if guard is None:
        raise SystemExit(
            "error: guard Tranco Top-1M no disponible (sin red y sin cache "
            f"{TRANCAN_CACHE.relative_to(ROOT)}). Aborto: publicar las "
            "fuentes sin curar sin guard puede meter FP (bancos, univ, "
            "RRSS). Ejecuta con conexion una vez para poblar la cache.")
    print(f"[guard] Tranco Top-1M: {len(guard):,} dominios populares protegidos")

    def ingest(name, text):
        doms = parse_domains(text)
        if name in GUARDED:
            before = len(doms)
            doms -= guard
            print(f"  -> {name}: {before:,} dominios; guard descarta "
                  f"{before - len(doms):,} populares; {len(doms):,} retenidos")
        else:
            print(f"  -> {name}: {len(doms):,} dominios")
        by_source.setdefault(name, set()).update(doms)

    # 1. fuentes remotas
    if args.auto and not args.noupdate:
        for name, url in SOURCES.items():
            cache = ROOT / f"data/{name}/hosts"
            try:
                print(f"[fetch] {name} ...")
                text = fetch(url)
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(text, encoding="utf-8")
                ingest(name, text)
            except Exception as e:
                print(f"  !! fallo {name}: {e}, uso cache local")
                if cache.exists():
                    ingest(name, cache.read_text(encoding="utf-8", errors="ignore"))
    else:
        # usa lo que haya en data/*/hosts (el nombre del dir identifica la fuente)
        for f in (ROOT / "data").rglob("hosts"):
            if f.parent.name == "custom":
                continue  # curaduria propia va aparte, sin guard
            ingest(f.parent.name, f.read_text(encoding="utf-8", errors="ignore"))

    return by_source

def write_curated(own, args, now):
    """adlist.txt (Pi-hole) + hosts (/etc/hosts): SOLO curaduria."""
    adlist_head = f"""# Title: Centinela ThreatList - curaduria manual (by Jesus Ruiz)
#
# SOLO curaduria propia (amenazas detectadas en campo). Ligero y de
# actualizacion inmediata. Fuentes agregadas por categoria en la rama `bulk`.
#
# Curador: Jesus Ruiz, asesor de cyberseguridad
# Date: {now}
# Dominios curados: {len(own)}
#
# Este archivo (Pi-hole Adlist): {REPO}/adlist.txt
# Agregado por categoria:        {REPO}/bulk/<categoria>.txt
# Project home page: https://github.com/contacto-jruizh/centinela-threatlist
#
# ===============================================================
# BLOQUE 1 - CURADURIA CENTINELA (Jesus Ruiz)
# Amenazas detectadas en campo
# ===============================================================
"""
    adlist = adlist_head + ("\n".join(f"0.0.0.0 {d}" for d in own) + "\n" if own else "")
    (ROOT / "adlist.txt").write_text(adlist, encoding="utf-8")
    print(f"[ok] adlist.txt: {len(own)} dominios (curaduria)")

    hosts_head = f"""# Title: Centinela ThreatList - curaduria manual (by Jesus Ruiz)
#
# Formato /etc/hosts. SOLO curaduria propia; el agregado va por categoria.
#
# Curador: Jesus Ruiz, asesor de cyberseguridad
# Date: {now}
# Dominios curados: {len(own)}
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
# Amenazas detectadas en campo
# ===============================================================
"""
    myhosts_path = ROOT / "myhosts"
    myhosts = myhosts_path.read_text(encoding="utf-8").strip() if myhosts_path.exists() and myhosts_path.read_text().strip() else ""
    own_body = "\n".join(f"{args.ip} {d}" for d in own)
    out = hosts_head + (myhosts + "\n\n" if myhosts else "") + (own_body + "\n" if own_body else "")
    out_path = (ROOT / args.output).resolve()
    if ROOT.resolve() not in out_path.parents and out_path != (ROOT.resolve() / args.output):
        raise SystemExit("error: --output debe quedar dentro del repo")
    out_path.write_text(out, encoding="utf-8")
    print(f"[ok] {args.output}: {len(own)} dominios (curaduria)")

def write_categories(by_source, custom_domains, now):
    """Un archivo por categoria en dist/ (Pi-hole), con whitelist y sin curaduria."""
    wl = load_whitelist()
    def whitelisted(d):
        return any(d == w or d.endswith("." + w) for w in wl)

    outdir = ROOT / "dist"
    outdir.mkdir(exist_ok=True)
    for cat, sources in CATEGORIES.items():
        doms = set()
        for s in sources:
            doms |= by_source.get(s, set())
        doms = {d for d in doms if not whitelisted(d)} - custom_domains
        head = f"""# Title: Centinela ThreatList - categoria: {cat}
#
# Fuentes: {", ".join(sources)}
# Guard anti-FP: Tranco Top-1M en las fuentes no curadas. Sin curaduria manual.
#
# Curador: Jesus Ruiz, asesor de cyberseguridad
# Date: {now}
# Dominios en esta categoria: {len(doms):,}
#
# Pi-hole Adlist (categoria {cat}): {REPO}/bulk/{cat}.txt
# Curaduria manual (ligero):        {REPO}/adlist.txt
# Project home page: https://github.com/contacto-jruizh/centinela-threatlist
#
# ===============================================================
"""
        body = "\n".join(f"0.0.0.0 {d}" for d in sorted(doms))
        (outdir / f"{cat}.txt").write_text(head + body + "\n", encoding="utf-8")
        print(f"[ok] dist/{cat}.txt: {len(doms):,} dominios")

def main():
    ap = argparse.ArgumentParser(description="Centinela ThreatList generator")
    ap.add_argument("--auto", action="store_true", help="fetch fuentes remotas y genera dist/*.txt (por categoria)")
    ap.add_argument("--noupdate", action="store_true", help="usa cache local data/ y genera dist/*.txt (por categoria)")
    ap.add_argument("--curated", action="store_true", help="solo curaduria (rapido, sin red): adlist.txt + hosts")
    ap.add_argument("--ip", default="0.0.0.0", help="IP objetivo (default 0.0.0.0)")
    ap.add_argument("--output", default="hosts", help="nombre del hosts curado (default hosts)")
    args = ap.parse_args()

    do_bulk = bool(args.auto or args.noupdate)
    do_curated = bool(args.curated) or not do_bulk  # por defecto: curaduria (seguro, sin red)

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y %H:%M:%S (UTC)")

    # curaduria propia (siempre barata): lista custom + blacklist (gana siempre)
    custom_domains = load_list("data/custom/hosts") | load_list("blacklist.txt")
    own = sorted(custom_domains)

    if do_curated:
        write_curated(own, args, now)
    if do_bulk:
        by_source = collect_by_source(args)
        write_categories(by_source, custom_domains, now)

if __name__ == "__main__":
    main()
