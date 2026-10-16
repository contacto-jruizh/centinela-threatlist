# brandwatch - protección de marca (typosquatting / phishing)

Herramientas para rastrear dominios clonados de una marca (por defecto **Xuper TV**).
**No auto-bloquea**: genera candidatos para revisión humana; los confirmados se
pasan a `data/custom/malware-hosts` (lista TV Box) y se publican con
`python3 update.py --curated`.

## Componentes
- `seeds.txt` — dominios semilla de la marca (una por línea).
- `watch.py` — orquesta `dnstwist`, centraliza en `ledger.sqlite` y emite
  candidatos (`--report`).
- `external.yaml` — keywords para `phishing_catcher` (Certstream, tiempo real).
- `.github/workflows/brandwatch.yml` — Action programada que abre un issue con
  los candidatos para revisión.

## Uso local
```bash
pip install dnstwist
python3 watch.py              # enumera seeds.txt -> ledger.sqlite
python3 watch.py --report     # imprime candidatos (Markdown)
```

## Certstream (tiempo real)
```bash
git clone https://github.com/x0rz/phishing_catcher && cd phishing_catcher
pip install -r requirements.txt
cp ../scripts/brandwatch/external.yaml external.yaml
./catch_phishing.py
```

## cron (Debian)
```cron
30 3 * * * cd /opt/brandwatch && /usr/bin/python3 watch.py >> out/cron.log 2>&1
```

## Flujo
candidatos (`--report` / issue) → revisión → `data/custom/malware-hosts` →
`python3 update.py --curated` → `malware-block.txt` + `unifi/malware-block.txt`.

> Alcance: usar solo sobre marcas propias/autorizadas. dnstwist lanza muchas
> consultas DNS; limitar `--threads`/`--nameservers`.
