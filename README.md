# Centinela ThreatList — feed de asesor en cyberseguridad para Pi-hole

Fuentes iniciales: `data/custom/hosts` + `blacklist.txt`.
Genera `hosts` (formato 0.0.0.0) y `adlist.txt` (1 dominio/línea, para Pi-hole).

## Agregar un dominio

```bash
echo "malicioso.ejemplo.com" >> data/custom/hosts
python3 update.py --noupdate
```

## Usar en Pi-hole

1. Sube este repo a GitHub como `centinela-threatlist`.
2. Pi-hole Admin → Group Management → Adlists → Add:
   `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/adlist.txt`
3. Tools → Update Gravity.
4. Verifica: `pihole -q nidir.info` debe dar match.

Bloqueo extra recomendado en Pi-hole → Domains → Regex:
```
\.nidir\.info$
biograft\.my\.canva\.site$
```
Esto cubre subdominios del atacante.

## Comandos

```bash
python3 update.py --noupdate  # solo local, rápido
python3 update.py --auto      # trae StevenBlack + AdAway + URLHaus + yoyo y regenera
```
