# Centinela ThreatList — feed de asesor en cyberseguridad para Pi-hole

Listas separadas para **control** y **velocidad**:

| Archivo | Contenido | Tamaño | Cadencia |
|---|---|---|---|
| `adlist.txt` | **Solo curaduría manual** (Pi-hole) | ~KB | inmediata |
| `hosts` | **Solo curaduría manual** (`/etc/hosts`) | ~KB | inmediata |
| `bulk/ads-trackers.txt` | Agregado: ads/trackers | ~2 MB | mensual |
| `bulk/malware.txt` | Agregado: malware (URLHaus) | ~10 KB | mensual |
| `bulk/phishing.txt` | Agregado: phishing | ~10 MB | mensual |
| `bulk/threat-intel.txt` | Agregado: threat intel (HaGeZi pro) | ~6 MB | mensual |

Fuentes curadas: `data/custom/hosts` + `blacklist.txt`.
Fuentes agregadas por categoría (carpeta `bulk/`), con guard anti-FP contra Tranco Top-1M.

## Agregar un dominio (rápido, sin red)

```bash
echo "malicioso.ejemplo.com" >> data/custom/hosts
python3 update.py --curated      # regenera adlist.txt + hosts en segundos
```

## Usar en Pi-hole

1. Sube este repo a GitHub como `centinela-threatlist`.
2. Pi-hole Admin → Group Management → Adlists → Add:

   **Requerida (curaduría, ligera):**
   `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/adlist.txt`

   **Opcionales por categoría (elige las que quieras):**
   `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/bulk/ads-trackers.txt`
   `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/bulk/malware.txt`
   `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/bulk/phishing.txt`
   `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/bulk/threat-intel.txt`
3. Tools → Update Gravity.
4. Verifica: `pihole -q nidir.info` debe dar match.

> Empieza con `adlist.txt` + las categorías que te interesen. `threat-intel.txt`
> (HaGeZi pro, ~6 MB) es la más pesada; puedes omitirla y aún cubres
> phishing/malware/ads con las otras tres.

Bloqueo extra recomendado en Pi-hole → Domains → Regex:
```
\.nidir\.info$
```
Esto cubre subdominios del atacante.

## Comandos

```bash
python3 update.py --curated               # curaduría (rápido, sin red) -> adlist.txt + hosts
python3 update.py --noupdate              # agregado desde caché local -> dist/*.txt
python3 update.py --auto                  # fetch fuentes remotas -> dist/*.txt
python3 update.py --curated --noupdate    # ambos
```


## Manual de uso

### 1. Validar un dominio desde cualquier equipo (DNS directo al Pi-hole)

Apunta el `dig` a la IP de tu Pi-hole (sustituye `<IP_DEL_PIHOLE>`):

```bash
dig @<IP_DEL_PIHOLE> nidir.info
```

Resultado esperado si esta en la lista:

```
;; ANSWER SECTION:
nidir.info.    0    IN    A    0.0.0.0
```

Si devuelve la IP real del atacante, el dominio NO esta bloqueado.

Para ver solo la respuesta, mas legible:

```bash
dig +short @<IP_DEL_PIHOLE> nidir.info
# 0.0.0.0   <- bloqueado
# 104.21.x.x  <- NO bloqueado
```

### 2. Validar desde el propio Pi-hole (SSH)

```bash
ssh tu_usuario@pihole
```

Una vez dentro, consulta si el dominio esta en gravity:

```bash
pihole -q nidir.info
```

Interpretacion de la salida:

| Salida | Significado |
|--------|-------------|
| `Exact match found in adlist` | Bloqueado por una de tus adlists (incluida Centinela) |
| `Match found in ...` | Bloqueado, muestra la fuente |
| `No exact matches found` | NO esta bloqueado |

Otros casos utiles:

```bash
pihole -q nidir.info                # IoC de campo
pihole -q -adlist https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/adlist.txt
                                   # cuenta cuantos dominios de ESA adlist intersectan con gravity
```

### 3. Forzar la actualizacion de gravity (tras anyadir la adlist)

```bash
pihole -g
```

### 4. Probar en tiempo real sin esperar a gravity

```bash
dig +short @<IP_DEL_PIHOLE> nidir.info
```

Si despues de `pihole -g` sigue devolviendo IP real, revisa en Admin →
Group Management → Adlists que la URL apunte a `main/adlist.txt` y que el
estado sea "valid".
