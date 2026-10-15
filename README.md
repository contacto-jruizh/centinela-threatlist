# Centinela ThreatList — feed de asesor en cyberseguridad para Pi-hole

Listas separadas para **control** y **velocidad**:

| Archivo | Contenido | Tamaño | Cadencia |
|---|---|---|---|
| `adlist.txt` | **Solo curaduría manual** (Pi-hole) | ~KB | inmediata |
| `hosts` | **Solo curaduría manual** (`/etc/hosts`) | ~KB | inmediata |
| `ai-block.txt` | Bloqueo de IA y sus APIs (Pi-hole Adlist) | ~KB | inmediata |
| `ai-allow.txt` | Whitelist de IA permitidas (Pi-hole Allowlist) | ~KB | inmediata |
| `unifi/ai-block.txt` (+`-inline`) | IA a bloquear, formato UniFi | ~KB | inmediata |
| `unifi/ai-allow.txt` (+`-inline`) | IA permitidas (Claude + Copilot), formato UniFi | ~KB | inmediata |
| `streaming-block.txt` | Bloqueo de streaming (Pi-hole Adlist) | ~KB | inmediata |
| `streaming-allow.txt` | Whitelist de streaming (vacía por defecto) | ~KB | inmediata |
| `unifi/streaming-block.txt` (+`-inline`) | Streaming a bloquear, formato UniFi | ~KB | inmediata |
| `unifi/streaming-allow.txt` (+`-inline`) | Streaming permitido, formato UniFi | ~KB | inmediata |
| `bulk/ads-trackers.txt` | Agregado: ads/trackers | ~2 MB | mensual |
| `bulk/malware.txt` | Agregado: malware (URLHaus) | ~10 KB | mensual |
| `bulk/phishing.txt` | Agregado: phishing | ~10 MB | mensual |
| `bulk/threat-intel.txt` | Agregado: threat intel (HaGeZi pro) | ~6 MB | mensual |

Fuentes curadas: `data/custom/hosts` + `blacklist.txt`.
Listas de IA: `data/custom/ai-hosts` (bloqueo) y `ai-allow.txt` (permitir).
Listas de streaming: `data/custom/streaming-hosts` (bloqueo) y `streaming-allow.txt`.
Fuentes agregadas por categoría (carpeta `bulk/`), con guard anti-FP contra Tranco Top-1M.

## Agregar un dominio (rápido, sin red)

```bash
echo "malicioso.ejemplo.com" >> data/custom/hosts
python3 update.py --curated      # regenera adlist.txt + hosts + *-block.txt + unifi/ en segundos
```

## Bloquear IA y permitir solo las que quieras

Dos listas complementarias:

| Lista | Archivo | Rol en Pi-hole |
|---|---|---|
| Bloqueo IA + APIs | `ai-block.txt` | **Adlist** (bloquea) |
| IA permitidas | `ai-allow.txt` | **Allowlist** (permite) |

- `ai-block.txt` bloquea proveedores de IA y sus endpoints/APIs (OpenAI/ChatGPT,
  Gemini, Perplexity, xAI/Grok, Mistral, Cohere, DeepSeek, Zhipu/z.ai, etc.).
  Se genera desde `data/custom/ai-hosts`. **Claude y Microsoft Copilot no se
  bloquean** (van en `ai-allow.txt`).
- `ai-allow.txt` **permite** dominios que de otro modo se bloquearían. De fábrica
  lleva **Claude / Anthropic** (web + API) y **todo Microsoft Copilot**
  (`copilot.microsoft.com`, `copilot.cloud.microsoft`, `m365.cloud.microsoft`,
  `copilot.com`, `m365copilot.com`, `cloud.microsoft`, Copilot en Edge…). El
  Allowlist de Pi-hole gana SIEMPRE al bloqueo, así que aunque un dominio esté
  en las dos listas, se permite.

Para bloquear otra IA: añade su dominio (y subdominios de API) a `data/custom/ai-hosts`.
Para permitir otra IA: añade su dominio a `ai-allow.txt`.

> **DNS no distingue pago de gratis.** `claude.ai` es el mismo dominio para el
> plan gratis y el de pago; Pi-hole no sabe tu suscripción. Permitir el dominio
> habilita tu Claude de pago (web) y la API; no existe una regla DNS que deje
> pasar "solo el plan de pago".

En Pi-hole v6, `ai-allow.txt` se añade como **Allowlist** (lista suscrita tipo
antilist). En v5 o si prefieres manual, pega los dominios en **Domains → Allowlist**.

## Bloquear streaming

Misma mecánica que las IA: una fuente de bloqueo y una allowlist opcional.

| Lista | Archivo | Rol |
|---|---|---|
| Bloqueo streaming | `streaming-block.txt` | **Adlist** (bloquea) |
| Streaming permitido | `streaming-allow.txt` | **Allowlist** (permite; vacía por defecto) |

- `streaming-block.txt` bloquea Netflix, YouTube (+`googlevideo.com`), Prime
  Video, Disney+, Hulu, Max/HBO, Roku, Peacock, Paramount+, Twitch, Spotify,
  Deezer, Tidal, Bilibili, Crunchyroll, operadores de TV, etc. Se genera desde
  `data/custom/streaming-hosts`.
- `streaming-allow.txt` está **vacía** por defecto (se bloquea todo). Para dejar
  pasar algo, añade el dominio (y sus CDNs) y Pi-hole/UniFi lo permitirá aunque
  siga en la lista de bloqueo.
- No se bloquean dominios raíz compartidos (`amazon.com`, `google.com`,
  `apple.com`, `microsoft.com`) para no romper compras u otros servicios; se
  usan subdominios y CDNs específicos.

Para bloquear otro servicio: añade su dominio y CDNs a `data/custom/streaming-hosts`.

URLs de Pi-hole:
- Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-block.txt`
- Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-allow.txt`

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

   **IA (opcional):**
   - Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/ai-block.txt`
   - Allowlist (permitir Claude/Copilot): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/ai-allow.txt`

   **Streaming (opcional):**
   - Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-block.txt`
   - Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-allow.txt`
3. Tools → Update Gravity.
4. Verifica: `pihole -q nidir.info` debe dar match.

> Empieza con `adlist.txt` + las categorías que te interesen. `threat-intel.txt`
> (HaGeZi pro, ~6 MB) es la más pesada; puedes omitirla y aún cubres
> phishing/malware/ads con las otras tres.

> Para IA: añade `ai-block.txt` como **Adlist** y `ai-allow.txt` como **Allowlist**.
> Si Pi-hole v6 no tiene Allowlist por URL, pega los dominios de `ai-allow.txt`
> manualmente en **Domains → Allowlist**.

Bloqueo extra recomendado en Pi-hole → Domains → Regex:
```
\.nidir\.info$
```
Esto cubre subdominios del atacante.

## Usar en UniFi

UniFi (Firewall / Content Filter) acepta dominios **uno por línea** o **todos en
una sola línea separados por `;`**. La carpeta `unifi/` trae las mismas listas de
IA en ese formato (sin IP, sin comentarios):

| Archivo | Formato | Uso |
|---|---|---|
| `unifi/ai-block.txt` | un dominio por línea | pegar en la lista **Block** |
| `unifi/ai-block-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/ai-allow.txt` | un dominio por línea | pegar en la lista **Allow** |
| `unifi/ai-allow-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/streaming-block.txt` | un dominio por línea | pegar en la lista **Block** |
| `unifi/streaming-block-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/streaming-allow.txt` | un dominio por línea | pegar en la lista **Allow** |
| `unifi/streaming-allow-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |

Ejemplo (formato inline):
```
example.com;example.net
```

- **Bloquear IA:** `unifi/ai-block.txt` (o el `-inline`). Incluye
  `gemini.google.com`, `chatgpt.com`, `api.openai.com`, `chat.deepseek.com`, etc.
- **Permitir IA (Claude + Microsoft Copilot):** `unifi/ai-allow.txt` (o el
  `-inline`). El allow de UniFi tiene prioridad; sirve para que Claude y Copilot
  no se bloqueen aunque estén en una regla amplia.

URLs para copiar (todas publicadas):
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/ai-block.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/ai-block-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/ai-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/ai-allow-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/streaming-block.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/streaming-block-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/streaming-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/streaming-allow-inline.txt`

> Si tu versión de UniFi solo tiene un campo de texto, usa los `*-inline.txt`
> (una sola línea con `;`); si admite pegar varias líneas, usa los normales.
> Para añadir otra IA, edita `data/custom/ai-hosts` (bloqueo) o `ai-allow.txt`
> (permitir) y vuelve a correr `python3 update.py --curated`.

## Comandos

```bash
python3 update.py --curated               # curaduría (rápido, sin red) -> adlist.txt + hosts + *-block.txt + unifi/
python3 update.py --noupdate              # agregado desde caché local -> bulk/*.txt
python3 update.py --auto                  # fetch fuentes remotas -> bulk/*.txt
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
