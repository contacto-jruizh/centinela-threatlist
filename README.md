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
| `streaming-allow.txt` | Whitelist de streaming (Spotify permitido) | ~KB | inmediata |
| `unifi/streaming-block.txt` (+`-inline`) | Streaming a bloquear, formato UniFi | ~KB | inmediata |
| `unifi/streaming-allow.txt` (+`-inline`) | Streaming permitido, formato UniFi | ~KB | inmediata |
| `social-block.txt` | Bloqueo de redes sociales (Pi-hole Adlist) | ~KB | inmediata |
| `social-allow.txt` | Whitelist social (WhatsApp/LinkedIn/Telegram) | ~KB | inmediata |
| `unifi/social-block.txt` (+`-inline`) | Redes sociales a bloquear, formato UniFi | ~KB | inmediata |
| `unifi/social-allow.txt` (+`-inline`) | Redes permitidas, formato UniFi | ~KB | inmediata |
| `vpn-block.txt` | Bloqueo VPN/anonimizadores/botnets (Pi-hole Adlist) | ~KB | inmediata |
| `vpn-allow.txt` | VPN permitidas (vacía por ahora) | ~KB | inmediata |
| `unifi/vpn-block.txt` (+`-inline`) | VPN a bloquear, formato UniFi | ~KB | inmediata |
| `unifi/vpn-allow.txt` (+`-inline`) | VPN permitidas, formato UniFi | ~KB | inmediata |
| `microsoft-allow.txt` / `apple-allow.txt` / `whatsapp-allow.txt` | Allowlists por fabricante (también `unifi/`) | ~KB | inmediata |
| `bulk/ads-trackers.txt` | Agregado: ads/trackers | ~2 MB | mensual |
| `bulk/malware.txt` | Agregado: malware (URLHaus) | ~10 KB | mensual |
| `bulk/phishing.txt` | Agregado: phishing | ~10 MB | mensual |
| `bulk/threat-intel.txt` | Agregado: threat intel (HaGeZi pro) | ~6 MB | mensual |

Fuentes curadas: `data/custom/hosts` + `blacklist.txt`.
Listas de IA: `data/custom/ai-hosts` (bloqueo) y `ai-allow.txt` (permitir).
Listas de streaming: `data/custom/streaming-hosts` (bloqueo) y `streaming-allow.txt`.
Fuentes agregadas por categoría (carpeta `bulk/`), con guard anti-FP contra Tranco Top-1M.

## Nunca bloquear (regla fija)

**WhatsApp, LinkedIn, Telegram, Spotify, Claude, Apple, Microsoft, YouTube y
Adobe NUNCA se bloquean.** Cada uno vive en su propia allowlist (un dominio =
una sola lista), y el generador aplica `whitelist.txt` **+ todas** las
`*-allow.txt` a las listas `bulk/`, así que ningún feed puede bloquearlos:

| Uso | Lista | Dominios |
|---|---|---|
| WhatsApp web/app/media + API | `whatsapp-allow.txt` | `whatsapp.com`, `whatsapp.net`, `wa.me`, `graph.facebook.com`… |
| LinkedIn / Telegram | `social-allow.txt` | `linkedin.com`, `lnkd.in`, `licdn.com`, `telegram.org`, `t.me`… |
| Spotify (música) | `streaming-allow.txt` | `spotify.com`, `spotifycdn.com`, `scdn.co`… |
| Claude / Anthropic | `ai-allow.txt` | `claude.ai`, `claude.com`, `api.anthropic.com`… |
| Apple (sin Apple TV) | `apple-allow.txt` | `icloud.com`, `apps.apple.com`, `partiality.itunes.apple.com`… |
| Microsoft (sin juegos) | `microsoft-allow.txt` | Office/M365, Outlook, Teams, OneDrive… |
| YouTube | `youtube-allow.txt` | `youtube.com`, `googlevideo.com`… |
| Globales | `whitelist.txt` | `google.com`, `translate.google.com`, `rae.es`, `adobe.com` |

> Regla: **un dominio = una sola lista** (UniFi/Pi-hole exigen únicos).
> `verify_allow_disjoint()` aborta si un dominio se repite entre allowlists.

> Dominios requeridos por Claude / Claude Code:
> https://code.claude.com/docs/en/network-config

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
| Streaming permitido | `streaming-allow.txt` | **Allowlist** (permite; Spotify) |

- `streaming-block.txt` bloquea:
  - **Video**: Netflix, Prime Video, Disney+, Hulu, Max/HBO, Roku, Peacock,
    Paramount+, Twitch, Vimeo, Dailymotion, etc. (**YouTube no se bloquea**;
    está en `youtube-allow.txt`).
  - **Deportes**: oficiales (ESPN+, DAZN, Fubo, NBA/NFL/MLB/NHL, UFC, F1 TV…) y
    agregadores pirata (Streameast, Crackstreams, Buffstreams, VIPBox, Methstreams,
    Sportsurge, Rojadirecta, Footybite…).
  - **Películas/series pirata**: 123Movies, Fmovies, Putlocker, Soap2Day,
    YesMovies, SolarMovie, MyFlixer, HDToday, etc.
  - **Anime**: 9anime, GoGoAnime, AnimePahe, HiAnime, WCOfun…
  - **Torrents**: The Pirate Bay, 1337x, YTS, Nyaa, EZTV, TorrentGalaxy…
  - **Música/TV/regionales**: Deezer, Tidal, Bilibili, Crunchyroll, Sky, BBC, etc.
  Se genera desde `data/custom/streaming-hosts`. **Spotify y WhatsApp no se
  bloquean** (excluidos). Los dominios pirata rotan, así que conviene mantenerlos.
- `streaming-allow.txt` **excluye** dominios del bloqueo. De fábrica lleva
  Spotify; añade aquí lo que quieras permitir (y sus CDNs) y Pi-hole/UniFi lo
  dejará pasar aunque siga en `streaming-hosts`.
- No se bloquean dominios raíz compartidos (`amazon.com`, `google.com`,
  `apple.com`, `microsoft.com`) para no romper compras u otros servicios; se
  usan subdominios y CDNs específicos.

Para bloquear otro servicio: añade su dominio y CDNs a `data/custom/streaming-hosts`.

URLs de Pi-hole:
- Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-block.txt`
- Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-allow.txt`

## Bloquear redes sociales

| Lista | Archivo | Rol |
|---|---|---|
| Bloqueo redes sociales | `social-block.txt` | **Adlist** (bloquea) |
| Redes permitidas | `social-allow.txt` | **Allowlist** (permite) |

- `social-block.txt` bloquea Facebook (+ Messenger/Threads), Instagram, TikTok,
  X/Twitter, Reddit, Snapchat, WeChat, Douyin, Kuaishou, Pinterest, Tumblr, VK,
  Bluesky, Discord, Line, Viber… Se genera desde `data/custom/social-hosts`.
- `social-allow.txt` **excluye** WhatsApp, LinkedIn y Telegram (regla fija).
  Se permiten aunque estén en una regla amplia.
- **YouTube no está aquí**: ya está en la lista de streaming. Tampoco se bloquea
  `graph.facebook.com` (es la API de WhatsApp Business/Cloud).

URLs de Pi-hole:
- Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/social-block.txt`
- Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/social-allow.txt`

URLs de UniFi (formato UniFi; también `-inline.txt` con `;`):
- Blacklist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-blacklist.txt`
- Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-allow.txt`

## Bloquear VPN / anonimizadores (botnet_anonimizadores)

| Lista | Archivo | Rol |
|---|---|---|
| Bloqueo VPN/anonimizadores | `vpn-block.txt` | **Adlist** (bloquea) |
| VPN permitidas | `vpn-allow.txt` | **Allowlist** (vacía por ahora) |

- `vpn-block.txt` bloquea VPN, anonimizadores, proxies y botnets. Incluye los
  IoCs observados de **Urban VPN** (`urban-vpn.com` y sus subdominios
  `authentication`, `config-toolbar`, `analytics-toolbar`,
  `anti-phishing-protection-toolbar`, `anti-phishing-protection`) más Hola,
  Hotspot Shield, Psiphon, Tor, NordVPN, ExpressVPN, etc.
- `vpn-allow.txt` está **vacía**: por ahora no hay VPN permitidas. Para permitir
  una, agrega su dominio (y servidores/CDNs) y tendrá prioridad sobre el bloqueo.

URLs de Pi-hole:
- Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/vpn-block.txt`
- Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/vpn-allow.txt`

URLs de UniFi (formato UniFi; también `-inline.txt` con `;`):
- Blacklist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-block.txt`
- Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-allow.txt`

## Allowlists por fabricante (Microsoft / Apple / WhatsApp)

Listas de **solo permitidos** para subir a UniFi (o Pi-hole), sin bloqueo asociado:

| Fabricante | Contenido | Excluye |
|---|---|---|
| Microsoft | M365/Office (login, Office, Outlook, Teams, SharePoint, OneDrive, Graph, Copilot) | **juegos/Xbox** (xbox.com, xboxlive.com, minecraft.net…) |
| Apple | iCloud, App Store/iTunes, push, updates, cuenta | **Apple TV** (`tv.apple.com`) |
| WhatsApp | web/app, media (`*.whatsapp.net`), API (Graph) | — |
| YouTube | web, music, TV, CDN (`googlevideo.com`) | — |

URLs UniFi (formato UniFi; también `-inline.txt` con `;`):
- Microsoft: `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/microsoft-allow.txt`
- Apple: `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/apple-allow.txt`
- WhatsApp: `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/whatsapp-allow.txt`
- YouTube: `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/youtube-allow.txt`

URLs Pi-hole (Allowlist):
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/microsoft-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/apple-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/whatsapp-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/youtube-allow.txt`

> Editar fuentes: `data/custom/microsoft-allow`, `data/custom/apple-allow`,
> `data/custom/whatsapp-allow` (un dominio por línea) y correr `update.py --curated`.

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

   **Redes sociales (opcional):**
   - Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/social-block.txt`
   - Allowlist (permitir WhatsApp/LinkedIn/Telegram): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/social-allow.txt`

   **VPN / anonimizadores (opcional):**
   - Adlist (bloqueo): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/vpn-block.txt`
   - Allowlist (permitir): `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/vpn-allow.txt`
3. Tools → Update Gravity.
4. Verifica: `pihole -q nidir.info` debe dar match.

> Empieza con `adlist.txt` + las categorías que te interesen. `threat-intel.txt`
> (HaGeZi pro, ~6 MB) es la más pesada; puedes omitirla y aún cubres
> phishing/malware/ads con las otras tres.

> Para IA: añade `ai-block.txt` como **Adlist** y `ai-allow.txt` como **Allowlist**.
> Si Pi-hole v6 no tiene Allowlist por URL, pega los dominios de `ai-allow.txt`
> manualmente en **Domains → Allowlist**.

## Whitelist en Pi-hole (permitir siempre) — proceso inverso

Para **permitir siempre** un dominio (no el proceso de bloquear, sino el
contrario), Pi-hole usa el **Allowlist / Antilist**:

1. Elige el archivo según el tipo de servicio (un dominio = **una sola** lista):
   - Global / nunca bloquear (aplica a las `bulk/`): `whitelist.txt`.
   - Por categoría: `ai-allow.txt`, `streaming-allow.txt`, `social-allow.txt`, `vpn-allow.txt`.
   - Por fabricante: `microsoft-allow.txt`, `apple-allow.txt`, `whatsapp-allow.txt`
     (fuentes en `data/custom/`).
2. Añade el dominio (uno por línea) y regenera:
   ```bash
   python3 update.py --curated     # ai/streaming/social/vpn + fabricante
   python3 update.py --noupdate    # solo si tocaste whitelist.txt (afecta bulk/)
   ```
3. En Pi-hole v6, súbelo como **Allowlist** (lista suscrita), o pega los dominios
   en **Domains → Allowlist**. Luego Tools → Update Gravity (`pihole -g`).

URLs de Allowlist (Pi-hole):
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/whitelist.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/ai-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/streaming-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/social-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/vpn-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/microsoft-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/apple-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/whatsapp-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/youtube-allow.txt`

> Regla: **un dominio = una sola lista** (UniFi/Pi-hole exigen únicos).
> `verify_allow_disjoint()` aborta si un dominio aparece en dos listas de allow.

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
| `unifi/social-block.txt` | un dominio por línea | pegar en la lista **Block** |
| `unifi/social-block-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/social-allow.txt` | un dominio por línea | pegar en la lista **Allow** |
| `unifi/social-allow-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/social-blacklist.txt` | `0.0.0.0 dominio` (una por línea) | **blacklist** social (hosts) |
| `unifi/social-blacklist-inline.txt` | dominios separados por `;` (sin IP) | pegar en el campo de dominio |
| `unifi/vpn-block.txt` | un dominio por línea | pegar en la lista **Block** |
| `unifi/vpn-block-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/vpn-allow.txt` | un dominio por línea | pegar en la lista **Allow** |
| `unifi/vpn-allow-inline.txt` | una línea separada por `;` | pegar en el campo de dominio |
| `unifi/vpn-blacklist.txt` | `0.0.0.0 dominio` (una por línea) | **blacklist** VPN (hosts) |
| `unifi/vpn-blacklist-inline.txt` | dominios separados por `;` (sin IP) | pegar en el campo de dominio |

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
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-block.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-block-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-allow-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-blacklist.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/social-blacklist-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-block.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-block-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-allow.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-allow-inline.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-blacklist.txt`
- `https://raw.githubusercontent.com/contacto-jruizh/centinela-threatlist/main/unifi/vpn-blacklist-inline.txt`

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
