# 🕵️‍♂️ CloudGhost - Modo Ninja OSINT V4.0

**CloudGhost** es una herramienta **OSINT** avanzada escrita en Python, diseñada para descubrir la IP real de origen detrás de **cualquier WAF/CDN** (Cloudflare, Akamai, Imperva, Sucuri, Fastly, AWS CloudFront, Azure Front Door, y cualquier otro), mediante técnicas pasivas y activas de recopilación de inteligencia, resolución DNS agresiva, fingerprinting y análisis multifuente.

**Pensada con fines educativos, auditorías de seguridad, pentesting ético y bug bounty, CloudGhost automatiza un flujo completo de OSINT ofensivo.**

---

# 🆕 ¿Qué hay de nuevo en la versión 4.0?

Esta versión se enfoca en **precisión** (menos falsos positivos) y **velocidad** (concurrencia real), no solo en agregar fuentes:

🔐 **Matching de certificado TLS**: compara el SHA-256 del certificado real del dominio contra el de cada IP candidata. Es la señal de mayor confianza que existe para confirmar el origen — misma técnica en la que se basa CloudFlair.

🖼️ **Favicon hashing + Shodan**: calcula el hash del favicon (formato Shodan/`mmh3`) y busca `http.favicon.hash:X` para encontrar hosts en cualquier IP/puerto de internet sirviendo el mismo ícono, tengan o no un subdominio conocido apuntándoles.

🎯 **Sondeo de subdominios no proxeados**: prueba \~30 prefijos típicos (`mail`, `cpanel`, `ns1`, `direct`, `webdisk`, `autodiscover`, `ftp`...) que habitualmente **no** pasan por el proxy de Cloudflare aunque el sitio principal sí — técnica central de CloudFail.

📊 **Sistema de scoring por confianza**: ya no se queda con "la primera IP que responde" (eso generaba falsos positivos con cualquier servidor random del rango). Ahora cada candidata se puntúa por certificado TLS, favicon, headers, tecnologías y puertos, y se muestra el ranking completo con los motivos de cada score.

🔗 **SecurityTrails realmente conectado**: las funciones de subdominios e IPs históricas existían en versiones anteriores pero nunca se invocaban desde el flujo principal. Ahora sí forman parte del pipeline.

⚡ **Concurrencia real**: resolución DNS masiva, fuzzing de directorios y escaneo de puertos corren en paralelo con `ThreadPoolExecutor` (antes eran secuenciales pese a importar `threading`).

🌐 **Rangos de Cloudflare siempre actualizados**: se descargan en vivo desde `cloudflare.com/ips-v4` y `/ips-v6` en cada corrida (con `--static-cf-ranges` para forzar la lista embebida como respaldo offline).

🔑 **API keys por variable de entorno**: ya no se hardcodean en el código — se cargan desde un archivo `.env` (ver `.env.example`).

🐛 **Fuentes muertas reemplazadas**: ThreatCrowd (inactiva desde 2020) fue reemplazada por AlienVault OTX; Pastebin ahora avisa explícitamente si tu cuenta no es Pro en vez de fallar en silencio.

---

# 🆕 Novedades v4.4 (técnicas tomadas de CF-Hero y CloakQuest3r)

🐛 **Bug real corregido — extracción de IPs desde TXT/SPF nunca funcionaba**: CF-Hero destaca esta técnica (los registros SPF casi siempre traen las IPs como `ip4:X.X.X.X`, no como IP pura). CloudGhost ya tenía el código para esto, pero la regex nunca manejó el prefijo `ip4:`/`ip6:`, así que la extracción devolvía cero IPs siempre -- y encima el token crudo (`ip4:9.9.9.9`) se colaba como si fuera un "host" a resolver. Corregido y verificado con el mismo ejemplo que usa CF-Hero en su documentación.

🎯 **Detección de round-robin DNS en el dominio raíz**: técnica que CF-Hero ilustra explícitamente -- un dominio puede tener varios registros A, y en configuraciones mal hechas alguno de los adicionales apunta directo al origen sin pasar por el WAF. Antes CloudGhost solo miraba el primero (`socket.gethostbyname`); ahora se consultan TODOS los A/AAAA del dominio raíz y se suman como candidatas.

📋 **Wordlist de subdominios no-proxeados ampliado**: se agregaron patrones comunes que faltaban (entornos de staging/UAT/beta, paneles de administración, herramientas internas como Jenkins/GitLab/Grafana, nodos numerados). Se mantiene deliberadamente enfocado en precisión en vez de fuerza bruta masiva (CloakQuest3r prueba miles de nombres) porque la recolección OSINT de otras fuentes ya cubre ese descubrimiento amplio de forma más eficiente.

# 🆕 Novedades v4.3

🕵️ **Identificación de WAF/CDN por firma**: nuevo paso que reporta qué WAF/CDN protege al dominio (Cloudflare, Akamai, Imperva/Incapsula, Sucuri, AWS WAF, Azure Front Door, F5 BIG-IP ASM, Barracuda, FortiWeb, Citrix NetScaler, DDoS-Guard, StackPath, Reblaze, Wangsu, BunnyCDN), combinando cookies, headers y cuerpo de una respuesta normal más respuestas a payloads de sondeo típicos de XSS/SQLi/traversal que suelen disparar la página de bloqueo del WAF.

⚠️ **Importante — es informativo, no decide el filtrado**: esta herramienta ya tuvo un detector de WAF por firma antes, se retiró por poco fiable, y ese retiro causó un bug real (una IP de Akamai se reportó como "confirmada" porque nada la reconocía como perteneciente a un WAF). La lección no fue "no detectar el WAF" sino "no depender solo de eso". Por diseño, `identificar_waf()` únicamente informa al usuario — el filtrado real de candidatas sigue haciéndolo, como siempre, la descarga de rangos oficiales + la heurística ASN en `evaluar_candidatas()`, que no dependen de que la identificación por firma acierte. Un WAF no reconocido por firma (uno nuevo, o uno sin firma en esta versión) sigue estando cubierto igual por esas dos capas.

# 🆕 Novedades v4.2

🔍 **Auditoría de seguridad completa**: se corrigió una regresión real (TLS deshabilitado a nivel de sesión para las 10 fuentes OSINT async, contradecía la política de seguridad documentada), un bug de caché (fallos de configuración quedaban "confirmados" por 6h), y se dimensionó correctamente el pool de conexiones HTTP compartido.

🌍 **Cobertura multi-WAF ampliada de verdad**: además de Cloudflare/Fastly/AWS CloudFront, ahora se descargan también los rangos oficiales de **Azure Front Door** (con manejo de su URL de descarga inestable). Google Cloud Armor/CDN se dejó deliberadamente fuera — Google no separa esos rangos de su IP pool genérico, y agregarlos generaría falsos descartes de orígenes reales alojados en GCP.

🧹 **Limpieza de código muerto**: 5 funciones que estaban definidas pero nunca se llamaban desde ningún lado (`priorizar_ips_por_puertos`, `resolucion_dns_avanzada`, `encontrar_ip_real`, `escanear_puertos` simple, `consultar_workers_ai`) fueron removidas. `buscar_shodan_por_favicon()` sí valía la pena — estaba completa y correcta pero nunca conectada; ahora es una fuente más de descubrimiento de IP.

🎯 **Framing corregido**: el banner y la descripción del CLI ya no dicen "Cloudflare" como si fuera el único objetivo — reflejan la cobertura multi-WAF real de la herramienta.

# 🆕 Novedades v4.1

🥇 **WAF/CDN frontal primero, IP real después**: el primer paso ahora es identificar qué protege al dominio (Cloudflare, Akamai, Fastly, AWS CloudFront, Sucuri, Incapsula/Imperva, Azure Front Door, F5, entre otros) y usar ese resultado para elegir la estrategia de filtrado de rangos — ya no se asume Cloudflare siempre. Los proveedores con rangos IP públicos (Cloudflare, Fastly, AWS CloudFront) se descargan en vivo; para el resto, el scoring hace todo el trabajo.

🔎 **Segunda pasada de WAF sobre el origen**: tras encontrar la IP real, se vuelve a correr la detección contra ella — revela si el origen tiene su propia capa de protección además de la del frontal (defensa en profundidad).

📝 **`--title-referencia`**: evita que una página de challenge/captcha del WAF ("Just a moment...", "Attention Required", etc.) contamine el matching — la herramienta advierte automáticamente si el título auto-detectado parece uno de estos, y permite pasar el título real manualmente. El título ahora es una señal de scoring más, no solo un dato informativo.

🌐 **Censys Platform API**: nueva fuente que busca otros hosts en Internet sirviendo el mismo certificado TLS que el objetivo (la técnica original de CloudFlair). Usa la Platform API con Personal Access Token — no la legacy `search.censys.io`, que Censys retira en 2026.

👯 **`--sibling-domains`**: además del wordlist fijo de subdominios comúnmente no proxeados, ahora se puede pasar un archivo con marcas/subsidiarias del mismo programa que quizás compartan infraestructura sin estar detrás del mismo WAF.

🧦 **`--proxy` real**: la lista `PROXIES` que existía desde v4.0 sin usarse en ningún lado del código ahora enruta de verdad todo el tráfico (Burp, SOCKS5/Tor) a través de un único flag.

⏸️ **JA3 spoofing — deliberadamente NO implementado en esta versión**: algunos WAFs bloquean el JA3 hash de `requests`/`urllib3` a nivel TLS antes de que la petición HTTP llegue siquiera. Python puro no permite controlar el orden de cifrados/extensiones TLS sin librerías adicionales (`curl_cffi`, `curl-impersonate`) — se evaluó y se decidió posponerlo por ser la mejora de mayor esfuerzo/menor retorno inmediato de esta ronda. Queda como mejora futura documentada, no como pendiente olvidado.

---

# 📜 Descripción

**CloudGhost** combina técnicas pasivas y activas de **OSINT** ofensivo para encontrar la IP real detrás de un firewall, mediante resolución DNS profunda, escaneo de infraestructura, análisis de servicios, matching criptográfico de certificados y validación multifuente.

---

# 🚀 Características Principales

📑 Subdominios desde crt.sh, VirusTotal, SecurityTrails, AlienVault OTX, Wayback Machine.

🎯 Sondeo activo de subdominios comúnmente no proxeados (mail, cpanel, ns1, direct...).

🕰️ Análisis histórico vía SecurityTrails, ViewDNS, WHOIS History.

🌐 Resolución DNS avanzada y paralela (A, AAAA, MX, TXT, CNAME, NS, PTR, SOA, SRV...).

🔐 Matching de certificado TLS (SHA-256) entre el dominio real y cada IP candidata.

🖼️ Favicon hashing (`mmh3`) + búsqueda cruzada en Shodan por `http.favicon.hash`.

📊 Ranking de candidatas por score de confianza, con motivos explicados.

🔄 Rotación de proxies y user-agents (HTTP, SOCKS4/5, móviles, crawlers...).

🔍 Escaneo de puertos concurrente (comunes y extendidos: 80, 443, 22, 3306, 6379...).

🧠 Bypass HTTP/HTTPS (Host header spoofing, X-Forwarded, SNI...).

🔒 Filtro de IPs de Cloudflare con rangos oficiales descargados en vivo.

🧠 Fingerprinting de tecnologías por headers y contenido web.

🔗 Integración con APIs: Shodan, ZoomEye, VirusTotal, SecurityTrails, IPinfo, Censys.

📍 Enriquecimiento con IPInfo: ASN, país, ISP, ubicación, zona horaria.

📂 Fuzzing paralelo de rutas, búsqueda de leaks en Pastebin y GitHub.

🧪 Escaneo básico de vulnerabilidades en servicios descubiertos.

📜 Guardado de IPs candidatas (`--output`) y volcado completo en JSON (`--json`).

📊 Barra de progreso visual clara y estructurada.

🧱 Modularidad total para ampliar funcionalidades.

---

## ⚙️ Requisitos

Agrega tus **API KEYS** en el archivo **.env**

**API Keys válidas (opcionales pero recomendadas — más keys = más fuentes activas):**

* [Shodan.io](https://shodan.io) — habilita búsqueda por favicon
* [ZoomEye](https://www.zoomeye.ai/)
* [IPInfo.io](https://ipinfo.io/)
* [Virustotal](https://www.virustotal.com/gui/home/upload)
* [SecurityTrails](https://securitytrails.com/) — habilita subdominios e IPs históricas
* [Censys Platform](https://docs.censys.com/reference/get-started) — busca otros hosts que compartan el mismo certificado TLS que el objetivo (técnica CloudFlair). **Requiere la Platform API (PAT)**, no la legacy `search.censys.io` que Censys retira en 2026. Variables: `CENSYS_PAT` (obligatoria) y `CENSYS_ORG_ID` (opcional, recomendada si tu cuenta es de pago — sin ella solo obtienes permisos Free y puede devolver 403).

**- Instalar dependencias:**

```bash
pip install -r requirements.txt
```

**- Configurar API keys:**

Edita .env y completa tus claves reales
```bash
nano .env
```

Las funciones que dependan de una key ausente simplemente se saltan esa fuente y continúan con las demás — CloudGhost nunca falla por falta de una key opcional.

## 📦 Instalación y uso

**1. Clona este repositorio:**

```bash
git clone https://github.com/Zuk4r1/CloudGhost.git
cd CloudGhost
```

**2. Ejecuta la herramienta:**

```bash
python3 cloudghost.py <dominio.com>
```

# Ejemplo:

```bash
python3 cloudghost.py vulnerable.site
```

## 🎛️ Opciones de línea de comandos

```
usage: cloudghost.py [-h] [-o OUTPUT] [-t THREADS] [--json ARCHIVO]
                      [--static-cf-ranges] [--waf PROVEEDOR]
                      [--title-referencia TITULO] [--proxy URL]
                      [--sibling-domains ARCHIVO]
                      dominio

positional arguments:
  dominio               Dominio objetivo, ej: vulnerable.site

options:
  -h, --help            Muestra esta ayuda y termina
  -o, --output OUTPUT   Archivo donde guardar las IPs candidatas
                        (default: ips_detectadas.txt)
  -t, --threads THREADS Hilos concurrentes para resolución DNS,
                        fuzzing y escaneo de puertos (default: 30)
  --json ARCHIVO        Guarda el resultado completo (info IP, headers,
                        ranking, whois, vulns...) en formato JSON
  --static-cf-ranges    Usa la lista de rangos Cloudflare embebida en
                        el código en vez de descargarla en vivo
                        (útil sin conexión o si el endpoint de
                        Cloudflare está caído)
  --waf PROVEEDOR       Forzar el proveedor de WAF/CDN en vez de
                        auto-detectarlo (útil si la huella es ambigua)
  --title-referencia TITULO
                        Título HTML real del sitio, para evitar
                        auto-detectarlo si el dominio está bloqueado por
                        el WAF (challenge/captcha) y el título obtenido
                        contaminaría el matching de candidatas
  --proxy URL           Proxy para TODO el tráfico de la herramienta:
                        http://127.0.0.1:8080 (Burp) o
                        socks5://127.0.0.1:9050 (Tor)
  --sibling-domains ARCHIVO
                        Archivo con un dominio/subdominio hermano por
                        línea (marcas, subsidiarias del mismo programa)
                        a sondear además del wordlist fijo
```

### Ejemplos

```bash
# Scan estándar
python3 cloudghost.py vulnerable.site

# Más hilos para targets con muchos subdominios (cuidado con rate limits del programa VDP)
python3 cloudghost.py vulnerable.site --threads 60

# Guardar todo el resultado en JSON para adjuntar a un reporte
python3 cloudghost.py vulnerable.site --json resultado.json

# Sin conexión a internet para descargar rangos oficiales de Cloudflare
python3 cloudghost.py vulnerable.site --static-cf-ranges

# El dominio está detrás de un challenge de Cloudflare (título auto-detectado
# sería "Just a moment...") -> se pasa el título real manualmente
python3 cloudghost.py vulnerable.site --title-referencia "Vulnerable Site - Panel Cliente"

# Enrutar todo el tráfico por Burp para inspeccionar las peticiones en vivo
python3 cloudghost.py vulnerable.site --proxy http://127.0.0.1:8080

# Sondear también las marcas/subsidiarias del mismo programa (una por línea
# en el archivo) por si comparten infraestructura sin estar detrás del WAF
python3 cloudghost.py vulnerable.site --sibling-domains marcas-hermanas.txt

# Forzar el proveedor si la auto-detección de WAF es ambigua
python3 cloudghost.py vulnerable.site --waf akamai
```

## 🧪 Ejemplo de salida

```bash
[+] Escaneando: vulnerable.site
[#######-----------------------------] 22.00%
[*] Extrayendo subdominios desde crt.sh, VirusTotal, SecurityTrails, OTX...
[*] Sondeando 30 subdominios candidatos a no estar proxeados...
[+] mail.vulnerable.site -> 45.67.89.101 (fuera de rangos Cloudflare)
[*] Resolviendo 84 subdominios en paralelo (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR)...
[##############################-----] 90.00%

[ RANKING DE CANDIDATAS POR CONFIANZA ]
  45.67.89.101     score=98   motivos: certificado TLS idéntico al del dominio, favicon idéntico, responde con Host header spoofed
  185.101.22.2     score=6    motivos: headers/título HTTP no genéricos

[ RESULTADOS AVANZADOS ]
 Dominio objetivo     : vulnerable.site
 IP Cloudflare        : 104.26.14.123
 IP real detectada    : 45.67.89.101
 PTR Hostname         : server.vulnhost.net
 Organización         : OVH SAS
 ASN                  : AS16276
 País                 : FR
 Server Header        : nginx
 X-Powered-By         : PHP/8.1.12

3 IPS candidatas guardadas en: ips detectadas.txt
```

## 🧠 Cómo interpretar el ranking

El score no es un veredicto absoluto — es una guía de dónde poner tu atención primero:

|Señal|Peso|Confiabilidad|
|-|-|-|
|Certificado TLS idéntico|60|Muy alta — casi imposible de falsificar sin ser el origen real|
|Favicon idéntico (vía Shodan)|25|Alta — puede haber coincidencias si el favicon es genérico (ej. WordPress default)|
|Responde con Host header spoofed|10|Media — confirma que el server conoce el vhost, pero cualquier server mal configurado en el mismo hosting puede dar falso positivo|
|Headers/título no genéricos|5|Baja — orientativa|
|Tecnologías detectadas|3|Baja — orientativa|
|Puerto común abierto|1|Muy baja — solo suma si no hay nada mejor|

Un score ≥ 60 con motivo de certificado es evidencia sólida para incluir en un reporte. Un score bajo (solo headers/puertos) debe tratarse como candidata a validar manualmente, no como hallazgo confirmado.

## 🔐 Advertencia legal

**⚠️ CloudGhost** fue creada únicamente con fines educativos, de investigación y para pruebas de seguridad con consentimiento previo.
El uso indebido de esta herramienta puede violar leyes locales o internacionales.
El autor no se responsabiliza por daños derivados de su uso incorrecto o malicioso.

Antes de correr esta herramienta contra un target, verifica que esté dentro del **scope autorizado** (programa de Bug Bounty, VDP, pentest contratado, o laboratorio propio) y respeta cualquier límite de *rate limiting* que imponga la política del programa — el sondeo de subdominios y las consultas a APIs de terceros pueden generar volumen de tráfico no despreciable.

## ☕ Apoya mis proyectos

Si te resultan útiles mis herramientas, considera dar una ⭐ en GitHub o invitarme un café. ¡Gracias!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/investigacq)  [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/yordansuarezrojas)

---

# 🧠 Autor

Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1). – defensor del hacking ético y la investigación digital.

## ⚖️ LICENCIA

Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo [`LICENSE`](https://github.com/Zuk4r1/CloudGhost/blob/main/LICENSE) para más detalles.

## ¡Feliz hackeo! 🎯

