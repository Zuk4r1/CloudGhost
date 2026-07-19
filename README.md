# 🕵️‍♂️ CloudGhost - Modo Ninja OSINT V4.0

**CloudGhost** es una herramienta **OSINT** avanzada escrita en Python, diseñada para descubrir la IP real detrás de un servidor protegido por **Cloudflare** u otros **WAFs**, mediante técnicas pasivas y activas de recopilación de inteligencia, resolución DNS agresiva, fingerprinting y análisis multifuente.

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

🔗 Integración con APIs: Shodan, ZoomEye, VirusTotal, SecurityTrails, IPinfo, Workers AI.

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
* [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai/)
* [SecurityTrails](https://securitytrails.com/) — habilita subdominios e IPs históricas

**- Instalar dependencias:**

```bash
pip install -r requirements.txt
```

**- Configurar API keys:**

```bash
cp .env.example .env
# edita .env y completa tus claves reales
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
                      [--static-cf-ranges]
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

