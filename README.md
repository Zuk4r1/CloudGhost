# 🕵️‍♂️ CloudGhost - Modo Ninja OSINT V3.6

**CloudGhost** es una herramienta **OSINT** avanzada escrita en Python, diseñada para descubrir la IP real detrás de un servidor protegido por **Cloudflare** u otros **WAFs**, mediante técnicas pasivas y activas de recopilación de inteligencia, resolución DNS agresiva, fingerprinting y análisis multifuente.

**Pensada con fines educativos, auditorías de seguridad, pentesting ético y bug bounty, CloudGhost automatiza un flujo completo de OSINT ofensivo.**

---

# 🆕 ¿Qué hay de nuevo en la versión 3.6?

🌐 **Rangos IP de Cloudflare ampliados**: Se incluyen bloques históricos, IPv4/IPv6 actuales y rangos de 2024–2025.

🔁 **Resolución de subdominios más agresiva**: Se usan múltiples fuentes como crt.sh, Wayback Machine, VirusTotal, ThreatCrowd, SecurityTrails...

🧠 **Resolución DNS masiva**: Tipos A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR e históricos.

🕵️ **USER_AGENTS y PROXIES avanzados**: Amplia rotación de agentes de usuario (desktop, móvil, bots) y proxies HTTP, HTTPS, SOCKS4/5 de múltiples ubicaciones.

🚪 **Bypass HTTP/HTTPS avanzado**: Rutas, métodos HTTP, puertos y cabeceras combinadas, con soporte SNI para HTTPS.

⚡ **Priorización inteligente de IPs**: Basado en puertos abiertos, escaneo multi-thread y rangos extendidos.

🔍 **Fingerprinting web mejorado**: Análisis de headers y HTML para detección de tecnologías y servicios.

🗂️ **Fuzzing y búsqueda de leaks**: Detección de directorios y archivos comunes, leaks en GitHub y Pastebin.

🧪 **Escaneo básico de vulnerabilidades**: Identificación de servicios inseguros y versiones vulnerables.

🔗 **Soporte multifuente OSINT**: crt.sh, Wayback Machine, VirusTotal, ThreatCrowd, Shodan, ZoomEye, SecurityTrails, ViewDNS y más.

📊 **Mejoras visuales**: Reporte estructurado, barra de progreso y banner más claro.

🧱 **Código modular y extensible**: Preparado para futuras técnicas OSINT y detección evasiva.

---

# 📜 Descripción

**CloudGhost** combina técnicas pasivas y activas de **OSINT** ofensivo para encontrar la IP real detrás de un firewall, mediante resolución DNS profunda, escaneo de infraestructura, análisis de servicios y validación multifuente.

---

# 🚀 Características Principales

📑 Subdominios desde crt.sh, VirusTotal, SecurityTrails, ThreatCrowd...

🕰️ Análisis histórico vía Wayback Machine, ViewDNS, WHOIS History.

🌐 Resolución DNS avanzada (A, AAAA, MX, TXT, CNAME, NS, PTR, SOA, SRV...).

🔄 Rotación avanzada de proxies y agentes de usuario (HTTP, SOCKS4/5, móviles, crawlers...).

🔍 Escaneo de puertos comunes y extendidos (80, 443, 22, 21, 3306...).

🧠 Técnicas automáticas de bypass HTTP/HTTPS (cabeceras, rutas, SNI...).

🔒 Filtro de IPs de Cloudflare actualizado y extendido.

🧠 Fingerprinting de tecnologías por headers y contenido web.

🔗 Integración con APIs: Shodan, ZoomEye, VirusTotal, SecurityTrails, IPinfo, Workers AI.

🧠 Análisis de headers HTTP (Server, X-Powered-By...), banners de servicios.

📍 Enriquecimiento con IPInfo: ASN, país, ISP, ubicación, zona horaria.

📂 Fuzzing de rutas, búsqueda de leaks en Pastebin y GitHub.

🧪 Escaneo básico de vulnerabilidades en servicios descubiertos.

📜 Guardado automático en `ips_detectadas.txt`.

📊 Barra de progreso visual clara y estructurada.

🧱 Modularidad total para ampliar funcionalidades.

---

## ⚙️ Requisitos

**- API Keys válidas de:**

  - [Shodan.io](https://shodan.io)  
  - [ZoomEye](https://www.zoomeye.ai/)  
  - [IPInfo.io](https://ipinfo.io/)  
  - [Virustotal](https://www.virustotal.com/gui/home/upload)  
  - [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai/)  
  - [SecurityTrails](https://securitytrails.com/)

**- Instalar dependencias:**
```bash
pip install -r requirements.txt
```

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

## 🧪 Ejemplo de salida
```bash
[+] Escaneando: vulnerable.site
[#######-----------------------------] 22.00%
[*] Extrayendo subdominios desde crt.sh, VirusTotal, SecurityTrails...
[*] Buscando URLs históricas en Wayback Machine...
[*] Resolviendo registros DNS (A, MX, TXT, CNAME, PTR...)...
[*] Escaneando puertos abiertos (80, 443, 8080...)...
[*] Consultando APIs externas...
[##############################-----] 90.00%

[ RESULTADOS ]
 Dominio objetivo     : vulnerable.site
 IP Cloudflare        : 104.26.14.123
 IP real detectada    : 45.67.89.101
 PTR Hostname         : server.vulnhost.net
 Organización         : OVH SAS
 ASN                  : AS16276
 País                 : FR
 Ubicación            : Hauts-de-France - Gravelines (50.1234, 2.5678)
 Zona horaria         : Europe/Paris
 Server Header        : nginx
 X-Powered-By         : PHP/8.1.12
 WHOIS                : Registrado por John Doe, actualizado en 2025-01-20
 DNS History          : IPs antiguas: 45.67.89.10, 185.101.22.2

[*] IPs candidatas guardadas en: ips_detectadas.txt
```

## 🔐 Advertencia legal
**⚠️ CloudGhost** fue creada únicamente con fines educativos, de investigación y para pruebas de seguridad con consentimiento previo.
El uso indebido de esta herramienta puede violar leyes locales o internacionales.
El autor no se responsabiliza por daños derivados de su uso incorrecto o malicioso.

## 🤝 ¡Apoya el proyecto!

Si esta herramienta te ha sido útil, puedes apoyar su desarrollo con una donación:

☕ [Buy Me a Coffee](https://buymeacoffee.com/investigacq)

💸 [PayPal](https://www.paypal.com/paypalme/babiloniaetica)

---
# 🧠 Autor

Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1). – defensor del hacking ético y la investigación digital.

## ⚖️ LICENCIA
Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo [`LICENCIA`](https://github.com/Zuk4r1/CloudGhost/blob/main/LICENSE) para más detalles.

## ¡Feliz hackeo! 🎯
