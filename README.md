# 🕵️‍♂️ CloudGhost - Modo Ninja OSINT v3.3
CloudGhost es una herramienta OSINT avanzada escrita en Python, diseñada para descubrir la IP real detrás de un servidor protegido por Cloudflare u otros WAFs, mediante técnicas pasivas y activas de recopilación de inteligencia, resolución DNS avanzada, escaneo de infraestructura y análisis multifuente.

Pensada con fines educativos, auditorías de seguridad, pentesting ético y bug bounty, CloudGhost automatiza un flujo completo de OSINT ofensivo.

---

# 🆕 ¿Qué hay de nuevo en la versión 3.3?

🌐 Ampliación y actualización de rangos IP de Cloudflare, incluyendo históricos, nuevos bloques IPv4/IPv6 y rangos para 2024-2025.

🔁 Resolución de subdominios más agresiva y recursiva desde múltiples fuentes (crt.sh, Wayback Machine, VirusTotal, ThreatCrowd, SecurityTrails...).

🧠 Resolución DNS masiva y avanzada con múltiples tipos de registros: A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR.

🔗 Integración de APIs externas: Shodan, ZoomEye, VirusTotal, SecurityTrails, IPinfo y Workers AI de Cloudflare.

🚪 Priorización de IPs candidatas por escaneo de puertos abiertos (80, 443, 8080...) y técnicas automáticas de bypass HTTP/HTTPS.

🕰️ IPs históricas desde ViewDNS y SecurityTrails. Consulta WHOIS y DNS History.

🧾 Mejoras visuales y robustez: barra de progreso optimizada, mejor manejo de errores, y salida más clara.

🧱 Código modular y extensible para nuevas técnicas OSINT.

---

# 📜 Descripción

CloudGhost combina múltiples fuentes OSINT, APIs avanzadas, escaneo de infraestructura y resolución DNS agresiva para encontrar filtraciones de IP, incluso si el servidor está completamente tras Cloudflare. Automatiza descubrimiento, filtrado y validación de IPs reales con priorización inteligente.

---

# 🚀 Características Principales

📑 Extracción de subdominios desde crt.sh, VirusTotal, SecurityTrails, ThreatCrowd...

🕰️ Análisis histórico vía Wayback Machine, ViewDNS y WHOIS History.

🌐 Resolución DNS avanzada (A, AAAA, MX, TXT, CNAME, NS, PTR, SOA, SRV...).

🔍 Escaneo de puertos comunes (80, 443, 22...) para priorizar IPs accesibles.

🧠 Técnicas automáticas de bypass HTTP/HTTPS y validación.

🔒 Filtro de IPs de Cloudflare actualizado (rangos oficiales + extendidos).

🤖 Integración con APIs: Shodan, ZoomEye, VirusTotal, SecurityTrails, IPinfo, Workers AI.

🧠 Análisis inteligente de headers HTTP (Server, X-Powered-By...).

📍 Enriquecimiento de IPs detectadas con IPInfo (ASN, país, ubicación, ISP...).

📜 Guardado automático de IPs útiles (ips_detectadas.txt).

📊 Barra de progreso visual mejorada en consola.

🧱 Código modular para futuras ampliaciones.

---

## ⚙️ Requisitos

- API Keys válidas de:

    [Shodan.io](https://shodan.io)
  
    [ZoomEye](https://www.zoomeye.ai/)

    [IPInfo.io](https://ipinfo.io/)

    [Virustotal](https://www.virustotal.com/gui/home/upload)

    [Cloudflare Workers AI](https://developers.cloudflare.com/workers-ai/)

    [SecurityTrails](https://securitytrails.com/)
  
- Instalar **requirements.txt**:

```bash
pip install requirements.txt
```
---
## 📦 Instalación y uso

**1. Clona este repositorio:**

```bash
git clone https://github.com/Zuk4r1/CloudGhost.git
cd cloudghost
```

**2. Ejecuta la herramienta:**
```bash
python3 cloudghost.py <dominio.com>
```

# Ejemplo:
```bash
python3 cloudghost.py vulnerable.site
```

# 🧪 Ejemplo de salida

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
---
## 🔐 Advertencia legal

**⚠️ CloudGhost** fue creada únicamente con fines educativos, de investigación y para pruebas de seguridad con consentimiento previo.

 El uso indebido de esta herramienta puede violar leyes locales o internacionales.

## El autor no se responsabiliza por daños derivados de su uso incorrecto o malicioso.

---
# 🤝 Contribuciones

Se aceptan pull requests, mejoras de código, integración con más fuentes OSINT y módulos de detección avanzados.
  <br />
	<br/>
      	<p width="20px"><b>Se aceptan donaciones para mantener este proyecto</p></b>
	      <a href="https://buymeacoffee.com/investigacq"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=investigacqc&button_colour=FF5F5F&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" /></a><br />
      	<a href="https://www.paypal.com/paypalme/babiloniaetica"><img title="Donations For Projects" height="25" src="https://ionicabizau.github.io/badges/paypal.svg" /></a>
</div>

---
# 🧠 Autor

Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1). – defensor del hacking ético y la investigación digital.

## ¡Feliz hackeo! 🎯

---
## LICENCIA
Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo `LICENCIA` para más detalles.
