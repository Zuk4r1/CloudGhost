# 🕵️‍♂️ CloudGhost - Modo Ninja OSINT v1.3

CloudGhost es una herramienta OSINT avanzada escrita en Python, diseñada para intentar descubrir la **IP real de un servidor protegido por Cloudflare u otros WAFs**, mediante múltiples técnicas de recopilación de inteligencia, escaneo DNS y análisis de infraestructura.
Está pensada con fines educativos, perfecta para **auditorías de seguridad**, **pentesting ético** y **programas de bug bounty**.

---
# 🆕 ¿Qué hay de nuevo en la versión 1.3?

* 🔁 Nuevo sistema de barra de progreso visual en terminal (progreso dinámico por porcentaje).

* 📜 Wayback Machine integrada: extrae archivos históricos como robots.txt o config.js.

* 🔐 Soporte completo para ZoomEye con autenticación vía token JWT.

* 📍 Enriquecimiento de IPs con IPInfo: ASN, ISP, geolocalización y hostname PTR.

* 🧠 Análisis inteligente de headers HTTP (Server, X-Powered-By).

* 📂 Sistema automático de guardado de IPs detectadas (ips_detectadas.txt).

* 🔥 Más precisión en filtrado de IPs de Cloudflare (basado en prefijos actualizados).

* 🧱 Código modular y optimizado para futuras ampliaciones OSINT.

## 📜 Descripción

CloudGhost combina múltiples fuentes OSINT y técnicas ofensivas pasivas para identificar posibles filtraciones de IP, incluso si el dominio principal está protegido tras servicios como Cloudflare. Su poder está en la combinación de certificados, DNS, escaneos externos y consultas enriquecidas.

---

## 🚀 Características

- 📑 Extracción de subdominios desde crt.sh

- 🕰️ Análisis histórico vía Wayback Machine

- 🌐 Resolución masiva de subdominios a IPs

- 🔎 Integración con Shodan API

- 🌍 Soporte para ZoomEye API

- 🔁 PTR Lookup (DNS inverso)

- 🧠 Enriquecimiento con IPInfo API

- 🔐 Filtro automático de IPs de Cloudflare

- 🖥️ Escaneo de headers HTTP

- 📊 Progreso visual dinámico

- 🧾 Guardado automático de IPs útiles

---

## ⚙️ Requisitos

- API Keys válidas de:

    [Shodan.io](https://shodan.io)
  
    [ZoomEye](https://www.zoomeye.ai/)

    [IPInfo.io](https://ipinfo.io/)

- Instalar requirements.txt:

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
[##################------------------------] 40.00%
[*] Extrayendo subdominios desde crt.sh...
[*] Buscando URLs filtradas en Wayback Machine...
[*] Resolviendo subdominios...
[*] Consultando Shodan...
[*] Consultando ZoomEye...
[##################################--------] 90.00%

[ RESULTADOS ]
 Dominio objetivo    : vulnerable.site
 IP Cloudflare       : 104.26.14.123
 IP real detectada   : 45.67.89.101
 PTR Hostname        : server.vulnhost.net
 Organización        : OVH SAS
 ASN                 : AS16276
 País                : FR
 Ubicación           : Hauts-de-France - Gravelines (50.1234,2.5678)
 Zona horaria        : Europe/Paris
 Server Header       : nginx
 X-Powered-By        : PHP/8.1.12

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

Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1).

## ¡Feliz hackeo! 🎯

---
## LICENCIA
Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo `LICENCIA` para más detalles.
