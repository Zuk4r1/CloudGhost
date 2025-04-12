# 🕵️‍♂️ CloudGhost 

CloudGhost es una herramienta OSINT escrita en Python que permite intentar descubrir la **IP real de un servidor protegido por Cloudflare**, utilizando diversas técnicas de recopilación de inteligencia y resolución DNS. Fue desarrollada con fines educativos, para **auditorías de seguridad**, **pentesting ético** y **programas de bug bounty**.

---

## 📜 Descripción

CloudGhost combina múltiples técnicas para rastrear posibles IPs filtradas que puedan estar expuestas, aun si el dominio principal está protegido por Cloudflare. Su enfoque es encontrar pistas a través de registros DNS, subdominios mal configurados, consultas a Shodan y escaneo de registros PTR (DNS inverso).

---

## 🚀 Características

- 🔍 Consulta de subdominios vía Hackertarget
- 🌐 Resolución de IPs desde subdominios expuestos
- 🔁 Escaneo DNS inverso (PTR Lookup)
- 🧠 Integración con la API de **Shodan**
- 🚫 Filtrado de IPs que pertenecen a rangos de Cloudflare
- 🗺️ Información adicional de geolocalización e ISP
- 📊 Barra de progreso visual integrada
- 🖥️ Interfaz limpia desde consola

---

## ⚙️ Requisitos

- Python 3.x
- Acceso a Internet
- Una cuenta gratuita en [Shodan.io](https://shodan.io) con una API Key válida

Instala las dependencias necesarias (usa solo módulos estándar más `requests`):

```bash
pip install requests
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
[####################--------------------] 50.00%
[*] Consultando subdominios vía Hackertarget...
[*] Consultando PTR reverso...
[*] Consultando Shodan...
[##############################----------] 75.00%
...
IP real detectada   : 198.51.100.42
Organización        : DigitalOcean
Ubicación           : US, New York, NY
```
---
## 🔐 Advertencia legal

**⚠️ CloudGhost** fue creada únicamente con fines educativos, de investigación y para pruebas de seguridad autorizadas.

El uso indebido de esta herramienta puede violar leyes locales, nacionales o internacionales. No está permitido usarla contra sistemas sin consentimiento explícito del propietario.
El autor no se hace responsable por cualquier daño, pérdida de datos o uso malintencionado.

---
# 🤝 Contribuciones

Se aceptan pull requests, mejoras de código, integración con más fuentes OSINT y módulos de detección avanzados.

---
# 🧠 Autor

Created with ❤️ by [@Zuk4r1](https://github.com/Zuk4r1).

## ¡Feliz hackeo! 🎯

---
## LICENCIA
Este proyecto está licenciado bajo la licencia **MIT**. Consulte el archivo `LICENCIA` para más detalles.
