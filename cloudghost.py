#!/usr/bin/env python3
import os
import sys
import argparse
import requests
import socket
import dns.resolver
from urllib.parse import urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
import ipaddress
import re
import whois
import threading
import random
import urllib3

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv es opcional; si no está, se usan solo variables de entorno del sistema

# Silencia InsecureRequestWarning generado por verify=False (necesario para IPs sin SNI/cert válido)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# API KEYS — se cargan desde variables de entorno (.env o exportadas en el shell).
# NUNCA hardcodees claves reales en el código fuente.
ZOOMEYE_API_KEY = os.getenv("ZOOMEYE_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
WORKERS_AI_USER_ID = os.getenv("WORKERS_AI_USER_ID", "")
WORKERS_AI_API_KEY = os.getenv("WORKERS_AI_API_KEY", "")

DEFAULT_THREADS = 30

BANNER = """
\033[0;36m       __     
\033[0;36m    __(  )_      \033[1;97m\033[4;37mCloudGhost Modo Ninja OSINT\033[0;0m \033[4;31mv4.0\033[0;0m
\033[0;36m __(       )__   \033[0;0mAuthor:\033[4;31m@Zuk4r1
\033[0;36m(_____________)  \033[0;0mDetecta IP real tras Cloudflare
\033[0;36m  /⚡/⚡/⚡/    \033[0;0m
"""

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
}

# User-Agents para rotación
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0)"
]

# Proxies (puedes añadir más o cargar desde archivo)
PROXIES = [
    None,  # Sin proxy
    # "http://127.0.0.1:8080",
    # "socks5://127.0.0.1:9050"
]

# Lista oficial de rangos Cloudflare (ampliada y actualizada)
CLOUDFLARE_RANGES = [
    # IPv4 (oficial + históricos y ampliados)
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/12",
    "104.24.0.0/14",
    "104.28.0.0/15",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "162.159.0.0/16",
    "162.159.192.0/18",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "188.114.100.0/22",
    "188.114.96.0/23",
    "188.114.98.0/23",
    "188.114.100.0/23",
    "188.114.102.0/23",
    "188.114.104.0/22",
    "188.114.108.0/22",
    "188.114.112.0/20",
    "190.93.240.0/20",
    "190.93.241.0/24",
    "190.93.242.0/23",
    "190.93.244.0/22",
    "190.93.240.0/21",
    "190.93.248.0/21",
    "197.234.240.0/22",
    "197.234.241.0/24",
    "197.234.242.0/23",
    "197.234.240.0/21",
    "198.41.128.0/17",
    "198.41.129.0/24",
    "198.41.130.0/23",
    "198.41.132.0/22",
    "198.41.136.0/21",
    "198.41.144.0/20",
    "198.41.160.0/19",
    "198.41.192.0/18",
    "104.19.0.0/16",
    "104.20.0.0/15",
    "104.22.0.0/15",
    "141.101.120.0/21",
    "162.159.128.0/17",
    # IPv6 (oficial + extendidos)
    "2400:cb00::/32",
    "2405:8100::/32",
    "2405:b500::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2a06:98c0::/29",
    "2a09:bac0::/29",
    "2a09:bac0::/28",
    "2c0f:f248::/32",
    # Rango adicional de Cloudflare IPv6 (RIPE/ARIN y otras fuentes públicas)
    "2a12:4940::/29",
    "2a13:5240::/29",
    "2a14:4c00::/29",
    "2a15:8b00::/29",
    "2a15:8c00::/29",
    "2a15:8d00::/29",
    "2a15:8e00::/29",
    "2a15:8f00::/29",
    "2a15:9000::/29",
    "2a15:9100::/29",
    "2a15:9200::/29",
    "2a15:9300::/29",
    "2a15:9400::/29",
    "2a15:9500::/29",
    "2a15:9600::/29",
    "2a15:9700::/29",
    # Nuevos rangos publicados por Cloudflare (2024-2025 y ampliados)
    "2a06:98c0:1000::/36",
    "2a06:98c0:2000::/36",
    "2a06:98c0:3000::/36",
    "2a06:98c0:4000::/36",
    "2a06:98c0:5000::/36",
    "2a06:98c0:6000::/36",
    "2a06:98c0:7000::/36",
    "2a10:50c0::/29",
    "2a11:fa40::/29",
    # Otros bloques públicos conocidos (puedes ampliar según fuentes públicas)
    "2a10:6000::/29",
    "2a10:7000::/29",
    "2a10:8000::/29",
    "2a10:9000::/29",
    "2a10:a000::/29",
    "2a10:b000::/29",
    "2a10:c000::/29",
    "2a10:d000::/29",
    "2a10:e000::/29",
    "2a10:f000::/29"
]

def limpiar_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).netloc

def mostrar_barra_progreso(porcentaje):
    largo_total = 40
    largo_lleno = int(porcentaje / 100 * largo_total)
    barra = "[" + "#" * largo_lleno + "-" * (largo_total - largo_lleno) + "]"
    print(f"\r{barra} {porcentaje:.2f}%", end="")

def buscar_certificados_crtsh(domain):
    print("[*] Extrayendo subdominios y posibles IPs desde crt.sh (agresivo y recursivo)...")
    subdominios = set()
    ips = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        resultados = r.json()
        for entry in resultados:
            nombre = entry.get("name_value", "")
            for sub in nombre.split("\n"):
                if domain in sub:
                    subdominios.add(sub.strip())
        # Extrae posibles IPs de los Common Name/SAN y busca patrones de IP en los nombres
        for sub in subdominios:
            try:
                ip = socket.gethostbyname(sub)
                ips.add(ip)
            except:
                found_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', sub)
                for ip in found_ips:
                    ips.add(ip)
                continue
        # Intenta resolver CNAMEs de los subdominios
        for sub in subdominios:
            try:
                cname_answers = dns.resolver.resolve(sub, 'CNAME')
                for cname in cname_answers:
                    cname_host = str(cname.target).rstrip('.')
                    try:
                        ip_cname = socket.gethostbyname(cname_host)
                        ips.add(ip_cname)
                    except:
                        pass
            except:
                continue
        return list(subdominios), list(ips)
    except:
        return list(subdominios), list(ips)

def buscar_en_wayback(domain):
    print("[*] Buscando URLs filtradas en Wayback Machine...")
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey", timeout=10)
        data = r.json()[1:]  # Skip header
        return [d[0] for d in data if any(ext in d[0] for ext in ["robots.txt", "config.js"])]
    except:
        return []

def _resolver_un_subdominio(sub, tipos):
    ips_local, hosts_local = set(), set()
    for rtype in tipos:
        try:
            answers = dns.resolver.resolve(sub, rtype, lifetime=5)
            for rdata in answers:
                if rtype in ('A', 'AAAA'):
                    ips_local.add(rdata.address)
                elif rtype == 'MX':
                    hosts_local.add(str(rdata.exchange).rstrip('.'))
                elif rtype in ('CNAME', 'NS', 'SRV', 'PTR'):
                    hosts_local.add(str(rdata.target).rstrip('.'))
                elif rtype == 'SOA':
                    hosts_local.add(str(rdata.mname).rstrip('.'))
                elif rtype == 'TXT':
                    for part in str(rdata).split():
                        clean = part.strip('"')
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', clean):
                            ips_local.add(clean)
                        elif '.' in part:
                            hosts_local.add(clean)
        except dns.exception.DNSException:
            continue
    return ips_local, hosts_local

def _resolver_host_adicional(host):
    ips_local = set()
    try:
        ips_local.update(socket.gethostbyname_ex(host)[2])
    except socket.error:
        pass
    try:
        for cname in dns.resolver.resolve(host, 'CNAME', lifetime=5):
            try:
                ips_local.add(socket.gethostbyname(str(cname.target).rstrip('.')))
            except socket.error:
                pass
    except dns.exception.DNSException:
        pass
    return ips_local

def resolucion_dns_masiva(subdominios, threads=DEFAULT_THREADS):
    print(f"[*] Resolviendo {len(subdominios)} subdominios en paralelo (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR)...")
    ips, hosts = set(), set()
    tipos = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'SRV', 'PTR']
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futuros = {ex.submit(_resolver_un_subdominio, sub, tipos): sub for sub in subdominios}
        for f in as_completed(futuros):
            ips_local, hosts_local = f.result()
            ips.update(ips_local)
            hosts.update(hosts_local)
    # Resuelve hosts adicionales descubiertos (CNAME/MX/NS/etc.), también en paralelo
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for f in as_completed({ex.submit(_resolver_host_adicional, h): h for h in hosts}):
            ips.update(f.result())
    return list(ips)

def consultar_shodan(domain):
    print("[*] Consultando Shodan (DNS y búsqueda directa)...")
    try:
        # Consulta DNS de Shodan
        r = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}")
        data = r.json()
        sub_ips = set()
        for sub in data.get("subdomains", []):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                sub_ips.add(ip)
            except:
                continue
        # Búsqueda directa en Shodan (host search)
        r2 = requests.get(f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=hostname:{domain}")
        if r2.status_code == 200:
            data2 = r2.json()
            for match in data2.get("matches", []):
                ip = match.get("ip_str")
                if ip:
                    sub_ips.add(ip)
        return list(sub_ips)
    except:
        return []

def consultar_zoom_eye(domain):
    print("[*] Consultando ZoomEye...")
    try:
        headers = {"Authorization": f"JWT {ZOOMEYE_API_KEY}"}
        r = requests.get(f"https://api.zoomeye.org/host/search?query=hostname:{domain}", headers=headers)
        data = r.json()
        return [hit["ip"] for hit in data.get("matches", []) if "ip" in hit]
    except:
        return []

def dns_ptr_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "PTR no disponible"

def obtener_datos_ip(ip):
    try:
        info = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}").json()
        org = info.get("org", "Desconocido")
        asn = info.get("asn", {}).get("asn", "N/A")
        pais = info.get("country", "Desconocido")
        ubicacion = info.get("loc", "")
        ciudad = info.get("city", "")
        region = info.get("region", "")
        zona = info.get("timezone", "")

        # Precisión: consulta fuentes adicionales si hay valores por defecto
        if org == "Desconocido":
            try:
                r = requests.get(f"https://ipapi.co/{ip}/org/", timeout=5)
                if r.status_code == 200 and r.text.strip() and "Desconocido" not in r.text:
                    org = r.text.strip()
            except:
                pass
        if asn == "N/A":
            try:
                r = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=5)
                if r.status_code == 200 and r.text.startswith("AS"):
                    asn = r.text.split()[0]
            except:
                pass
        if pais == "Desconocido":
            try:
                r = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=5)
                if r.status_code == 200 and r.text.strip() and "Desconocido" not in r.text:
                    pais = r.text.strip()
            except:
                pass
        if not ubicacion or ubicacion == ",":
            try:
                r = requests.get(f"https://ipapi.co/{ip}/latlong/", timeout=5)
                if r.status_code == 200 and r.text.strip():
                    ubicacion = r.text.strip()
            except:
                pass
        if not ciudad:
            try:
                r = requests.get(f"https://ipapi.co/{ip}/city/", timeout=5)
                if r.status_code == 200 and r.text.strip():
                    ciudad = r.text.strip()
            except:
                pass
        if not region:
            try:
                r = requests.get(f"https://ipapi.co/{ip}/region/", timeout=5)
                if r.status_code == 200 and r.text.strip():
                    region = r.text.strip()
            except:
                pass
        if not zona:
            try:
                r = requests.get(f"https://ipapi.co/{ip}/timezone/", timeout=5)
                if r.status_code == 200 and r.text.strip():
                    zona = r.text.strip()
            except:
                pass

        # Extra: consulta ARIN si sigue sin datos
        if org == "Desconocido" or asn == "N/A":
            try:
                r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    if org == "Desconocido":
                        org = data.get("name") or data.get("handle") or org
                    if asn == "N/A":
                        asn = data.get("autnum") or asn
            except:
                pass

        return {
            "ip": info.get("ip"),
            "org": org,
            "asn": asn,
            "hostname": dns_ptr_lookup(ip),
            "pais": pais,
            "ubicacion": ubicacion,
            "ciudad": ciudad,
            "region": region,
            "zona": zona
        }
    except:
        return {}

def escanear_headers(domain_or_ip):
    # Si los headers principales son por defecto, prueba puertos alternativos
    print(f"[*] Analizando headers para {domain_or_ip} (HTTP y HTTPS, agresivo)...")
    resultados = {}
    urls = [f"http://{domain_or_ip}", f"https://{domain_or_ip}"]
    alt_ports = [80, 443, 8080, 8443, 8000, 8888, 5000, 5001]
    for url in urls:
        found = False
        for port in [None] + alt_ports:
            try:
                proto = "https" if url.startswith("https") else "http"
                if port and port not in [80, 443]:
                    test_url = f"{proto}://{domain_or_ip}:{port}"
                else:
                    test_url = url
                r = requests.get(test_url, headers=HEADERS, timeout=7, verify=False, allow_redirects=True)
                server = r.headers.get("Server", "Desconocido")
                powered = r.headers.get("X-Powered-By", "Desconocido")
                title = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE)
                title = title.group(1) if title else ""
                if (server and server != "Desconocido") or (powered and powered != "Desconocido") or title:
                    resultados[url] = {
                        "Server": server,
                        "X-Powered-By": powered,
                        "Title": title,
                        "Location": r.headers.get("Location", ""),
                        "Set-Cookie": r.headers.get("Set-Cookie", "")
                    }
                    found = True
                    break
            except:
                continue
        if not found:
            resultados[url] = {"Server": "Error", "X-Powered-By": "Error", "Title": "", "Location": "", "Set-Cookie": ""}
    return resultados

def obtener_rangos_cloudflare_oficiales():
    # Trae la lista oficial y siempre-actualizada de Cloudflare. Si falla (sin red,
    # timeout, cambio de endpoint), cae de vuelta al listado estático como respaldo.
    try:
        v4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=8).text.split()
        v6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=8).text.split()
        rangos = [r for r in (v4 + v6) if r]
        if rangos:
            return rangos
    except requests.RequestException:
        pass
    return CLOUDFLARE_RANGES

def ip_in_cloudflare(ip, rangos=None):
    # rangos=None usa CLOUDFLARE_RANGES (estático); pasar el resultado de
    # obtener_rangos_cloudflare_oficiales() para usar la lista siempre-actualizada.
    if rangos is None:
        rangos = CLOUDFLARE_RANGES
    if not ip or not isinstance(ip, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in rangos:
        try:
            if ip_obj in ipaddress.ip_network(net):
                return True
        except ValueError:
            # Una entrada corrupta en la lista ya no aborta el resto del chequeo
            continue
    return False

def buscar_subdominios_securitytrails(domain):
    print("[*] Buscando subdominios en SecurityTrails...")
    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": SECURITYTRAILS_API_KEY}
        )
        if r.status_code == 200:
            data = r.json()
            return [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
    except:
        pass
    return []

def buscar_subdominios_virustotal(domain):
    print("[*] Buscando subdominios en VirusTotal...")
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}
        )
        if r.status_code == 200:
            data = r.json()
            return [item["id"] for item in data.get("data", [])]
    except:
        pass
    return []

def buscar_subdominios_otx(domain):
    # ThreatCrowd está inactiva desde ~2020 (siempre devuelve error/timeout).
    # AlienVault OTX cubre el mismo caso de uso, sigue activa y no requiere API key.
    print("[*] Buscando subdominios en AlienVault OTX...")
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            hosts = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname and domain in hostname:
                    hosts.add(hostname)
            return list(hosts)
    except (requests.RequestException, ValueError):
        pass
    return []

def escanear_puertos(ip, puertos=[80, 443, 8080, 8443, 22, 21, 25], threads=DEFAULT_THREADS):
    def probar(puerto):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, puerto)) == 0:
                    return puerto
        except OSError:
            pass
        return None
    with ThreadPoolExecutor(max_workers=min(threads, len(puertos) or 1)) as ex:
        return [p for p in ex.map(probar, puertos) if p is not None]

def intentar_bypass_http(domain, ip):
    print(f"[*] Probando bypass HTTP/HTTPS agresivo a {ip}...")
    try:
        headers = HEADERS.copy()
        headers["Host"] = domain
        # HTTP
        r = requests.get(f"http://{ip}", headers=headers, timeout=7)
        if domain in r.text or r.status_code in [200, 403, 401]:
            return True
        # HTTPS
        try:
            r = requests.get(f"https://{ip}", headers=headers, timeout=7, verify=False)
            if domain in r.text or r.status_code in [200, 403, 401]:
                return True
        except:
            pass
        # X-Forwarded-Host y X-Forwarded-For
        headers["X-Forwarded-Host"] = domain
        headers["X-Forwarded-For"] = "127.0.0.1"
        r = requests.get(f"http://{ip}", headers=headers, timeout=7)
        if domain in r.text or r.status_code in [200, 403, 401]:
            return True
        # User-Agent alternativo
        headers["User-Agent"] = "curl/7.68.0"
        r = requests.get(f"http://{ip}", headers=headers, timeout=7)
        if domain in r.text or r.status_code in [200, 403, 401]:
            return True
        # Prueba con HTTPS y headers alternativos
        try:
            r = requests.get(f"https://{ip}", headers=headers, timeout=7, verify=False)
            if domain in r.text or r.status_code in [200, 403, 401]:
                return True
        except:
            pass
        # Prueba con otros headers comunes de proxy
        headers["X-Real-IP"] = "127.0.0.1"
        headers["Forwarded"] = f"for=127.0.0.1;host={domain};proto=http"
        r = requests.get(f"http://{ip}", headers=headers, timeout=7)
        if domain in r.text or r.status_code in [200, 403, 401]:
            return True
    except:
        pass
    return False

def obtener_fingerprint_certificado(host_conexion, sni, puerto=443, timeout=6):
    # Conecta por TCP a host_conexion:puerto pero envía SNI=sni (server_hostname),
    # y devuelve el SHA-256 del certificado de hoja servido. Esto permite:
    #   - Sacar el cert "de referencia" conectando al dominio real (vía Cloudflare)
    #   - Sacar el cert de cada IP candidata pidiendo el mismo SNI
    # Si ambos SHA-256 coinciden, la IP candidata sirve el certificado real del
    # sitio -> señal de altísima confianza de que es el origen (técnica usada por
    # CloudFlair y herramientas similares).
    import ssl, hashlib
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host_conexion, puerto), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                return hashlib.sha256(der_cert).hexdigest()
    except (socket.error, ssl.SSLError, OSError):
        return None

def obtener_favicon_hash(url, timeout=7):
    # Hash estilo Shodan (mmh3 de 32 bits sobre el favicon en base64) para poder
    # buscar directamente "http.favicon.hash:<hash>" en Shodan y encontrar otros
    # hosts (potencialmente el origen) sirviendo el mismo favicon.
    import base64
    import mmh3
    try:
        r = requests.get(url.rstrip('/') + "/favicon.ico", headers=random_headers(),
                          timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code == 200 and r.content:
            b64 = base64.encodebytes(r.content)
            return mmh3.hash(b64)
    except requests.RequestException:
        pass
    return None

def buscar_shodan_por_favicon(favicon_hash):
    if not SHODAN_API_KEY or favicon_hash is None:
        return []
    print(f"[*] Buscando en Shodan hosts con el mismo favicon (hash={favicon_hash})...")
    try:
        r = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_API_KEY, "query": f"http.favicon.hash:{favicon_hash}"},
            timeout=15
        )
        if r.status_code == 200:
            return [m["ip_str"] for m in r.json().get("matches", []) if m.get("ip_str")]
    except requests.RequestException:
        pass
    return []

SUBDOMINIOS_NO_PROXEADOS = [
    "direct", "origin", "origin-www", "cpanel", "webdisk", "webmail", "mail",
    "autodiscover", "autoconfig", "ns1", "ns2", "smtp", "pop", "imap", "ftp",
    "sftp", "vpn", "remote", "sql", "db", "database", "dev", "staging", "old",
    "backup", "test", "demo", "portal", "direct-connect", "server", "host",
]

def buscar_subdominios_no_proxeados(domain, rangos_cf=None, threads=DEFAULT_THREADS):
    # Muchos servicios (correo, paneles de admin, DNS, backups) no pasan por el
    # proxy de Cloudflare aunque el sitio principal sí. Si alguno de estos
    # subdominios resuelve a una IP que no es de Cloudflare, esa IP casi siempre
    # vive en la misma red/hosting que el origen real -> pista de alto valor.
    print(f"[*] Sondeando {len(SUBDOMINIOS_NO_PROXEADOS)} subdominios candidatos a no estar proxeados...")
    rangos_cf = rangos_cf if rangos_cf is not None else CLOUDFLARE_RANGES
    candidatos = [f"{s}.{domain}" for s in SUBDOMINIOS_NO_PROXEADOS]

    def resolver(sub):
        try:
            ip = socket.gethostbyname(sub)
            if not ip_in_cloudflare(ip, rangos_cf):
                return (sub, ip)
        except socket.error:
            pass
        return None

    hallazgos = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(resolver, candidatos):
            if res:
                hallazgos.append(res)
                print(f"    [+] {res[0]} -> {res[1]} (fuera de rangos Cloudflare)")
    return hallazgos

def guardar_ips(ips, ruta="ips_detectadas.txt"):
    with open(ruta, "w") as f:
        for ip in ips:
            f.write(ip + "\n")

def resolucion_dns_avanzada(subdominios, threads=DEFAULT_THREADS):
    # Antes era una copia 1:1 de resolucion_dns_masiva con lifetime=7 en vez de 5.
    # Se unifica reutilizando los mismos helpers paralelizados para no mantener
    # dos implementaciones idénticas (y consultar cada subdominio dos veces por scan).
    return resolucion_dns_masiva(subdominios, threads=threads)

def buscar_ips_historicas_securitytrails(domain):
    print("[*] Buscando IPs históricas en SecurityTrails...")
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/history/{domain}/dns/a", headers={"APIKEY": "API_KEY"})
        if r.status_code == 200:
            data = r.json()
            ips = []
            for record in data.get("records", []):
                for value in record.get("values", []):
                    ip = value.get("ip")
                    if ip:
                        ips.append(ip)
            return ips
    except:
        pass
    return []

def buscar_ips_historicas_viewdns(domain):
    print("[*] Buscando IPs históricas en ViewDNS.info (agresivo y recursivo)...")
    try:
        r = requests.get(f"https://viewdns.info/iphistory/?domain={domain}")
        if r.status_code == 200:
            lines = r.text.splitlines()
            ips = []
            for line in lines:
                found_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
                ips.extend(found_ips)
            # Intenta resolver hosts históricos también
            hosts = re.findall(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')', "\n".join(lines))
            for host in set(hosts):
                try:
                    ip = socket.gethostbyname(host)
                    ips.append(ip)
                except:
                    continue
            return list(set(ips))
    except:
        pass
    return []

def priorizar_ips_por_puertos(ips, puertos=[80, 443, 8080, 8443]):
    print("[*] Priorizando IPs por puertos abiertos...")
    ip_puertos = []
    for ip in ips:
        abiertos = escanear_puertos(ip, puertos)
        if abiertos:
            ip_puertos.append((ip, abiertos))
    # Ordena por cantidad de puertos abiertos
    ip_puertos.sort(key=lambda x: len(x[1]), reverse=True)
    return ip_puertos

def whois_dns_history(domain):
    print("[*] Consultando WHOIS y DNS History (agresivo y extendido)...")
    info = {}
    try:
        w = whois.whois(domain)
        info["registrar"] = w.registrar
        info["creation_date"] = str(w.creation_date)
        info["expiration_date"] = str(w.expiration_date)
        info["name_servers"] = w.name_servers
        info["emails"] = w.emails
        info["status"] = w.status
    except:
        info["whois"] = "No disponible"
    # DNS History con ViewDNS (agresivo y extendido)
    try:
        r = requests.get(f"https://viewdns.info/iphistory/?domain={domain}")
        if r.status_code == 200:
            lines = r.text.splitlines()
            history_ips = []
            for line in lines:
                found_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
                history_ips.extend(found_ips)
            # Intenta resolver hosts históricos también
            hosts = re.findall(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')', "\n".join(lines))
            for host in set(hosts):
                try:
                    ip = socket.gethostbyname(host)
                    history_ips.append(ip)
                except:
                    continue
            info["dns_history"] = list(set(history_ips))
    except:
        info["dns_history"] = []
    return info

def consultar_workers_ai(query, model="llama-2-7b-chat-fp16"):
    print("[*] Consultando Workers AI (Cloudflare) para análisis avanzado...")
    try:
        url = f"https://api.cloudflare.com/client/v4/accounts/{WORKERS_AI_USER_ID}/ai/run/@cf/{model}"
        headers = {
            "Authorization": f"Bearer {WORKERS_AI_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {"input": query}
        r = requests.post(url, headers=headers, json=data, timeout=15)
        if r.status_code == 200:
            result = r.json()
            return result.get("result", {}).get("response", "")
        else:
            return f"Error Workers AI: {r.text}"
    except Exception as e:
        return f"Error Workers AI: {e}"

def filtrar_ips_cloudflare(ips, rangos=None):
    return [ip for ip in ips if not ip_in_cloudflare(ip, rangos)]

def random_headers():
    headers = HEADERS.copy()
    headers["User-Agent"] = random.choice(USER_AGENTS)
    return headers

def escanear_puertos_avanzado(ip, puertos=None, threads=50):
    print(f"[*] Escaneo avanzado de puertos para {ip} (multi-thread)...")
    if puertos is None:
        puertos = list(range(1, 1025)) + [3306, 5432, 6379, 11211, 27017, 9200, 5000, 8000, 8080, 8443, 8888, 27018, 27019]
    abiertos = []
    lock = threading.Lock()
    def scan_port(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.7)
            if s.connect_ex((ip, p)) == 0:
                with lock:
                    abiertos.append(p)
            s.close()
        except:
            pass
    threads_list = []
    for puerto in puertos:
        t = threading.Thread(target=scan_port, args=(puerto,))
        t.start()
        threads_list.append(t)
        if len(threads_list) >= threads:
            for th in threads_list:
                th.join()
            threads_list = []
    for th in threads_list:
        th.join()
    return abiertos

def banner_grabbing(ip, puerto):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, puerto))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(1024)
        s.close()
        return data.decode(errors="ignore")
    except:
        return ""

def detectar_tecnologias(url):
    # Si no detecta nada, prueba con puertos alternativos y HTML más profundo
    print(f"[*] Fingerprinting de tecnologías web en {url}...")
    tecnologias = set()
    ports = [None, 8080, 8443, 8000, 8888, 5000, 5001]
    for port in ports:
        try:
            proto = "https" if url.startswith("https") else "http"
            base = url.split('://')[1].split('/')[0]
            test_url = f"{proto}://{base}:{port}/" if port else url
            r = requests.get(test_url, headers=random_headers(), timeout=7, verify=False, allow_redirects=True)
            headers = r.headers
            html = r.text
            if "x-powered-by" in headers:
                tecnologias.add(headers["x-powered-by"])
            if "server" in headers:
                tecnologias.add(headers["server"])
            if "wp-content" in html or "wordpress" in html.lower():
                tecnologias.add("WordPress")
            if "drupal" in html.lower():
                tecnologias.add("Drupal")
            if "joomla" in html.lower():
                tecnologias.add("Joomla")
            if "set-cookie" in headers and "PHPSESSID" in headers["set-cookie"]:
                tecnologias.add("PHP")
            if "X-AspNet-Version" in headers:
                tecnologias.add("ASP.NET")
            if "laravel_session" in headers.get("set-cookie", ""):
                tecnologias.add("Laravel")
            if re.search(r'<meta[^>]+generator[^>]+wordpress', html, re.I):
                tecnologias.add("WordPress")
            if re.search(r'<meta[^>]+generator[^>]+drupal', html, re.I):
                tecnologias.add("Drupal")
            if re.search(r'<meta[^>]+generator[^>]+joomla', html, re.I):
                tecnologias.add("Joomla")
            if "react" in html.lower():
                tecnologias.add("ReactJS")
            if "vue" in html.lower():
                tecnologias.add("VueJS")
            if "angular" in html.lower():
                tecnologias.add("Angular")
            if "django" in html.lower():
                tecnologias.add("Django")
            if "rails" in html.lower():
                tecnologias.add("Ruby on Rails")
            if "express" in html.lower():
                tecnologias.add("ExpressJS")
            if tecnologias:
                break
        except:
            continue
    return list(tecnologias)

def detectar_waf(domain_or_ip):
    # Si no detecta, prueba con HTTPS y puertos alternativos
    print(f"[*] Detección de WAF/firewall en {domain_or_ip}...")
    wafs = {
        "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
        "sucuri": ["sucuri"],
        "incapsula": ["incap_ses", "incapsula"],
        "aws": ["awselb", "awsalb"],
        "f5": ["bigip"],
        "barracuda": ["barra"],
        "imperva": ["imperva"],
        "akamai": ["akamai"],
        "mod_security": ["mod_security"],
    }
    ports = [None, 8080, 8443, 8000, 8888, 5000, 5001]
    protos = ["http", "https"]
    for proto in protos:
        for port in ports:
            try:
                url = f"{proto}://{domain_or_ip}:{port}" if port else f"{proto}://{domain_or_ip}"
                r = requests.get(url, headers=random_headers(), timeout=5, verify=False)
                headers = str(r.headers).lower()
                html = r.text.lower()
                for nombre, firmas in wafs.items():
                    for firma in firmas:
                        if firma in headers or firma in html:
                            return nombre
            except:
                continue
    return "No detectado"

def buscar_leaks_github(domain):
    print(f"[*] Buscando posibles leaks en GitHub para {domain}...")
    leaks = []
    try:
        r = requests.get(f"https://api.github.com/search/code?q={domain}", headers=random_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                leaks.append(item.get("html_url"))
    except:
        pass
    return leaks

def buscar_leaks_pastebin(domain):
    # AVISO: el endpoint de scraping de Pastebin requiere una cuenta Pro con IP
    # en whitelist desde 2019. Sin eso, esta llamada siempre devuelve 403.
    # Se deja implementada por si el usuario tiene acceso Pro; si no, devuelve
    # vacío de forma explícita en vez de fallar en silencio como antes.
    print(f"[*] Buscando posibles leaks en Pastebin para {domain} (requiere cuenta Pro)...")
    leaks = []
    try:
        r = requests.get("https://scrape.pastebin.com/api_scraping.php?limit=50", timeout=10)
        if r.status_code == 403:
            print("    [!] Pastebin devolvió 403 — necesitas cuenta Pro con IP en whitelist para esta fuente.")
            return leaks
        if r.status_code == 200:
            data = r.json()
            for item in data:
                if domain in item.get("title", "") or domain in item.get("key", ""):
                    leaks.append(item.get("scrape_url"))
    except (requests.RequestException, ValueError):
        pass
    return leaks

def escanear_vulnerabilidades(ip, puertos):
    print(f"[*] Escaneo rápido de vulnerabilidades conocidas en {ip}...")
    vulns = []
    # Ejemplo: detectar SMBv1, versiones inseguras de HTTP, etc.
    for puerto in puertos:
        banner = banner_grabbing(ip, puerto)
        if "smb" in banner.lower() and "version: 1" in banner.lower():
            vulns.append(f"SMBv1 inseguro en puerto {puerto}")
        if "apache/2.2" in banner.lower():
            vulns.append(f"Apache 2.2 detectado (EOL) en puerto {puerto}")
        if "iis/6.0" in banner.lower():
            vulns.append(f"IIS 6.0 detectado (EOL) en puerto {puerto}")
        # ...puedes añadir más firmas de CVE...
    return vulns

def evaluar_candidatas(dominio, candidatas, fp_referencia=None, favicon_hash_ref=None,
                        puertos=[80, 443, 8080, 8443, 8000, 8888, 5000, 5001]):
    # Antes: "la primera IP que responde con 200/403/401 gana" -> muchos falsos
    # positivos, cualquier servidor random en el rango contestaba y se aceptaba.
    # Ahora: cada candidata se puntúa con varias señales independientes y se
    # devuelve el ranking completo, no solo una IP. La de mayor score es la más
    # probable de ser el origen real.
    resultados = []
    for ip in candidatas:
        score = 0
        motivos = []

        if fp_referencia:
            fp_candidata = obtener_fingerprint_certificado(ip, dominio)
            if fp_candidata and fp_candidata == fp_referencia:
                score += 60
                motivos.append("certificado TLS idéntico al del dominio")

        if favicon_hash_ref is not None:
            fh = obtener_favicon_hash(f"http://{ip}")
            if fh == favicon_hash_ref:
                score += 25
                motivos.append("favicon idéntico")

        if intentar_bypass_http(dominio, ip):
            score += 10
            motivos.append("responde con Host header spoofed")

        headers = escanear_headers(ip)
        for url, data in headers.items():
            if data.get("Server") not in ["Desconocido", "Error", None] or data.get("Title"):
                score += 5
                motivos.append("headers/título HTTP no genéricos")
                break

        if detectar_tecnologias(f"http://{ip}"):
            score += 3
            motivos.append("tecnologías web detectadas")

        for port in puertos:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        score += 1
                        break
            except OSError:
                continue

        if score > 0:
            resultados.append({"ip": ip, "score": score, "motivos": motivos})

    resultados.sort(key=lambda r: r["score"], reverse=True)
    return resultados

def encontrar_ip_real(dominio, candidatas, puertos=[80, 443, 8080, 8443, 8000, 8888, 5000, 5001]):
    # Wrapper simple sobre evaluar_candidatas para mantener compatibilidad con
    # código que solo necesita "la mejor IP", sin certificado/favicon de referencia.
    ranking = evaluar_candidatas(dominio, candidatas, puertos=puertos)
    return ranking[0]["ip"] if ranking else None

def fuzz_directorios(ip, paths=None, threads=DEFAULT_THREADS):
    if paths is None:
        paths = [
            "admin", "login", "dashboard", "config", "config.php", "robots.txt",
            "backup", "db", "test", "old", "dev", "api", ".env", ".git", "wp-admin",
            "wp-login.php", "phpinfo.php", "server-status"
        ]
    urls = [f"{proto}://{ip}/{path}" for proto in ("http", "https") for path in paths]
    print(f"[*] Fuzzing de {len(urls)} rutas en {ip} (paralelo)...")
    encontrados = []
    def probar(url):
        try:
            r = requests.get(url, headers=random_headers(), timeout=5, verify=False, allow_redirects=True)
            if r.status_code in (200, 301, 302, 403):
                return f"{url} [{r.status_code}]"
        except requests.RequestException:
            pass
        return None
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(probar, urls):
            if res:
                encontrados.append(res)
    return encontrados

def parse_args():
    parser = argparse.ArgumentParser(
        prog="cloudghost.py",
        description="CloudGhost - OSINT ofensivo para detectar la IP real tras Cloudflare/WAF."
    )
    parser.add_argument("dominio", help="Dominio objetivo, ej: vulnerable.site")
    parser.add_argument("-o", "--output", default="ips_detectadas.txt",
                         help="Archivo donde guardar las IPs candidatas (default: ips_detectadas.txt)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                         help=f"Hilos concurrentes para resolución/fuzzing/escaneo (default: {DEFAULT_THREADS})")
    parser.add_argument("--json", metavar="ARCHIVO",
                         help="Guarda además el resultado completo en formato JSON en el archivo indicado")
    parser.add_argument("--static-cf-ranges", action="store_true",
                         help="Usa la lista estática de rangos Cloudflare embebida en vez de descargar la oficial")
    return parser.parse_args()

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    args = parse_args()

    dominio = limpiar_url(args.dominio)
    print(f"\n[+] Escaneando: {dominio}")
    mostrar_barra_progreso(5)

    try:
        cf_ip = socket.gethostbyname(dominio)
    except socket.gaierror:
        print(f"\n[!] No se pudo resolver {dominio}. ¿Está bien escrito el dominio?")
        sys.exit(1)
    mostrar_barra_progreso(10)

    rangos_cf = CLOUDFLARE_RANGES if args.static_cf_ranges else obtener_rangos_cloudflare_oficiales()

    # crt.sh mejorado
    sub1, ips_crtsh = buscar_certificados_crtsh(dominio)
    sub2 = buscar_en_wayback(dominio)
    sub3 = buscar_subdominios_virustotal(dominio)
    sub4 = buscar_subdominios_otx(dominio)
    sub5 = buscar_subdominios_securitytrails(dominio)  # antes definida pero nunca llamada
    subdominios = list(set(sub1 + sub2 + sub3 + sub4 + sub5))
    mostrar_barra_progreso(20)

    # DNS masiva (paralela) + fuentes externas
    ips1 = resolucion_dns_masiva(subdominios, threads=args.threads)
    ips2 = consultar_shodan(dominio)
    ips3 = consultar_zoom_eye(dominio)
    ips5 = buscar_ips_historicas_viewdns(dominio)
    ips6 = buscar_ips_historicas_securitytrails(dominio)  # antes definida pero nunca llamada

    # Subdominios comúnmente NO proxeados (mail, cpanel, ns1...) -> pista de alto valor
    no_proxeados = buscar_subdominios_no_proxeados(dominio, rangos_cf, threads=args.threads)
    ips7 = [ip for _, ip in no_proxeados]

    todas = list(set(ips1 + ips2 + ips3 + ips5 + ips6 + ips7 + ips_crtsh))
    mostrar_barra_progreso(45)

    candidatas = filtrar_ips_cloudflare(todas, rangos_cf)
    mostrar_barra_progreso(55)

    # Certificado y favicon de referencia del dominio real (vía Cloudflare) para
    # poder comparar contra cada IP candidata más adelante
    fp_referencia = obtener_fingerprint_certificado(dominio, dominio)
    favicon_ref = obtener_favicon_hash(f"https://{dominio}")
    mostrar_barra_progreso(60)

    # Priorización por puertos abiertos (ahora avanzado)
    ip_puertos = []
    for ip in candidatas:
        abiertos = escanear_puertos_avanzado(ip, threads=args.threads)
        if abiertos:
            ip_puertos.append((ip, abiertos))
    ip_puertos.sort(key=lambda x: len(x[1]), reverse=True)
    mostrar_barra_progreso(70)

    # Scoring por confianza: certificado TLS + favicon + headers + tecnologías + puertos
    ranking = evaluar_candidatas(
        dominio, [ip for ip, _ in ip_puertos],
        fp_referencia=fp_referencia, favicon_hash_ref=favicon_ref
    )
    ip_real = ranking[0]["ip"] if ranking else None
    puertos = []
    if ip_real:
        puertos = next((abiertos for ip, abiertos in ip_puertos if ip == ip_real), [])
    mostrar_barra_progreso(90)

    if ranking:
        print("\n\n[ RANKING DE CANDIDATAS POR CONFIANZA ]")
        for r in ranking[:5]:
            print(f"  {r['ip']:<16} score={r['score']:<4} motivos: {', '.join(r['motivos']) or 'ninguno'}")

    if not ip_real:
        print("\n\n[!] No se encontró una IP real fuera de Cloudflare con bypass HTTP.")
        print("[*] IPs candidatas y puertos abiertos detectados:")
        for ip, abiertos in ip_puertos:
            print(f"  {ip} -> Puertos abiertos: {abiertos}")
        sys.exit(1)

    info = obtener_datos_ip(ip_real)
    headers = escanear_headers(ip_real)
    mostrar_barra_progreso(100)

    # WHOIS y DNS history
    whois_info = whois_dns_history(dominio)

    # Fingerprinting de tecnologías web
    tecnologias = detectar_tecnologias(f"http://{ip_real}")

    # Fuzzing de directorios
    fuzz = fuzz_directorios(ip_real, threads=args.threads)

    # Detección de WAF/firewall
    waf = detectar_waf(ip_real)

    # Búsqueda de leaks
    leaks_github = buscar_leaks_github(dominio)
    leaks_pastebin = buscar_leaks_pastebin(dominio)

    # Escaneo de vulnerabilidades
    vulns = escanear_vulnerabilidades(ip_real, puertos)

    print("\n\n\033[1;92m[ RESULTADOS AVANZADOS ]\033[0;0m")
    print(f" Dominio objetivo    : {dominio}")
    print(f" IP Cloudflare       : {cf_ip}")
    print(f" IP real detectada   : {info.get('ip') or 'No disponible'}")
    print(f" PTR Hostname        : {info.get('hostname') if info.get('hostname') and info.get('hostname') != 'PTR no disponible' else 'No disponible'}")
    print(f" Organización        : {info.get('org') if info.get('org') and info.get('org') != 'Desconocido' else 'No disponible'}")
    print(f" ASN                 : {info.get('asn') if info.get('asn') and info.get('asn') != 'N/A' else 'No disponible'}")
    print(f" País                : {info.get('pais') if info.get('pais') and info.get('pais') != 'Desconocido' else 'No disponible'}")
    ubicacion = f"{info.get('region', '')} - {info.get('ciudad', '')} ({info.get('ubicacion', '')})"
    print(f" Ubicación           : {ubicacion if ubicacion.strip(' -()') else 'No disponible'}")
    print(f" Zona horaria        : {info.get('zona') if info.get('zona') else 'No disponible'}")
    print(f" Puertos abiertos    : {puertos if puertos else 'No disponible'}")
    print(f" Server Header       : {headers.get('http://'+ip_real, {}).get('Server') if headers.get('http://'+ip_real, {}).get('Server') and headers.get('http://'+ip_real, {}).get('Server') != 'Desconocido' else 'No disponible'}")
    print(f" X-Powered-By        : {headers.get('http://'+ip_real, {}).get('X-Powered-By') if headers.get('http://'+ip_real, {}).get('X-Powered-By') and headers.get('http://'+ip_real, {}).get('X-Powered-By') != 'Desconocido' else 'No disponible'}")
    print(f" Título HTTP         : {headers.get('http://'+ip_real, {}).get('Title') if headers.get('http://'+ip_real, {}).get('Title') else 'No disponible'}")
    print(f" Server Header HTTPS : {headers.get('https://'+ip_real, {}).get('Server') if headers.get('https://'+ip_real, {}).get('Server') and headers.get('https://'+ip_real, {}).get('Server') != 'Desconocido' else 'No disponible'}")
    print(f" X-Powered-By HTTPS  : {headers.get('https://'+ip_real, {}).get('X-Powered-By') if headers.get('https://'+ip_real, {}).get('X-Powered-By') and headers.get('https://'+ip_real, {}).get('X-Powered-By') != 'Desconocido' else 'No disponible'}")
    print(f" Título HTTPS        : {headers.get('https://'+ip_real, {}).get('Title') if headers.get('https://'+ip_real, {}).get('Title') else 'No disponible'}")
    print(f" Tecnologías Web     : {tecnologias if tecnologias else 'No disponible'}")
    print(f" WAF/Firewall        : {waf if waf and waf != 'No detectado' else 'No disponible'}")
    print(f" Directorios/Archivos: {fuzz if fuzz else 'No disponible'}")
    print(f" Vulnerabilidades    : {vulns if vulns else 'No disponible'}")
    print(f" Leaks GitHub        : {leaks_github if leaks_github else 'No disponible'}")
    print(f" Leaks Pastebin      : {leaks_pastebin if leaks_pastebin else 'No disponible'}")
    print("\n[ WHOIS ]")
    for k, v in whois_info.items():
        print(f"  {k}: {v if v else 'No disponible'}")

    # Antes esta función existía pero nunca se llamaba: las IPs candidatas
    # nunca quedaban guardadas pese a lo que indicaba el README.
    guardar_ips(candidatas, args.output)
    print(f"\n[*] {len(candidatas)} IP(s) candidata(s) guardadas en: {args.output}")

    if args.json:
        resultado = {
            "dominio": dominio,
            "ip_cloudflare": cf_ip,
            "ip_real": info.get("ip"),
            "info_ip": info,
            "puertos_abiertos": puertos,
            "headers": headers,
            "tecnologias": tecnologias,
            "waf": waf,
            "fuzzing": fuzz,
            "vulnerabilidades": vulns,
            "leaks_github": leaks_github,
            "leaks_pastebin": leaks_pastebin,
            "whois": whois_info,
            "ips_candidatas": candidatas,
        }
        with open(args.json, "w") as f:
            json.dump(resultado, f, indent=2, default=str)
        print(f"[*] Resultado completo guardado en: {args.json}")

if __name__ == "__main__":
    main()
