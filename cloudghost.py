#!/usr/bin/env python3
import os
import sys
import requests
import socket
import dns.resolver
from urllib.parse import urlparse
from collections import defaultdict
import json
import time
import ipaddress
import re
import whois
import threading
import random

# API KEYS (coloca aquí tus claves)
ZOOMEYE_API_KEY = "API_KEY"
SHODAN_API_KEY = "API_KEY"
IPINFO_TOKEN = "API_KEY"
SECURITYTRAILS_API_KEY = "API_KEY"
VIRUSTOTAL_API_KEY = "API_KEY"
WORKERS_AI_USER_ID = "API_KEY"
WORKERS_AI_API_KEY = "API_KEY"
# ...puedes agregar aquí más claves si usas otros servicios...

BANNER = """
\033[0;36m       __     
\033[0;36m    __(  )_      \033[1;97m\033[4;37mCloudGhost Modo Ninja OSINT\033[0;0m \033[4;31mv3.6\033[0;0m
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
    "2a09:bac1::/29",
    "2a09:bac2::/31",
    "2a09:bac4::/30",
    "2a09:bac8::/29",
    "2a09:bac10::/28",
    "2a09:bac20::/27",
    "2a09:bac40::/26",
    "2a09:bac80::/25",
    "2a09:bac100::/24",
    "2a09:bac200::/23",
    "2a09:bac400::/22",
    "2a09:bac800::/21",
    "2a09:bac1000::/20",
    "2a09:bac2000::/19",
    "2a09:bac4000::/18",
    "2a09:bac8000::/17",
    "2a09:bac10000::/16",
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

def resolucion_dns_masiva(subdominios):
    print("[*] Resolviendo subdominios (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR)...")
    ips = set()
    hosts = set()
    tipos = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'SRV', 'PTR']
    for sub in subdominios:
        for rtype in tipos:
            try:
                answers = dns.resolver.resolve(sub, rtype, lifetime=5)
                for rdata in answers:
                    if rtype == 'A':
                        ips.add(rdata.address)
                    elif rtype == 'AAAA':
                        ips.add(rdata.address)
                    elif rtype == 'MX':
                        hosts.add(str(rdata.exchange).rstrip('.'))
                    elif rtype == 'CNAME':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'NS':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'SOA':
                        hosts.add(str(rdata.mname).rstrip('.'))
                    elif rtype == 'SRV':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'PTR':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'TXT':
                        txt = str(rdata)
                        # Busca IPs y dominios en TXT
                        for part in txt.split():
                            if part.count('.') == 3 and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', part.strip('"')):
                                ips.add(part.strip('"'))
                            elif '.' in part:
                                hosts.add(part.strip('"'))
            except Exception:
                continue
    # Intenta resolver hosts adicionales encontrados (más agresivo y recursivo)
    for host in list(hosts):
        try:
            ip_list = socket.gethostbyname_ex(host)[2]
            for ip in ip_list:
                ips.add(ip)
        except:
            continue
        # Intenta resolver CNAMEs y MXs como hosts también
        try:
            cname_answers = dns.resolver.resolve(host, 'CNAME')
            for cname in cname_answers:
                cname_host = str(cname.target).rstrip('.')
                try:
                    ip_cname = socket.gethostbyname(cname_host)
                    ips.add(ip_cname)
                except:
                    pass
        except:
            pass
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
        return {
            "ip": info.get("ip"),
            "org": info.get("org", "Desconocido"),
            "asn": info.get("asn", {}).get("asn", "N/A"),
            "hostname": dns_ptr_lookup(ip),
            "pais": info.get("country", "Desconocido"),
            "ubicacion": info.get("loc", ""),
            "ciudad": info.get("city", ""),
            "region": info.get("region", ""),
            "zona": info.get("timezone", "")
        }
    except:
        return {}

def escanear_headers(domain_or_ip):
    print(f"[*] Analizando headers para {domain_or_ip} (HTTP y HTTPS, agresivo)...")
    resultados = {}
    urls = [f"http://{domain_or_ip}", f"https://{domain_or_ip}"]
    for url in urls:
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, verify=False, allow_redirects=True)
            resultados[url] = {
                "Server": r.headers.get("Server", "Desconocido"),
                "X-Powered-By": r.headers.get("X-Powered-By", "Desconocido"),
                "Title": re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE).group(1) if "<title>" in r.text else "",
                "Location": r.headers.get("Location", ""),
                "Set-Cookie": r.headers.get("Set-Cookie", "")
            }
        except:
            resultados[url] = {"Server": "Error", "X-Powered-By": "Error", "Title": "", "Location": "", "Set-Cookie": ""}
    return resultados

def ip_in_cloudflare(ip):
    try:
        # Validar que ip no sea None, vacía, ni un hostname
        if not ip or not isinstance(ip, str):
            return False
        # Solo aceptar IPv4 o IPv6 válidas
        ip_obj = ipaddress.ip_address(ip)
        for net in CLOUDFLARE_RANGES:
            if ip_obj in ipaddress.ip_network(net):
                return True
    except Exception:
        # Si no es una IP válida, no está en Cloudflare
        return False
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

def buscar_subdominios_threatcrowd(domain):
    print("[*] Buscando subdominios en ThreatCrowd...")
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}")
        data = r.json()
        return data.get("subdomains", [])
    except:
        return []

def escanear_puertos(ip, puertos=[80, 443, 8080, 8443, 22, 21, 25]):
    abiertos = []
    for puerto in puertos:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            if s.connect_ex((ip, puerto)) == 0:
                abiertos.append(puerto)
            s.close()
        except:
            continue
    return abiertos

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

def guardar_ips(ips):
    with open("ips_detectadas.txt", "w") as f:
        for ip in ips:
            f.write(ip + "\n")

def resolucion_dns_avanzada(subdominios):
    print("[*] Resolución DNS avanzada (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR, agresivo)...")
    ips = set()
    hosts = set()
    tipos = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'SRV', 'PTR']
    for sub in subdominios:
        for rtype in tipos:
            try:
                answers = dns.resolver.resolve(sub, rtype, lifetime=7)
                for rdata in answers:
                    if rtype == 'A':
                        ips.add(rdata.address)
                    elif rtype == 'AAAA':
                        ips.add(rdata.address)
                    elif rtype == 'MX':
                        hosts.add(str(rdata.exchange).rstrip('.'))
                    elif rtype == 'CNAME':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'NS':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'SOA':
                        hosts.add(str(rdata.mname).rstrip('.'))
                    elif rtype == 'SRV':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'PTR':
                        hosts.add(str(rdata.target).rstrip('.'))
                    elif rtype == 'TXT':
                        txt = str(rdata)
                        # Busca IPs y dominios en TXT
                        for part in txt.split():
                            if part.count('.') == 3 and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', part.strip('"')):
                                ips.add(part.strip('"'))
                            elif '.' in part:
                                hosts.add(part.strip('"'))
            except Exception:
                continue
    # Intenta resolver hosts adicionales encontrados (más agresivo y recursivo)
    for host in list(hosts):
        try:
            ip_list = socket.gethostbyname_ex(host)[2]
            for ip in ip_list:
                ips.add(ip)
        except:
            continue
        # Intenta resolver CNAMEs y MXs como hosts también
        try:
            cname_answers = dns.resolver.resolve(host, 'CNAME')
            for cname in cname_answers:
                cname_host = str(cname.target).rstrip('.')
                try:
                    ip_cname = socket.gethostbyname(cname_host)
                    ips.add(ip_cname)
                except:
                    pass
        except:
            pass
    return list(ips)

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

def filtrar_ips_cloudflare(ips):
    return [ip for ip in ips if not ip_in_cloudflare(ip)]

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
    print(f"[*] Fingerprinting de tecnologías web en {url}...")
    tecnologias = set()
    try:
        r = requests.get(url, headers=random_headers(), timeout=8, verify=False, allow_redirects=True)
        headers = r.headers
        html = r.text
        # Detección básica por headers
        if "x-powered-by" in headers:
            tecnologias.add(headers["x-powered-by"])
        if "server" in headers:
            tecnologias.add(headers["server"])
        # Detección por HTML
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
        # ...puedes añadir más firmas...
    except:
        pass
    return list(tecnologias)

def fuzz_directorios(domain_or_ip, wordlist=None):
    print(f"[*] Fuzzing de directorios y archivos comunes en {domain_or_ip}...")
    if wordlist is None:
        wordlist = ["admin", "login", "config", ".env", "phpinfo.php", "backup", "test", "old", "dev", "api", "robots.txt"]
    encontrados = []
    for proto in ["http", "https"]:
        for word in wordlist:
            url = f"{proto}://{domain_or_ip}/{word}"
            try:
                r = requests.get(url, headers=random_headers(), timeout=4, verify=False, allow_redirects=False)
                if r.status_code in [200, 301, 302, 403]:
                    encontrados.append((url, r.status_code))
            except:
                continue
    return encontrados

def detectar_waf(domain_or_ip):
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
        # ...puedes añadir más firmas...
    }
    try:
        r = requests.get(f"http://{domain_or_ip}", headers=random_headers(), timeout=5, verify=False)
        headers = str(r.headers).lower()
        html = r.text.lower()
        for nombre, firmas in wafs.items():
            for firma in firmas:
                if firma in headers or firma in html:
                    return nombre
    except:
        pass
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
    print(f"[*] Buscando posibles leaks en Pastebin para {domain}...")
    leaks = []
    try:
        r = requests.get(f"https://scrape.pastebin.com/api_scraping.php?limit=50", timeout=10)
        if r.status_code == 200:
            data = r.json()
            for item in data:
                if domain in item.get("title", "") or domain in item.get("key", ""):
                    leaks.append(item.get("scrape_url"))
    except:
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

def main():
    os.system("clear")
    print(BANNER)

    if len(sys.argv) != 2:
        print("Uso: python3 cloudghost.py <dominio.com>")
        sys.exit(1)

    dominio = limpiar_url(sys.argv[1])
    print(f"\n[+] Escaneando: {dominio}")
    mostrar_barra_progreso(5)

    cf_ip = socket.gethostbyname(dominio)
    mostrar_barra_progreso(10)

    # crt.sh mejorado
    sub1, ips_crtsh = buscar_certificados_crtsh(dominio)
    sub2 = buscar_en_wayback(dominio)
    sub3 = buscar_subdominios_virustotal(dominio)
    sub4 = buscar_subdominios_threatcrowd(dominio)
    subdominios = list(set(sub1 + sub2 + sub3 + sub4))
    mostrar_barra_progreso(20)

    # DNS masiva mejorada
    ips1 = resolucion_dns_masiva(subdominios)
    ips2 = consultar_shodan(dominio)
    ips3 = consultar_zoom_eye(dominio)
    ips4 = resolucion_dns_avanzada(subdominios)
    ips5 = buscar_ips_historicas_viewdns(dominio)
    todas = list(set(ips1 + ips2 + ips3 + ips4 + ips5 + ips_crtsh))
    mostrar_barra_progreso(50)

    candidatas = filtrar_ips_cloudflare(todas)
    mostrar_barra_progreso(60)

    # Priorización por puertos abiertos (ahora avanzado)
    ip_puertos = []
    for ip in candidatas:
        abiertos = escanear_puertos_avanzado(ip)
        if abiertos:
            ip_puertos.append((ip, abiertos))
    ip_puertos.sort(key=lambda x: len(x[1]), reverse=True)
    mostrar_barra_progreso(70)

    # Escaneo de puertos y bypass HTTP
    ip_real = None
    puertos = []
    for ip, abiertos in ip_puertos:
        if intentar_bypass_http(dominio, ip):
            ip_real = ip
            puertos = abiertos
            break
    mostrar_barra_progreso(90)

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
    fuzz = fuzz_directorios(ip_real)

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
    print(f" IP real detectada   : {info.get('ip')}")
    print(f" PTR Hostname        : {info.get('hostname')}")
    print(f" Organización        : {info.get('org')}")
    print(f" ASN                 : {info.get('asn')}")
    print(f" País                : {info.get('pais')}")
    print(f" Ubicación           : {info.get('region')} - {info.get('ciudad')} ({info.get('ubicacion')})")
    print(f" Zona horaria        : {info.get('zona')}")
    print(f" Puertos abiertos    : {puertos}")
    print(f" Server Header       : {headers.get('http://'+ip_real, {}).get('Server', '')}")
    print(f" X-Powered-By        : {headers.get('http://'+ip_real, {}).get('X-Powered-By', '')}")
    print(f" Título HTTP         : {headers.get('http://'+ip_real, {}).get('Title', '')}")
    print(f" Server Header HTTPS : {headers.get('https://'+ip_real, {}).get('Server', '')}")
    print(f" X-Powered-By HTTPS  : {headers.get('https://'+ip_real, {}).get('X-Powered-By', '')}")
    print(f" Título HTTPS        : {headers.get('https://'+ip_real, {}).get('Title', '')}")
    print(f" Tecnologías Web     : {tecnologias}")
    print(f" WAF/Firewall        : {waf}")
    print(f" Directorios/Archivos: {fuzz}")
    print(f" Vulnerabilidades    : {vulns}")
    print(f" Leaks GitHub        : {leaks_github}")
    print(f" Leaks Pastebin      : {leaks_pastebin}")
    print("\n[ WHOIS ]")
    for k, v in whois_info.items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
