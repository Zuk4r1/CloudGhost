#!/usr/bin/env python3
import os
import sys
import requests
import socket
import dns.resolver
from urllib.parse import urlparse
from collections import defaultdict

SHODAN_API_KEY = "FeO26aRMu5NaNf0DzMDHO6Uztb6IbIiR"
IPINFO_TOKEN = "7db7570300e984"
ZOOMEYE_API_KEY = "CD103Dd3-5D25-79163-3A7B-A8c0862d1c1c"

BANNER = """
\033[0;36m       __     
\033[0;36m    __(  )_      \033[1;97m\033[4;37mCloudGhost Modo Ninja OSINT\033[0;0m \033[4;31mv1.3\033[0;0m
\033[0;36m __(       )__   \033[0;0mAuthor:\033[4;31m@Zuk4r1
\033[0;36m(_____________)  \033[0;0mDetecta IP real tras Cloudflare
\033[0;36m  /⚡/⚡/⚡/    \033[0;0m
"""

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
}

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
    print("[*] Extrayendo subdominios desde crt.sh...")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        resultados = r.json()
        subdominios = set()
        for entry in resultados:
            nombre = entry.get("name_value", "")
            for sub in nombre.split("\n"):
                if domain in sub:
                    subdominios.add(sub.strip())
        return list(subdominios)
    except:
        return []

def buscar_en_wayback(domain):
    print("[*] Buscando URLs filtradas en Wayback Machine...")
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey", timeout=10)
        data = r.json()[1:]  # Skip header
        return [d[0] for d in data if any(ext in d[0] for ext in ["robots.txt", "config.js"])]
    except:
        return []

def resolucion_dns_masiva(subdominios):
    print("[*] Resolviendo subdominios...")
    ips = set()
    for sub in subdominios:
        try:
            answers = dns.resolver.resolve(sub, 'A')
            for rdata in answers:
                ips.add(rdata.address)
        except:
            continue
    return list(ips)

def consultar_shodan(domain):
    print("[*] Consultando Shodan...")
    try:
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

def escanear_headers(domain):
    try:
        r = requests.get(f"http://{domain}", headers=HEADERS, timeout=5)
        return {
            "Server": r.headers.get("Server", "Desconocido"),
            "X-Powered-By": r.headers.get("X-Powered-By", "Desconocido")
        }
    except:
        return {"Server": "Error", "X-Powered-By": "Error"}

def filtrar_ips_cloudflare(ips):
    rangos_cf = ["104.", "172.", "173.", "162.", "188.", "198.", "190.",
        "103.21.", "103.22.", "103.31.", "141.101.", "108.162.",
        "190.93.", "188.114.", "197.234.", "198.41."]
    return [ip for ip in ips if not any(ip.startswith(pref) for pref in rangos_cf)]

def guardar_ips(ips):
    with open("ips_detectadas.txt", "w") as f:
        for ip in ips:
            f.write(ip + "\n")

def main():
    os.system("clear")
    print(BANNER)

    if len(sys.argv) != 2:
        print("Uso: python3 cloudghost.py <dominio.com>")
        sys.exit(1)

    dominio = limpiar_url(sys.argv[1])
    print(f"\n[+] Escaneando: {dominio}")
    mostrar_barra_progreso(10)

    cf_ip = socket.gethostbyname(dominio)
    mostrar_barra_progreso(20)

    sub1 = buscar_certificados_crtsh(dominio)
    sub2 = buscar_en_wayback(dominio)
    mostrar_barra_progreso(40)

    ips1 = resolucion_dns_masiva(sub1 + sub2)
    ips2 = consultar_shodan(dominio)
    ips3 = consultar_zoom_eye(dominio)
    mostrar_barra_progreso(70)

    todas = list(set(ips1 + ips2 + ips3))
    guardar_ips(todas)
    candidatas = filtrar_ips_cloudflare(todas)
    mostrar_barra_progreso(90)

    if not candidatas:
        print("\n\n[!] No se encontró una IP real fuera de Cloudflare.")
        sys.exit(1)

    real_ip = candidatas[0]
    info = obtener_datos_ip(real_ip)
    headers = escanear_headers(dominio)
    mostrar_barra_progreso(100)

    print("\n\n\033[1;92m[ RESULTADOS ]\033[0;0m")
    print(f" Dominio objetivo    : {dominio}")
    print(f" IP Cloudflare       : {cf_ip}")
    print(f" IP real detectada   : {info.get('ip')}")
    print(f" PTR Hostname        : {info.get('hostname')}")
    print(f" Organización        : {info.get('org')}")
    print(f" ASN                 : {info.get('asn')}")
    print(f" País                : {info.get('pais')}")
    print(f" Ubicación           : {info.get('region')} - {info.get('ciudad')} ({info.get('ubicacion')})")
    print(f" Zona horaria        : {info.get('zona')}")
    print(f" Server Header       : {headers['Server']}")
    print(f" X-Powered-By        : {headers['X-Powered-By']}")

if __name__ == "__main__":
    main()
