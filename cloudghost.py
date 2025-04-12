#!/usr/bin/env python3
import os
import sys
import re
import requests
import socket
from urllib.parse import urlparse

SHODAN_API_KEY = "api key shodan"

BANNER = """
\033[0;36m       __     
\033[0;36m    __(  )_   \033[1;97m\033[4;37mcloudghost\033[0;0m \033[4;31mv1.0 (Python Edition)\033[0;0m
\033[0;36m __(       )_   \033[0;0mAuthor: @Zuk4r1 
\033[0;36m(____________)  \033[0;0mDetecta IP real tras Cloudflare (OSINT + SHODAN + PTR)
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

def buscar_subdominios(domain):
    try:
        print("[*] Buscando subdominios vía Hackertarget...")
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        ips = set()
        for line in r.text.splitlines():
            partes = line.split(",")
            if len(partes) == 2:
                ips.add(partes[1].strip())
        return list(ips)
    except Exception as e:
        print(f"[!] Error subdominios: {e}")
        return []

def consultar_shodan(domain):
    try:
        print("[*] Consultando Shodan...")
        r = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}")
        data = r.json()
        ips = set()
        for sub in data.get("subdomains", []):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                ips.add(ip)
            except:
                continue
        return list(ips)
    except Exception as e:
        print(f"[!] Error con Shodan: {e}")
        return []

def dns_ptr_lookup(ip):
    try:
        ptr = socket.gethostbyaddr(ip)
        return ptr[0]
    except:
        return "PTR no disponible"

def obtener_datos_ip(ip):
    try:
        geojs = requests.get(f"https://get.geojs.io/v1/ip/country/{ip}.json").json()
        ipinfo = requests.get(f"https://ipinfo.io/{ip}/json?token=51a986ffa5ddb1").json()

        return {
            "ip": ipinfo.get("ip"),
            "org": ipinfo.get("org", "Desconocido"),
            "hostname": dns_ptr_lookup(ip),
            "pais": geojs.get("name", "Desconocido"),
            "ubicacion": ipinfo.get("loc", ""),
            "direccion": f"{ipinfo.get('country')}, {ipinfo.get('region')}, {ipinfo.get('city')}",
            "timezone": ipinfo.get("timezone", "Desconocido")
        }
    except Exception as e:
        print(f"[!] Error obteniendo datos IP: {e}")
        return {}

def detectar_nameservers(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except:
        return []

def filtrar_ips_cloudflare(ips):
    cf_ranges = [
        "104.", "172.", "173.", "162.", "188.", "198.", "190."
    ]
    return [ip for ip in ips if not any(ip.startswith(prefijo) for prefijo in cf_ranges)]

def main():
    os.system("clear")
    print(BANNER)

    if len(sys.argv) != 2:
        print("Uso: python3 cloudpeler_v27.py <dominio.com>")
        sys.exit(1)

    dominio = limpiar_url(sys.argv[1])
    print(f"\n[+] Escaneando: {dominio}")
    mostrar_barra_progreso(20)

    cf_ip = socket.gethostbyname(dominio)
    mostrar_barra_progreso(40)

    sub_ips = buscar_subdominios(dominio)
    shodan_ips = consultar_shodan(dominio)
    mostrar_barra_progreso(60)

    todas = list(set(sub_ips + shodan_ips))
    candidatas = filtrar_ips_cloudflare(todas)
    mostrar_barra_progreso(80)

    if not candidatas:
        print("\n\n[!] No se encontró una IP real fuera de Cloudflare.")
        sys.exit(1)

    real_ip = candidatas[0]
    datos = obtener_datos_ip(real_ip)
    mostrar_barra_progreso(100)

    nameservers = detectar_nameservers(dominio)

    print("\n\n\033[1;92m[ RESULTADOS ]\033[0;0m")
    print(f" Dominio objetivo    : {dominio}")
    print(f" IP detrás de CF     : {cf_ip}")
    print(f" Nameservers         : {', '.join(nameservers) if nameservers else 'No detectados'}")
    print(f" IP real detectada   : {datos.get('ip')} (vía OSINT + SHODAN)")
    print(f" Hostname PTR        : {datos.get('hostname')}")
    print(f" Organización        : {datos.get('org')}")
    print(f" País                : {datos.get('pais')}")
    print(f" Ubicación           : {datos.get('ubicacion')}")
    print(f" Dirección           : {datos.get('direccion')}")
    print(f" Zona horaria        : {datos.get('timezone')}")

if __name__ == "__main__":
    main()
