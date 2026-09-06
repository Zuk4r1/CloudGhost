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
import asyncio
import hashlib

try:
    import aiohttp
    AIOHTTP_DISPONIBLE = True
except ImportError:
    AIOHTTP_DISPONIBLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ZOOMEYE_API_KEY = os.getenv("ZOOMEYE_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
CENSYS_PAT = os.getenv("CENSYS_PAT", "")
CENSYS_ORG_ID = os.getenv("CENSYS_ORG_ID", "")

DEFAULT_THREADS = 30

BANNER = """
\033[0;36m       __     
\033[0;36m    __(  )_      \033[1;97m\033[4;37mCloudGhost Modo Ninja OSINT\033[0;0m \033[4;31mv4.0\033[0;0m
\033[0;36m __(       )__   \033[0;0mAuthor:\033[4;31m@Zuk4r1
\033[0;36m(_____________)  \033[0;0mDescubre la IP real tras CUALQUIER WAF/CDN
\033[0;36m  /⚡/⚡/⚡/    \033[0;0m
"""

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0)"
]


PROXIES = [
    None,
]

PROXY_CONFIG = {}

SESSION = requests.Session()

_adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
SESSION.mount("http://", _adapter)
SESSION.mount("https://", _adapter)

REINTENTOS_HTTP = 2
BACKOFF_BASE_SEGUNDOS = 0.5

def _con_reintentos(func, url, **kwargs):
    kwargs.setdefault("proxies", PROXY_CONFIG)
    ultimo_error = None
    for intento in range(REINTENTOS_HTTP + 1):
        try:
            return func(url, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            ultimo_error = e
            if intento < REINTENTOS_HTTP:
                time.sleep(BACKOFF_BASE_SEGUNDOS * (2 ** intento))
                continue
            raise
    raise ultimo_error

def http_get(url, **kwargs):
    return _con_reintentos(SESSION.get, url, **kwargs)

def http_post(url, **kwargs):
    return _con_reintentos(SESSION.post, url, **kwargs)

CLOUDFLARE_RANGES = [
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

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "cloudghost")
CACHE_TTL_SEGUNDOS = 6 * 3600  # 6 horas

def _cache_ruta(clave):
    os.makedirs(CACHE_DIR, exist_ok=True)
    nombre = hashlib.sha256(clave.encode("utf-8")).hexdigest() + ".json"
    return os.path.join(CACHE_DIR, nombre)

def cache_get(clave):
    ruta = _cache_ruta(clave)
    try:
        if os.path.exists(ruta) and (time.time() - os.path.getmtime(ruta)) < CACHE_TTL_SEGUNDOS:
            with open(ruta, encoding="utf-8") as f:
                return json.load(f)
    except (OSError, ValueError):
        pass
    return None

def cache_set(clave, valor):
    try:
        with open(_cache_ruta(clave), "w", encoding="utf-8") as f:
            json.dump(valor, f)
    except (OSError, TypeError):
        pass  # valores no serializables (ej. objetos response) simplemente no se cachean

def limpiar_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).netloc

def obtener_todos_los_a_records(dominio, timeout=5):

    ips = set()
    for tipo in ("A", "AAAA"):
        try:
            for rdata in dns.resolver.resolve(dominio, tipo, lifetime=timeout):
                ips.add(rdata.address)
        except dns.exception.DNSException:
            continue
    return ips

def mostrar_barra_progreso(porcentaje, tarea=""):
    largo_total = 40
    largo_lleno = int(porcentaje / 100 * largo_total)
    barra = "[" + "#" * largo_lleno + "-" * (largo_total - largo_lleno) + "]"
    etiqueta = f" {tarea}" if tarea else ""
    # \x1b[K borra el resto de la línea: si la etiqueta anterior era más larga
    # que la actual, no quedan caracteres viejos pegados al final.
    print(f"\r{barra} {porcentaje:6.2f}%{etiqueta}\x1b[K", end="", flush=True)

def buscar_certificados_crtsh(domain):
    print("[*] Extrayendo subdominios y posibles IPs desde crt.sh (agresivo y recursivo)...")
    subdominios = set()
    ips = set()
    try:
        r = http_get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        resultados = r.json()
        for entry in resultados:
            nombre = entry.get("name_value", "")
            for sub in nombre.split("\n"):
                if domain in sub:
                    subdominios.add(sub.strip())

        for sub in subdominios:
            try:
                ip = socket.gethostbyname(sub)
                ips.add(ip)
            except:
                found_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', sub)
                for ip in found_ips:
                    ips.add(ip)
                continue

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
        r = http_get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey", timeout=10)
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
                        if clean.lower().startswith(("ip4:", "ip6:")):
                            clean = clean.split(":", 1)[1].split("/", 1)[0]
                        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', clean):
                            ips_local.add(clean)
                        elif re.match(r'^[0-9a-fA-F:]+$', clean) and ':' in clean:
                            ips_local.add(clean)  # IPv6 desde ip6: en SPF
                        elif '.' in clean and not clean.lower().startswith(
                            ("v=spf1", "include:", "redirect=", "exists:", "a:", "mx:")
                        ):
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
        r = http_get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": SHODAN_API_KEY},
            timeout=10,
        )
        data = r.json()
        sub_ips = set()
        for sub in data.get("subdomains", []):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                sub_ips.add(ip)
            except:
                continue

        r2 = http_get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_API_KEY, "query": f"hostname:{domain}"},
            timeout=10,
        )
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
        r = http_get(f"https://api.zoomeye.org/host/search?query=hostname:{domain}", headers=headers)
        data = r.json()
        return [hit["ip"] for hit in data.get("matches", []) if "ip" in hit]
    except:
        return []

def _extraer_ips_de_json(data):

    ips = set()
    claves_ip = {"ip", "host_id", "ip_address"}

    def recorrer(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in claves_ip and isinstance(v, str):
                    try:
                        ipaddress.ip_address(v)
                        ips.add(v)
                    except ValueError:
                        pass
                else:
                    recorrer(v)
        elif isinstance(obj, list):
            for item in obj:
                recorrer(item)

    recorrer(data)
    return list(ips)

def consultar_censys_por_certificado(fingerprint_sha256_hex):

    if not CENSYS_PAT or not fingerprint_sha256_hex:
        return []
    print("[*] Consultando Censys Platform API por coincidencia de certificado TLS...")
    try:
        url = "https://api.platform.censys.io/v3/global/search/query"
        params = {"organization_id": CENSYS_ORG_ID} if CENSYS_ORG_ID else {}
        headers = {
            "Authorization": f"Bearer {CENSYS_PAT}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = {"query": f'host.services.cert.fingerprint_sha256: "{fingerprint_sha256_hex}"'}
        r = http_post(url, params=params, headers=headers, json=body, timeout=15)
        if r.status_code == 401:
            print("    [!] Censys devolvió 401 (no autorizado). El PAT puede ser inválido, o si tu "
                  "cuenta usa un flujo distinto, prueba enviar el header 'Authorization' sin el "
                  "prefijo 'Bearer ' (la documentación oficial indica Bearer, pero algunos ejemplos "
                  "de la comunidad de Censys muestran el token crudo).")
            return []
        if r.status_code == 403:
            print("    [!] Censys devolvió 403 — revisa el PAT y, si tu cuenta es de pago, CENSYS_ORG_ID.")
            return []
        if r.status_code != 200:
            print(f"    [!] Censys devolvió {r.status_code} — sin resultados de esta fuente.")
            return []
        ips = _extraer_ips_de_json(r.json())
        if ips:
            print(f"    [+] Censys: {len(ips)} host(s) sirviendo el mismo certificado TLS.")
        return ips
    except (requests.RequestException, ValueError):
        return []

def dns_ptr_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "PTR no disponible"

async def _async_get_json(session, url, **kwargs):
    async with session.get(url, **kwargs) as r:
        try:
            return r.status, await r.json(content_type=None)
        except Exception:
            return r.status, None

async def buscar_certificados_crtsh_async(session, domain):
    subdominios, ips = set(), set()
    try:
        status, data = await _async_get_json(
            session, f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=aiohttp.ClientTimeout(total=25)
        )
        if data:
            for entry in data:
                nombre = entry.get("name_value", "")
                for sub in nombre.split("\n"):
                    if domain in sub:
                        subdominios.add(sub.strip())
    except Exception:
        pass
    if subdominios:
        loop = asyncio.get_event_loop()

        async def resolver(sub):
            try:
                return await loop.run_in_executor(None, socket.gethostbyname, sub)
            except OSError:
                encontrados = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', sub)
                return encontrados[0] if encontrados else None

        resueltas = await asyncio.gather(*(resolver(s) for s in subdominios))
        ips.update(ip for ip in resueltas if ip)
    return list(subdominios), list(ips)

async def buscar_en_wayback_async(session, domain):
    try:
        status, data = await _async_get_json(
            session,
            f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
            timeout=aiohttp.ClientTimeout(total=10)
        )
        if data:
            data = data[1:]  # Skip header
            return [d[0] for d in data if any(ext in d[0] for ext in ["robots.txt", "config.js"])]
    except Exception:
        pass
    return []

async def buscar_subdominios_virustotal_async(session, domain):
    try:
        status, data = await _async_get_json(
            session, f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=aiohttp.ClientTimeout(total=15)
        )
        if status == 200 and data:
            return [item["id"] for item in data.get("data", [])]
    except Exception:
        pass
    return []

async def buscar_subdominios_otx_async(session, domain):
    try:
        status, data = await _async_get_json(
            session, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=aiohttp.ClientTimeout(total=10)
        )
        if status == 200 and data:
            hosts = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname")
                if hostname and domain in hostname:
                    hosts.add(hostname)
            return list(hosts)
    except Exception:
        pass
    return []

async def buscar_subdominios_securitytrails_async(session, domain):
    try:
        status, data = await _async_get_json(
            session, f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            headers={"APIKEY": SECURITYTRAILS_API_KEY}, timeout=aiohttp.ClientTimeout(total=15)
        )
        if status == 200 and data:
            return [f"{sub}.{domain}" for sub in data.get("subdomains", [])]
    except Exception:
        pass
    return []

async def consultar_shodan_async(session, domain):
    sub_ips = set()
    try:
        status, data = await _async_get_json(
            session, "https://api.shodan.io/dns/domain/" + domain,
            params={"key": SHODAN_API_KEY}, timeout=aiohttp.ClientTimeout(total=10)
        )
        if data and data.get("subdomains"):
            loop = asyncio.get_event_loop()

            async def resolver(fqdn):
                try:
                    return await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                except OSError:
                    return None

            fqdns = [f"{sub}.{domain}" for sub in data["subdomains"]]
            resueltas = await asyncio.gather(*(resolver(f) for f in fqdns))
            sub_ips.update(ip for ip in resueltas if ip)

        status2, data2 = await _async_get_json(
            session, "https://api.shodan.io/shodan/host/search",
            params={"key": SHODAN_API_KEY, "query": f"hostname:{domain}"},
            timeout=aiohttp.ClientTimeout(total=10)
        )
        if status2 == 200 and data2:
            for match in data2.get("matches", []):
                ip = match.get("ip_str")
                if ip:
                    sub_ips.add(ip)
    except Exception:
        pass
    return list(sub_ips)

async def consultar_zoom_eye_async(session, domain):
    try:
        status, data = await _async_get_json(
            session, f"https://api.zoomeye.org/host/search?query=hostname:{domain}",
            headers={"Authorization": f"JWT {ZOOMEYE_API_KEY}"}, timeout=aiohttp.ClientTimeout(total=10)
        )
        if data:
            return [hit["ip"] for hit in data.get("matches", []) if "ip" in hit]
    except Exception:
        pass
    return []

async def buscar_ips_historicas_securitytrails_async(session, domain):
    try:
        status, data = await _async_get_json(
            session, f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": SECURITYTRAILS_API_KEY}, timeout=aiohttp.ClientTimeout(total=10)
        )
        if status == 200 and data:
            ips = []
            for record in data.get("records", []):
                for value in record.get("values", []):
                    ip = value.get("ip")
                    if ip:
                        ips.append(ip)
            return ips
    except Exception:
        pass
    return []

async def buscar_ips_historicas_viewdns_async(session, domain):
    try:
        async with session.get(f"https://viewdns.info/iphistory/?domain={domain}",
                                timeout=aiohttp.ClientTimeout(total=15)) as r:
            texto = await r.text()
        lines = texto.splitlines()
        ips = []
        for line in lines:
            ips.extend(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line))
        hosts = set(re.findall(r'([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')', "\n".join(lines)))
        if hosts:
            loop = asyncio.get_event_loop()

            async def resolver(h):
                try:
                    return await loop.run_in_executor(None, socket.gethostbyname, h)
                except OSError:
                    return None

            resueltas = await asyncio.gather(*(resolver(h) for h in hosts))
            ips.extend(ip for ip in resueltas if ip)
        return list(set(ips))
    except Exception:
        return []

async def consultar_censys_por_certificado_async(session, fingerprint_sha256_hex):
    if not CENSYS_PAT or not fingerprint_sha256_hex:
        return []
    try:
        params = {"organization_id": CENSYS_ORG_ID} if CENSYS_ORG_ID else {}
        headers = {
            "Authorization": f"Bearer {CENSYS_PAT}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = {"query": f'host.services.cert.fingerprint_sha256: "{fingerprint_sha256_hex}"'}
        async with session.post("https://api.platform.censys.io/v3/global/search/query",
                                 params=params, headers=headers, json=body,
                                 timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                return []
            data = await r.json(content_type=None)
        return _extraer_ips_de_json(data)
    except Exception:
        return []

def _resultado_esta_vacio(resultado):

    if isinstance(resultado, tuple):
        return all(_resultado_esta_vacio(r) for r in resultado)
    return not resultado

async def _tarea_con_cache_y_nombre(nombre, dominio, corutina, valor_por_defecto):
    clave = f"{nombre}:{dominio}"
    cacheado = cache_get(clave)
    if cacheado is not None:
        return nombre, cacheado
    try:
        resultado = await corutina
    except Exception:
        resultado = valor_por_defecto

    if not _resultado_esta_vacio(resultado):
        cache_set(clave, resultado)
    return nombre, resultado

async def recolectar_fuentes_async(dominio, fp_referencia):
    proxy = PROXY_CONFIG.get("http") or PROXY_CONFIG.get("https")

    if proxy and proxy.startswith("socks"):
        print("[!] --proxy socks5:// no aplica a la fase async de recolección OSINT (limitación de aiohttp); "
              "sí se respeta en el resto de la herramienta.")
        proxy = None

    connector = aiohttp.TCPConnector(limit=20)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=HEADERS) as session:
        tareas_def = {
            "crt.sh": (buscar_certificados_crtsh_async(session, dominio), ([], [])),
            "wayback": (buscar_en_wayback_async(session, dominio), []),
            "virustotal": (buscar_subdominios_virustotal_async(session, dominio), []),
            "otx": (buscar_subdominios_otx_async(session, dominio), []),
            "securitytrails_sub": (buscar_subdominios_securitytrails_async(session, dominio), []),
            "shodan": (consultar_shodan_async(session, dominio), []),
            "zoomeye": (consultar_zoom_eye_async(session, dominio), []),
            "viewdns_hist": (buscar_ips_historicas_viewdns_async(session, dominio), []),
            "securitytrails_hist": (buscar_ips_historicas_securitytrails_async(session, dominio), []),
            "censys": (consultar_censys_por_certificado_async(session, fp_referencia), []),
        }
        futuros = [
            asyncio.ensure_future(_tarea_con_cache_y_nombre(nombre, dominio, coro, default))
            for nombre, (coro, default) in tareas_def.items()
        ]
        resultados = {}
        total = len(futuros)
        completadas = 0
        for fut in asyncio.as_completed(futuros):
            nombre, resultado = await fut
            resultados[nombre] = resultado
            completadas += 1
            mostrar_barra_progreso(20 + int(15 * completadas / total),
                                    f"Fuente OSINT completada: {nombre} ({completadas}/{total})")
        return resultados

def recolectar_fuentes_fallback_sync(dominio, fp_referencia):

    return {
        "crt.sh": buscar_certificados_crtsh(dominio),
        "wayback": buscar_en_wayback(dominio),
        "virustotal": buscar_subdominios_virustotal(dominio),
        "otx": buscar_subdominios_otx(dominio),
        "securitytrails_sub": buscar_subdominios_securitytrails(dominio),
        "shodan": consultar_shodan(dominio),
        "zoomeye": consultar_zoom_eye(dominio),
        "viewdns_hist": buscar_ips_historicas_viewdns(dominio),
        "securitytrails_hist": buscar_ips_historicas_securitytrails(dominio),
        "censys": consultar_censys_por_certificado(fp_referencia),
    }

def recolectar_fuentes(dominio, fp_referencia):
    if not AIOHTTP_DISPONIBLE:
        print("[!] aiohttp no está instalado -> recolección OSINT en modo secuencial de respaldo "
              "(pip install aiohttp para la recolección concurrente).")
        return recolectar_fuentes_fallback_sync(dominio, fp_referencia)
    try:
        return asyncio.run(recolectar_fuentes_async(dominio, fp_referencia))
    except RuntimeError:

        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(recolectar_fuentes_async(dominio, fp_referencia))
        finally:
            loop.close()

def obtener_datos_ip(ip):
    try:

        info = http_get(
            f"https://ipinfo.io/{ip}",
            headers={"Authorization": f"Bearer {IPINFO_TOKEN}"},
            timeout=8,
        ).json()
        org = info.get("org", "Desconocido")
        asn = info.get("asn", {}).get("asn", "N/A")
        pais = info.get("country", "Desconocido")
        ubicacion = info.get("loc", "")
        ciudad = info.get("city", "")
        region = info.get("region", "")
        zona = info.get("timezone", "")

        falta_algo = (
            org == "Desconocido" or pais == "Desconocido" or not ubicacion
            or ubicacion == "," or not ciudad or not region or not zona
        )
        if falta_algo:
            try:
                r = http_get(f"https://ipapi.co/{ip}/json/", timeout=6)
                if r.status_code == 200:
                    extra = r.json()
                    if org == "Desconocido" and extra.get("org"):
                        org = extra["org"]
                    if pais == "Desconocido" and extra.get("country_name"):
                        pais = extra["country_name"]
                    if (not ubicacion or ubicacion == ",") and extra.get("latitude") is not None:
                        ubicacion = f"{extra.get('latitude')},{extra.get('longitude')}"
                    if not ciudad and extra.get("city"):
                        ciudad = extra["city"]
                    if not region and extra.get("region"):
                        region = extra["region"]
                    if not zona and extra.get("timezone"):
                        zona = extra["timezone"]
            except (requests.RequestException, ValueError):
                pass

        if asn == "N/A":
            try:
                r = http_get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=5)
                if r.status_code == 200 and r.text and not r.text.lower().startswith("error"):
                    texto = r.text.strip()
                    if texto.startswith("AS"):
                        asn = texto.split()[0]
                    elif '"' in texto:
                        campos = [c.strip().strip('"') for c in texto.split(",")]
                        if len(campos) >= 2 and campos[1].isdigit():
                            asn = f"AS{campos[1]}"
            except:
                pass

        if org == "Desconocido" or asn == "N/A":
            try:
                r = http_get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=5)
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

def obtener_respuestas_representativas(domain_or_ip, timeout=7):
    alt_ports = [None, 8080, 8443, 8000, 8888, 5000, 5001]
    resultado = {"http": None, "https": None}
    for proto in ("http", "https"):
        for port in alt_ports:
            try:
                if port and port not in (80, 443):
                    test_url = f"{proto}://{domain_or_ip}:{port}"
                else:
                    test_url = f"{proto}://{domain_or_ip}"
                r = http_get(test_url, headers=random_headers(), timeout=timeout, verify=False, allow_redirects=True)
                resultado[proto] = {"url": test_url, "response": r}
                break
            except:
                continue
    return resultado

def escanear_headers(domain_or_ip, respuestas=None):
    print(f"[*] Analizando headers para {domain_or_ip} (HTTP y HTTPS, agresivo)...")
    respuestas = respuestas if respuestas is not None else obtener_respuestas_representativas(domain_or_ip)
    resultados = {}
    for proto in ("http", "https"):
        clave = f"{proto}://{domain_or_ip}"
        entry = respuestas.get(proto)
        if entry:
            r = entry["response"]
            server = r.headers.get("Server", "Desconocido")
            powered = r.headers.get("X-Powered-By", "Desconocido")
            title_m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE)
            title = title_m.group(1) if title_m else ""
            resultados[clave] = {
                "Server": server, "X-Powered-By": powered, "Title": title,
                "Location": r.headers.get("Location", ""),
                "Set-Cookie": r.headers.get("Set-Cookie", ""),
            }
        else:
            resultados[clave] = {"Server": "Error", "X-Powered-By": "Error", "Title": "", "Location": "", "Set-Cookie": ""}
    return resultados

FIRMAS_WAF = [
    {
        "nombre": "Cloudflare",
        "cookies": [r"(?:^|[;,\s])__cf(duid|uvid)", r"(?:^|[;,\s])cf_clearance"],
        "headers": {"server": r"cloudflare", "cf-ray": r".+", "cf-cache-status": r".+"},
        "cuerpo": [r"cloudflare-nginx", r"attention required.{0,40}cloudflare", r"cf-error-details"],
    },
    {
        "nombre": "Akamai",
        "cookies": [r"(?:^|[;,\s])ak_bmsc", r"(?:^|[;,\s])_abck", r"(?:^|[;,\s])bm_sz"],
        "headers": {"server": r"akamaighost", "x-akamai-transformed": r".+"},
        "cuerpo": [r"reference #\d+\.[0-9a-f]+\.\d+", r"access denied.{0,60}akamai"],
    },
    {
        "nombre": "Imperva / Incapsula",
        "cookies": [r"(?:^|[;,\s])incap_ses", r"(?:^|[;,\s])visid_incap", r"(?:^|[;,\s])nlbi_"],
        "headers": {"x-iinfo": r".+", "x-cdn": r"incapsula"},
        "cuerpo": [r"incapsula incident id", r"powered by incapsula"],
    },
    {
        "nombre": "Sucuri",
        "cookies": [r"(?:^|[;,\s])sucuri_cloudproxy"],
        "headers": {"server": r"sucuri", "x-sucuri-id": r".+", "x-sucuri-cache": r".+"},
        "cuerpo": [r"access denied.{0,60}sucuri", r"sucuri website firewall"],
    },
    {
        "nombre": "AWS WAF / CloudFront",
        "cookies": [],
        "headers": {"x-amz-cf-id": r".+", "x-amzn-requestid": r".+", "via": r"cloudfront"},
        "cuerpo": [r"generated by cloudfront", r"the request could not be satisfied"],
    },
    {
        "nombre": "Azure Front Door / Azure WAF",
        "cookies": [],
        "headers": {"x-azure-ref": r".+", "x-fd-": r".+"},
        "cuerpo": [r"the requested resource is not found.{0,40}azure"],
    },
    {
        "nombre": "F5 BIG-IP ASM",
        "cookies": [r"(?:^|[;,\s])TS[0-9a-f]{8}", r"(?:^|[;,\s])BIGipServer"],
        "headers": {"server": r"big-?ip"},
        "cuerpo": [r"the requested url was rejected.{0,60}support id"],
    },
    {
        "nombre": "Barracuda WAF",
        "cookies": [r"(?:^|[;,\s])barra_counter_session"],
        "headers": {},
        "cuerpo": [r"barracuda.{0,20}(waf|networks)"],
    },
    {
        "nombre": "Fortinet FortiWeb",
        "cookies": [r"(?:^|[;,\s])fortiwafsid"],
        "headers": {},
        "cuerpo": [r"fortiweb", r"blocked by fortinet"],
    },
    {
        "nombre": "Citrix NetScaler",
        "cookies": [r"(?:^|[;,\s])citrix_ns_id", r"(?:^|[;,\s])ns_af="],
        "headers": {"via": r"netscaler"},
        "cuerpo": [],
    },
    {
        "nombre": "DDoS-Guard",
        "cookies": [r"(?:^|[;,\s])__ddg"],
        "headers": {"server": r"ddos-guard"},
        "cuerpo": [r"ddos-guard"],
    },
    {
        "nombre": "StackPath (antes MaxCDN/Highwinds)",
        "cookies": [],
        "headers": {"server": r"stackpath"},
        "cuerpo": [],
    },
    {
        "nombre": "Reblaze",
        "cookies": [r"(?:^|[;,\s])rbzid"],
        "headers": {},
        "cuerpo": [],
    },
    {
        "nombre": "Wangsu (ChinaNetCenter)",
        "cookies": [],
        "headers": {"server": r"wts(/|_)|wangsu"},
        "cuerpo": [],
    },
    {
        "nombre": "BunnyCDN",
        "cookies": [],
        "headers": {"server": r"bunnycdn"},
        "cuerpo": [],
    },
]

_PAYLOADS_SONDEO_WAF = [
    "?id=1%27%20OR%20%271%27%3D%271",
    "?q=<script>alert(1)</script>",
    "?file=../../../../etc/passwd",
]

def _texto_coincide(patrones, texto):
    if not texto:
        return False
    texto = texto.lower()
    return any(re.search(p, texto, re.IGNORECASE) for p in patrones)

def identificar_waf(dominio, timeout=8):
    """
    Identifica qué WAF/CDN protege al dominio combinando cookies, headers y
    cuerpo de: (a) una respuesta normal y (b) respuestas a payloads de sondeo
    que suelen disparar una página de bloqueo. Es informativo -- ver el
    comentario de diseño arriba de FIRMAS_WAF. Nunca lanza excepción hacia
    afuera: en el peor caso devuelve resultado "sin identificar".
    """
    evidencias = []  # [(nombre_waf, de_donde_vino)]
    respuestas_texto = []
    respuestas_headers = []
    respuestas_cookies = []

    def _capturar(url):
        try:
            r = http_get(url, headers=random_headers(), timeout=timeout, allow_redirects=True)
            respuestas_texto.append(r.text or "")
            respuestas_headers.append({k.lower(): v for k, v in r.headers.items()})
            cookies_crudas = r.headers.get("Set-Cookie", "") or ""
            respuestas_cookies.append(cookies_crudas)
        except requests.RequestException:
            pass

    _capturar(f"https://{dominio}/")
    for payload in _PAYLOADS_SONDEO_WAF:
        _capturar(f"https://{dominio}/{payload}")

    if not respuestas_texto:
        return {"identificado": [], "estado": "sin_conexion"}

    for firma in FIRMAS_WAF:
        nombre = firma["nombre"]
        acierto = False
        for cookies_crudas in respuestas_cookies:
            if any(re.search(p, cookies_crudas, re.IGNORECASE) for p in firma["cookies"]):
                acierto = True
                break
        if not acierto:
            for headers in respuestas_headers:
                for header_nombre, patron in firma["headers"].items():
                    valor = headers.get(header_nombre, "")
                    if valor and re.search(patron, str(valor), re.IGNORECASE):
                        acierto = True
                        break
                    # header_nombre con prefijo (ej. "x-fd-") -- buscar cualquier
                    # header que empiece así, ya que el sufijo exacto varía.
                    if header_nombre.endswith("-") and any(
                        h.startswith(header_nombre) for h in headers
                    ):
                        acierto = True
                        break
                if acierto:
                    break
        if not acierto:
            for texto in respuestas_texto:
                if _texto_coincide(firma["cuerpo"], texto):
                    acierto = True
                    break
        if acierto:
            evidencias.append(nombre)

    return {
        "identificado": evidencias,
        "estado": "ok" if evidencias else "sin_identificar",
    }

TITULOS_CHALLENGE_CONOCIDOS = [
    "just a moment", "attention required", "please wait", "checking your browser",
    "access denied", "sorry, you have been blocked", "pardon our interruption",
    "one more step", "please stand by", "security check", "ddos-guard",
    "you have been blocked", "request blocked", "are you a human",
]

def obtener_titulo_html(url, timeout=7):

    try:
        r = http_get(url, headers=random_headers(), timeout=timeout, allow_redirects=True)
        m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else None
    except requests.RequestException:
        return None

def obtener_titulo_referencia(dominio, forzado=None):

    if forzado:
        return {"titulo": forzado, "estado": "forzado por el usuario (--title-referencia)"}

    titulo = obtener_titulo_html(f"https://{dominio}")
    if titulo is None:
        return {"titulo": None, "estado": "no se pudo obtener (timeout o sin <title>)"}

    bajo = titulo.lower()
    for firma in TITULOS_CHALLENGE_CONOCIDOS:
        if firma in bajo:
            print(f"\n[!] ADVERTENCIA: el título obtenido de {dominio} parece una página de "
                  f"challenge/bloqueo del WAF: \"{titulo}\"")
            print(f"    Si usas este título como referencia, el matching de TODAS las candidatas")
            print(f"    quedará contaminado (ninguna IP real lo va a mostrar nunca). Vuelve a")
            print(f"    correr con --title-referencia \"<título real del sitio>\" para evitarlo.\n")
            return {"titulo": titulo, "estado": "posible challenge page — usar con precaución"}

    return {"titulo": titulo, "estado": "auto-detectado"}

def obtener_rangos_cloudflare_oficiales():

    try:
        v4 = http_get("https://www.cloudflare.com/ips-v4", timeout=8).text.split()
        v6 = http_get("https://www.cloudflare.com/ips-v6", timeout=8).text.split()
        rangos = [r for r in (v4 + v6) if r]
        if rangos:
            return rangos
    except requests.RequestException:
        pass
    return CLOUDFLARE_RANGES

def obtener_rangos_fastly_oficiales():

    try:
        r = http_get("https://api.fastly.com/public-ip-list", timeout=8)
        if r.status_code == 200:
            data = r.json()
            return list(data.get("addresses", [])) + list(data.get("ipv6_addresses", []))
    except (requests.RequestException, ValueError):
        pass
    return []

def obtener_rangos_aws_cloudfront_oficiales():

    try:
        r = http_get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10)
        if r.status_code == 200:
            data = r.json()
            v4 = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
            v6 = [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"]
            return v4 + v6
    except (requests.RequestException, ValueError):
        pass
    return []

def obtener_rangos_azure_frontdoor_oficiales():

    try:
        portal = http_get("https://www.microsoft.com/en-us/download/details.aspx?id=56519", timeout=10)
        m = re.search(r'https://download\.microsoft\.com/[^"\'<>\s]*ServiceTags_Public_\d+\.json', portal.text)
        if not m:
            return []
        r = http_get(m.group(0), timeout=15)
        if r.status_code != 200:
            return []
        data = r.json()
        rangos = []
        for tag in data.get("values", []):
            if str(tag.get("name", "")).startswith("AzureFrontDoor.Frontend"):
                rangos.extend(tag.get("properties", {}).get("addressPrefixes", []))
        return rangos
    except (requests.RequestException, ValueError):
        return []

def obtener_rangos_cdn_conocidos(estatico=False):

    tareas = [obtener_rangos_fastly_oficiales, obtener_rangos_aws_cloudfront_oficiales,
              obtener_rangos_azure_frontdoor_oficiales]
    rangos = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        fut_cf = ex.submit(
            (lambda: CLOUDFLARE_RANGES) if estatico else obtener_rangos_cloudflare_oficiales
        )
        futs = [ex.submit(t) for t in tareas]
        rangos += fut_cf.result()
        for f in futs:
            rangos += f.result()
    return rangos

ORGANIZACIONES_CDN_WAF_CONOCIDAS = [
    "akamai", "imperva", "incapsula", "sucuri", "stackpath", "highwinds",
    "edgecast", "verizon digital media", "limelight", "cachefly", "keycdn",
    "cdn77", "fastly", "cloudflare", "ddos-guard", "radware", "f5 networks",
    "barracuda networks", "azure front door", "quantil", "chinacache",
    "leaseweb cdn", "g-core", "cdnetworks", "reblaze", "wangsu", "bunnycdn",
    "bunny.net", "section.io", "myra security", "indusguard", "netscout arbor",
    "a10 networks", "fortinet", "citrix netscaler", "aryaka",
]

def obtener_organizacion_rapida(ip, timeout=5):
   
    clave_cache = f"org:{ip}"
    cacheado = cache_get(clave_cache)
    if cacheado is not None:
        return cacheado.get("org", "")

    org = ""

    try:
        r = http_get(f"https://ipapi.co/{ip}/org/", timeout=timeout)
        if r.status_code == 200:
            texto = r.text.strip()
            if texto and "error" not in texto.lower() and "undefined" not in texto.lower():
                org = texto
    except requests.RequestException:
        pass

    if not org:
        try:
            r = http_get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=timeout)
            if r.status_code == 200 and r.text:
                texto = r.text.strip()
                if texto.lower().startswith("error") or "api count exceeded" in texto.lower():
                    pass  # mensaje de error/cuota de la API, no un resultado válido
                elif texto.startswith("AS"):
                    partes = texto.split(None, 1)
                    if len(partes) > 1:
                        org = partes[1].strip().strip('"')
                elif '"' in texto:
                    campos = [c.strip().strip('"') for c in texto.split(",")]
                    if len(campos) >= 4:
                        org = campos[3]
        except requests.RequestException:
            pass
    if not org:
        try:
            r = http_get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                org = data.get("name") or data.get("handle") or ""
        except (requests.RequestException, ValueError):
            pass

    cache_set(clave_cache, {"org": org})
    return org

def es_org_de_cdn_waf_conocido(org):
    if not org:
        return None
    bajo = org.lower()
    for nombre in ORGANIZACIONES_CDN_WAF_CONOCIDAS:
        if nombre in bajo:
            return nombre
    return False

def ip_in_cloudflare(ip, rangos=None):

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

            continue
    return False

def buscar_subdominios_securitytrails(domain):
    print("[*] Buscando subdominios en SecurityTrails...")
    try:
        r = http_get(
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
        r = http_get(
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

    print("[*] Buscando subdominios en AlienVault OTX...")
    try:
        r = http_get(
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

def _respuesta_es_challenge(texto):

    bajo = texto.lower()
    return any(firma in bajo for firma in TITULOS_CHALLENGE_CONOCIDOS)

def intentar_bypass_http(domain, ip, titulo_referencia=None):
   
    print(f"[*] Probando bypass HTTP/HTTPS agresivo a {ip}...")
    titulo_ref_norm = titulo_referencia.strip().lower() if titulo_referencia else None
    intento_debil = None  

    def evaluar_respuesta(r, tecnica):
        nonlocal intento_debil
        try:
            texto = r.text
        except Exception:
            texto = ""
        if _respuesta_es_challenge(texto):
            return None  
        if domain.lower() in texto.lower():
            return {"exito": True, "confianza": "alta",
                     "motivo": f"dominio literal en el cuerpo de la respuesta ({tecnica})"}
        if titulo_ref_norm:
            m = re.search(r"<title>(.*?)</title>", texto, re.IGNORECASE | re.DOTALL)
            if m and m.group(1).strip().lower() == titulo_ref_norm:
                return {"exito": True, "confianza": "alta",
                         "motivo": f"título de referencia coincide en el cuerpo ({tecnica})"}
        if r.status_code in [200, 403, 401] and intento_debil is None:
            intento_debil = {"exito": True, "confianza": "baja",
                              "motivo": f"status {r.status_code} plausible pero sin contenido confirmado ({tecnica})"}
        return None

    try:
        headers = HEADERS.copy()
        headers["Host"] = domain

        r = http_get(f"http://{ip}", headers=headers, timeout=7)
        res = evaluar_respuesta(r, "HTTP simple")
        if res:
            return res
        try:
            r = http_get(f"https://{ip}", headers=headers, timeout=7, verify=False)
            res = evaluar_respuesta(r, "HTTPS simple")
            if res:
                return res
        except:
            pass

        headers["X-Forwarded-Host"] = domain
        headers["X-Forwarded-For"] = "127.0.0.1"
        r = http_get(f"http://{ip}", headers=headers, timeout=7)
        res = evaluar_respuesta(r, "X-Forwarded-Host/For")
        if res:
            return res

        headers["User-Agent"] = "curl/7.68.0"
        r = http_get(f"http://{ip}", headers=headers, timeout=7)
        res = evaluar_respuesta(r, "User-Agent alternativo")
        if res:
            return res
        try:
            r = http_get(f"https://{ip}", headers=headers, timeout=7, verify=False)
            res = evaluar_respuesta(r, "HTTPS + UA alternativo")
            if res:
                return res
        except:
            pass

        headers["X-Real-IP"] = "127.0.0.1"
        headers["Forwarded"] = f"for=127.0.0.1;host={domain};proto=http"
        r = http_get(f"http://{ip}", headers=headers, timeout=7)
        res = evaluar_respuesta(r, "headers de proxy adicionales")
        if res:
            return res
    except:
        pass

    if intento_debil:
        return intento_debil
    return {"exito": False, "confianza": None, "motivo": "ninguna técnica confirmó el dominio en el cuerpo"}


DOMINIO_CONTROL_NEGATIVO = "cloudghost-control-negativo-9f3ak2.invalid"

def control_negativo_bypass(ip):
    resultado = intentar_bypass_http(DOMINIO_CONTROL_NEGATIVO, ip)
    return resultado["exito"]

def obtener_fingerprint_certificado(host_conexion, sni, puerto=443, timeout=6):

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

    import base64
    import mmh3
    try:
        r = http_get(url.rstrip('/') + "/favicon.ico", headers=random_headers(),
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
        r = http_get(
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
    "uat", "preprod", "pre-prod", "beta", "alpha", "sandbox", "internal",
    "intranet", "admin", "panel", "dashboard", "cms", "git", "gitlab",
    "jenkins", "jira", "confluence", "grafana", "kibana", "monitor", "status",
    "api-internal", "app", "m", "mobile", "assets-origin", "static-origin",
    "cdn-origin", "edge", "web1", "web2", "node1", "node2", "srv1", "srv2",
]

def cargar_dominios_hermanos(ruta):
  
    try:
        with open(ruta, encoding="utf-8") as f:
            dominios = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        print(f"[*] {len(dominios)} dominio(s) hermano(s) cargados desde {ruta}")
        return dominios
    except OSError as e:
        print(f"[!] No se pudo leer el archivo de dominios hermanos '{ruta}': {e}")
        return []

def buscar_subdominios_no_proxeados(domain, rangos_cf=None, threads=DEFAULT_THREADS, dominios_extra=None):

    dominios_extra = dominios_extra or []
    candidatos = [f"{s}.{domain}" for s in SUBDOMINIOS_NO_PROXEADOS] + dominios_extra
    print(f"[*] Sondeando {len(candidatos)} candidatos a no estar proxeados "
          f"({len(SUBDOMINIOS_NO_PROXEADOS)} del wordlist + {len(dominios_extra)} hermanos)...")
    rangos_cf = rangos_cf if rangos_cf is not None else CLOUDFLARE_RANGES

    def resolver(sub):
        try:
            ip = socket.gethostbyname(sub)
        except socket.error:
            return None
        if ip_in_cloudflare(ip, rangos_cf):
            return None  

        org = obtener_organizacion_rapida(ip)
        cdn_org = es_org_de_cdn_waf_conocido(org)
        if cdn_org:
            print(f"    [~] {sub} -> {ip} (fuera de rangos descargables, pero ASN/org='{org}' "
                  f"-> sigue en la red de {cdn_org}; descartado)")
            return None
        return (sub, ip, org)

    hallazgos = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(resolver, candidatos):
            if res:
                hallazgos.append(res)
                sub, ip, org = res
                extra = f", org='{org}'" if org else ""
                print(f"    [+] {sub} -> {ip} (fuera de rangos y de organizaciones de WAF/CDN conocidas{extra})")
    return hallazgos

def guardar_tabla_resultados(ruta, dominio, ranking, candidatas_sin_score=None, waf_detectado=None):

    candidatas_sin_score = candidatas_sin_score or []
    ancho_ip = max([15] + [len(r["ip"]) for r in ranking])
    try:
        with open(ruta, "w", encoding="utf-8") as f:
            f.write("CloudGhost - Resultado del escaneo\n")
            f.write(f"Dominio objetivo : {dominio}\n")
            f.write(f"Fecha            : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            if waf_detectado:
                f.write(f"WAF/CDN detectado: {', '.join(waf_detectado)} "
                        f"(informativo -- no determina el filtrado de IPs)\n")
            else:
                f.write("WAF/CDN detectado: no identificado por firma\n")
            f.write(f"Candidatas evaluadas con evidencia: {len(ranking)}\n\n")

            encabezado = (
                f"{'IP':<{ancho_ip}}  {'SCORE':>5}  {'CONFIANZA':<10}  "
                f"{'F.FUERTES':>9}  {'F.DEBILES':>9}  MOTIVOS"
            )
            f.write(encabezado + "\n")
            f.write("-" * len(encabezado) + "\n")
            for r in ranking:
                motivos_txt = "; ".join(m for m in r["motivos"] if not m.startswith("⚠"))
                advertencias = [m for m in r["motivos"] if m.startswith("⚠")]
                f.write(
                    f"{r['ip']:<{ancho_ip}}  {r['score']:>5}  {r['confianza'].upper():<10}  "
                    f"{r['señales_fuertes']:>9}  {r['señales_debiles']:>9}  {motivos_txt}\n"
                )
                for adv in advertencias:
                    f.write(f"{'':<{ancho_ip}}  {'':>5}  {'':<10}  {'':>9}  {'':>9}  {adv}\n")

            if candidatas_sin_score:
                f.write(f"\nOtras {len(candidatas_sin_score)} candidata(s) recolectada(s) sin ninguna "
                        f"señal de evidencia (score 0, no listadas arriba):\n")
                for ip in candidatas_sin_score:
                    f.write(f"  {ip}\n")
        return True
    except OSError as e:
        print(f"[!] No se pudo guardar el resultado en '{ruta}': {e}")
        return False

def buscar_ips_historicas_securitytrails(domain):
    print("[*] Buscando IPs históricas en SecurityTrails...")
    try:
        r = http_get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": SECURITYTRAILS_API_KEY},
            timeout=10,
        )
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
        r = http_get(f"https://viewdns.info/iphistory/?domain={domain}")
        if r.status_code == 200:
            lines = r.text.splitlines()
            ips = []
            for line in lines:
                found_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
                ips.extend(found_ips)

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

    try:
        r = http_get(f"https://viewdns.info/iphistory/?domain={domain}")
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

def detectar_tecnologias(domain_or_ip, respuestas=None):
    print(f"[*] Fingerprinting de tecnologías web en {domain_or_ip}...")
    respuestas = respuestas if respuestas is not None else obtener_respuestas_representativas(domain_or_ip)
    tecnologias = set()
    for proto in ("http", "https"):
        entry = respuestas.get(proto)
        if not entry:
            continue
        try:
            r = entry["response"]
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
        except:
            continue
    return list(tecnologias)

def buscar_leaks_github(domain):
    print(f"[*] Buscando posibles leaks en GitHub para {domain}...")
    leaks = []
    try:
        r = http_get(f"https://api.github.com/search/code?q={domain}", headers=random_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("items", []):
                leaks.append(item.get("html_url"))
    except:
        pass
    return leaks

def buscar_leaks_pastebin(domain):

    print(f"[*] Buscando posibles leaks en Pastebin para {domain} (requiere cuenta Pro)...")
    leaks = []
    try:
        r = http_get("https://scrape.pastebin.com/api_scraping.php?limit=50", timeout=10)
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

SEÑALES_FUERTES = {"cert_tls", "favicon", "titulo", "bypass_alta"}
SEÑALES_DEBILES = {"bypass_baja", "headers_genericos", "tecnologias", "puerto_abierto"}
CONFIANZA_RANK = {"confirmada": 4, "alta": 3, "media": 2, "baja": 1, "sin_evidencia": 0}

def clasificar_confianza_por_senales(n_fuertes, n_debiles):
    if n_fuertes >= 2:
        return "confirmada"
    if n_fuertes == 1:
        return "alta"
    if n_debiles >= 2:
        return "media"   # 2+ señales débiles independientes SÍ se corroboran entre sí
    if n_debiles == 1:
        return "baja"    # una sola señal débil no es corroboración, es una pista suelta
    return "sin_evidencia"

def evaluar_candidatas(dominio, candidatas, fp_referencia=None, favicon_hash_ref=None,
                        titulo_referencia=None,
                        puertos=[80, 443, 8080, 8443, 8000, 8888, 5000, 5001],
                        max_concurrentes=8):

    def evaluar_una(ip):
        score = 0
        motivos = []
        señales = set()  # tags para el criterio de corroboración (#3)

        if fp_referencia:
            fp_candidata = obtener_fingerprint_certificado(ip, dominio)
            if fp_candidata and fp_candidata == fp_referencia:
                score += 60
                motivos.append("certificado TLS idéntico al del dominio")
                señales.add("cert_tls")

        if favicon_hash_ref is not None:
            fh = obtener_favicon_hash(f"http://{ip}")
            if fh == favicon_hash_ref:
                score += 25
                motivos.append("favicon idéntico")
                señales.add("favicon")
        bypass = intentar_bypass_http(dominio, ip, titulo_referencia=titulo_referencia)
        if bypass["exito"]:
            if control_negativo_bypass(ip):
                motivos.append(
                    "⚠ CONTROL NEGATIVO FALLÓ: esta IP también 'confirma' un dominio inventado "
                    "-> acepta cualquier Host header (posible vhost por defecto/hosting compartido); "
                    "el bypass contra el dominio real NO se cuenta como evidencia aquí"
                )
            elif bypass["confianza"] == "alta":
                score += 10
                motivos.append(f"Host header spoofing confirmado: {bypass['motivo']}")
                señales.add("bypass_alta")
            else:  # confianza baja, pero pasó el control negativo
                score += 2
                motivos.append(f"Host header spoofing débil (sin control negativo positivo): {bypass['motivo']}")
                señales.add("bypass_baja")

        respuestas = obtener_respuestas_representativas(ip)
        headers = escanear_headers(ip, respuestas=respuestas)
        if titulo_referencia:
            titulo_ref_norm = titulo_referencia.strip().lower()
            for url, data in headers.items():
                titulo_candidata = (data.get("Title") or "").strip().lower()
                if titulo_candidata and titulo_candidata == titulo_ref_norm:
                    score += 20
                    motivos.append("título HTML idéntico al de referencia")
                    señales.add("titulo")
                    break

        for url, data in headers.items():
            if data.get("Server") not in ["Desconocido", "Error", None] or data.get("Title"):
                score += 5
                motivos.append("headers/título HTTP no genéricos")
                señales.add("headers_genericos")
                break

        if detectar_tecnologias(ip, respuestas=respuestas):
            score += 3
            motivos.append("tecnologías web detectadas")
            señales.add("tecnologias")

        for port in puertos:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        score += 1
                        motivos.append(f"puerto {port} abierto")
                        señales.add("puerto_abierto")
                        break
            except OSError:
                continue

        if señales & SEÑALES_FUERTES == {"cert_tls"}:
            org = obtener_organizacion_rapida(ip)
            cdn_org = es_org_de_cdn_waf_conocido(org)
            if cdn_org:
                señales.discard("cert_tls")
                score = max(0, score - 60)
                motivos.append(
                    f"⚠ Certificado idéntico, PERO esta IP pertenece a '{org}' — un proveedor de "
                    f"WAF/CDN conocido sin lista pública de rangos. Es muy probable que sea otro "
                    f"nodo edge/anycast de {cdn_org} sirviendo el mismo certificado público, no el "
                    f"origen real. Señal de certificado DEGRADADA — no cuenta como fuerte aquí."
                )

        if score <= 0:
            return None
        n_fuertes = len(señales & SEÑALES_FUERTES)
        n_debiles = len(señales & SEÑALES_DEBILES)
        confianza = clasificar_confianza_por_senales(n_fuertes, n_debiles)
        return {
            "ip": ip, "score": score, "motivos": motivos,
            "confianza": confianza,
            "señales_fuertes": n_fuertes, "señales_debiles": n_debiles,
        }

    resultados = []
    total = len(candidatas)
    completadas = 0
    with ThreadPoolExecutor(max_workers=min(max_concurrentes, max(1, total))) as ex:
        futuros = {ex.submit(evaluar_una, ip): ip for ip in candidatas}
        for fut in as_completed(futuros):
            r = fut.result()
            if r:
                resultados.append(r)
            completadas += 1
            mostrar_barra_progreso(70 + int(20 * completadas / total),
                                    f"Evaluando candidatas: {completadas}/{total} ({futuros[fut]})")

    resultados.sort(key=lambda r: (CONFIANZA_RANK[r["confianza"]], r["score"]), reverse=True)
    return resultados

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
            r = http_get(url, headers=random_headers(), timeout=5, verify=False, allow_redirects=True)
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
        description="CloudGhost - OSINT ofensivo para descubrir la IP real de origen detras de "
                    "cualquier WAF/CDN (Cloudflare, Akamai, Imperva, Sucuri, Fastly, AWS CloudFront, "
                    "Azure Front Door, y cualquier otro con o sin lista publica de rangos)."
    )
    parser.add_argument("dominio", help="Dominio objetivo, ej: vulnerable.site")
    parser.add_argument("-o", "--output", default="resultado_cloudghost.txt",
                         help="Archivo .txt donde guardar la tabla de resultados con el nivel de "
                              "confianza de cada IP candidata (default: resultado_cloudghost.txt)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                         help=f"Hilos concurrentes para resolución/fuzzing/escaneo (default: {DEFAULT_THREADS}). "
                              f"Valores muy altos (>60) aumentan el riesgo de rate-limit o baneo temporal "
                              f"por parte del WAF/CDN del objetivo — sube este número con cautela.")
    parser.add_argument("--static-cf-ranges", action="store_true",
                         help="Usa la lista estática de rangos Cloudflare embebida en vez de descargar la oficial")
    parser.add_argument("--title-referencia", metavar="TITULO", default=None,
                         help="Título HTML real del sitio, para evitar auto-detectarlo si el dominio "
                              "está bloqueado por el WAF (challenge/captcha) y el título obtenido "
                              "contaminaría el matching de candidatas")
    parser.add_argument("--proxy", metavar="URL", default=None,
                         help="Proxy para TODO el tráfico de la herramienta, ej: http://127.0.0.1:8080 "
                              "(Burp) o socks5://127.0.0.1:9050 (Tor). Requiere PySocks para socks5:// "
                              "(no aplica a la fase async de recolección OSINT, ver README)")
    parser.add_argument("--sibling-domains", metavar="ARCHIVO", default=None,
                         help="Archivo con un dominio/subdominio hermano por línea (marcas, subsidiarias "
                              "del mismo bug bounty program) a sondear además del wordlist fijo, por si "
                              "comparten infraestructura con el objetivo sin estar detrás del mismo WAF")
    args = parser.parse_args()
    if args.threads > 60:
        print(f"[!] --threads {args.threads} es agresivo: más conexiones concurrentes contra el mismo "
              f"objetivo aumenta el riesgo de que el WAF/CDN te rate-limitee o banee temporalmente a "
              f"mitad del engagement. Continúa bajo tu propio criterio.")
    return args

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    args = parse_args()

    if args.proxy:
        PROXY_CONFIG.update({"http": args.proxy, "https": args.proxy})
        print(f"[*] Todo el tráfico se enrutará a través de: {args.proxy}")

    dominio = limpiar_url(args.dominio)
    print(f"\n[+] Escaneando: {dominio}")
    mostrar_barra_progreso(2, "Resolviendo el dominio objetivo...")

    try:
        cf_ip = socket.gethostbyname(dominio)
    except socket.gaierror:
        print(f"\n[!] No se pudo resolver {dominio}. ¿Está bien escrito el dominio?")
        sys.exit(1)
    mostrar_barra_progreso(5, "Dominio resuelto")

    a_records_raiz = obtener_todos_los_a_records(dominio)
    a_records_raiz.add(cf_ip)
    if len(a_records_raiz) > 1:
        print(f"[!] El dominio tiene {len(a_records_raiz)} registros A/AAAA distintos "
              f"(round-robin): {', '.join(sorted(a_records_raiz))} -- se evaluarán todos "
              f"como candidatas, no solo el primero.")

    mostrar_barra_progreso(8, "Obteniendo título de referencia...")
    ref_titulo = obtener_titulo_referencia(dominio, forzado=args.title_referencia)
    if ref_titulo["titulo"]:
        print(f"[+] Título de referencia: \"{ref_titulo['titulo']}\"  ({ref_titulo['estado']})")
    else:
        print(f"[!] Título de referencia no disponible ({ref_titulo['estado']})")

    mostrar_barra_progreso(12, "Obteniendo certificado TLS y favicon de referencia...")
    fp_referencia = obtener_fingerprint_certificado(dominio, dominio)
    favicon_ref = obtener_favicon_hash(f"https://{dominio}")

    mostrar_barra_progreso(13, "Identificando WAF/CDN...")
    waf_info = identificar_waf(dominio)
    if waf_info["identificado"]:
        print(f"[+] WAF/CDN detectado: {', '.join(waf_info['identificado'])}")
    elif waf_info["estado"] == "sin_conexion":
        print("[!] No se pudo contactar al dominio para identificar el WAF.")
    else:
        print("[*] No se identificó un WAF/CDN conocido por firma (puede no tener uno, "
              "o ser uno sin firma en esta versión). La heurística ASN sigue activa igual.")

    mostrar_barra_progreso(15, "Descargando rangos IP de CDN conocidos...")
    rangos_conocidos = obtener_rangos_cdn_conocidos(estatico=args.static_cf_ranges)
    print(f"[*] {len(rangos_conocidos)} rangos IP agregados (Cloudflare + Fastly + AWS CloudFront + "
          f"Azure Front Door) para filtrar candidatas.")

    mostrar_barra_progreso(20, "Recolectando fuentes OSINT...")
    fuentes = recolectar_fuentes(dominio, fp_referencia)
    sub1, ips_crtsh = fuentes["crt.sh"]
    sub2 = fuentes["wayback"]
    sub3 = fuentes["virustotal"]
    sub4 = fuentes["otx"]
    sub5 = fuentes["securitytrails_sub"]
    subdominios = list(set(sub1 + sub2 + sub3 + sub4 + sub5))
    ips2 = fuentes["shodan"]
    ips3 = fuentes["zoomeye"]
    ips5 = fuentes["viewdns_hist"]
    ips6 = fuentes["securitytrails_hist"]
    ips_censys = fuentes["censys"]
    ips_favicon = buscar_shodan_por_favicon(favicon_ref)
    mostrar_barra_progreso(35, f"{len(subdominios)} subdominios y {len(ips_crtsh)+len(ips2)+len(ips3)+len(ips5)+len(ips6)+len(ips_censys)} IPs recolectadas")

    mostrar_barra_progreso(40, f"Resolviendo {len(subdominios)} subdominios en paralelo...")
    ips1 = resolucion_dns_masiva(subdominios, threads=args.threads)

    dominios_hermanos = cargar_dominios_hermanos(args.sibling_domains) if args.sibling_domains else []

    mostrar_barra_progreso(48, "Sondeando subdominios/dominios comúnmente no proxeados...")
    no_proxeados = buscar_subdominios_no_proxeados(
        dominio, rangos_conocidos, threads=args.threads, dominios_extra=dominios_hermanos
    )
    ips7 = [ip for _, ip, _ in no_proxeados]

    todas = list(set(ips1 + ips2 + ips3 + ips5 + ips6 + ips7 + ips_censys + ips_favicon +
                      ips_crtsh + list(a_records_raiz)))
    mostrar_barra_progreso(52, f"{len(todas)} IPs únicas recolectadas en total")

    candidatas = filtrar_ips_cloudflare(todas, rangos_conocidos) if rangos_conocidos else todas
    mostrar_barra_progreso(55, f"{len(candidatas)} candidatas tras filtrar rangos de CDN conocidos")

    if not candidatas:
        print("\n\n[!] No quedó ninguna IP candidata tras el filtrado. Nada que evaluar.")
        sys.exit(1)

    ip_puertos = []
    max_ips_concurrentes = min(5, max(1, len(candidatas)))
    total_candidatas = len(candidatas)
    completadas = 0
    with ThreadPoolExecutor(max_workers=max_ips_concurrentes) as ex:
        futuros = {ex.submit(escanear_puertos_avanzado, ip, None, args.threads): ip for ip in candidatas}
        for fut in as_completed(futuros):
            ip = futuros[fut]
            abiertos = fut.result()
            if abiertos:
                ip_puertos.append((ip, abiertos))
            completadas += 1
            mostrar_barra_progreso(55 + int(15 * completadas / total_candidatas),
                                    f"Puertos escaneados: {completadas}/{total_candidatas} ({ip})")
    ip_puertos.sort(key=lambda x: len(x[1]), reverse=True)

    ranking = evaluar_candidatas(
        dominio, [ip for ip, _ in ip_puertos],
        fp_referencia=fp_referencia, favicon_hash_ref=favicon_ref,
        titulo_referencia=ref_titulo["titulo"]
    )
    ip_real = ranking[0]["ip"] if ranking else None
    confianza_resultado = ranking[0]["confianza"] if ranking else None
    puertos = []
    if ip_real:
        puertos = next((abiertos for ip, abiertos in ip_puertos if ip == ip_real), [])

    if ranking:
        print("\n\n[ RANKING DE CANDIDATAS POR CONFIANZA ]")
        for r in ranking[:5]:
            print(f"  {r['ip']:<16} confianza={r['confianza'].upper():<6} score={r['score']:<4} "
                  f"motivos: {', '.join(r['motivos']) or 'ninguno'}")

    ips_sin_score = [ip for ip in candidatas if ip not in {r["ip"] for r in ranking}]

    if not ip_real:
        print(f"\n\n[!] Ninguna candidata obtuvo evidencia alguna (todas score 0).")
        print("[*] IPs candidatas y puertos abiertos detectados:")
        for ip, abiertos in ip_puertos:
            print(f"  {ip} -> Puertos abiertos: {abiertos}")
        guardar_tabla_resultados(args.output, dominio, [], candidatas_sin_score=candidatas,
                                  waf_detectado=waf_info["identificado"])
        print(f"\n[*] Tabla (vacía) guardada en: {args.output}")
        sys.exit(1)

    n_f, n_d = ranking[0]["señales_fuertes"], ranking[0]["señales_debiles"]
    if confianza_resultado == "confirmada":
        print(f"\n\033[1;92m[✓✓] IP real CONFIRMADA: {ip_real}\033[0;0m "
              f"(score={ranking[0]['score']}, {n_f} señales fuertes independientes corroborándose)")
    elif confianza_resultado == "alta":
        print(f"\n\033[1;96m[✓] POSIBLE IP real (alta confianza, NO concluyente): {ip_real}\033[0;0m "
              f"(score={ranking[0]['score']}, 1 sola señal fuerte — corrobórala con una segunda señal "
              f"independiente antes de reportarla como origen confirmado en el hallazgo).")
    elif confianza_resultado == "media":
        print(f"\n\033[1;93m[~] IP candidata con confianza MEDIA: {ip_real}\033[0;0m "
              f"(score={ranking[0]['score']}, {n_d} señales débiles corroborándose, ninguna fuerte) "
              f"— corrobora manualmente antes de reportarla como origen confirmado.")
    else:
        print(f"\n\033[1;91m[!] IP candidata con confianza BAJA: {ip_real}\033[0;0m "
              f"(score={ranking[0]['score']}, solo {n_d} señal débil aislada sin corroborar) "
              f"— NINGUNA señal fuerte (cert TLS/favicon/título/bypass confirmado) la respalda. "
              f"Esto NO es una confirmación, es la menos mala de las candidatas encontradas. "
              f"No la reportes como origen real sin verificación manual adicional.")

    mostrar_barra_progreso(90, "Recolectando información adicional de la IP real...")
    info = obtener_datos_ip(ip_real)
    headers = escanear_headers(ip_real)

    whois_info = whois_dns_history(dominio)
    tecnologias = detectar_tecnologias(ip_real)

    mostrar_barra_progreso(95, "Fuzzing de directorios en la IP real...")
    fuzz = fuzz_directorios(ip_real, threads=args.threads)

    leaks_github = buscar_leaks_github(dominio)
    leaks_pastebin = buscar_leaks_pastebin(dominio)
    vulns = escanear_vulnerabilidades(ip_real, puertos)
    mostrar_barra_progreso(100, "Escaneo completo")

    print("\n\n\033[1;92m[ RESULTADOS AVANZADOS ]\033[0;0m")
    print(f" Dominio objetivo    : {dominio}")
    print(f" IP frontal (CDN/WAF): {cf_ip}")
    print(f" Confianza resultado : {confianza_resultado.upper()} (score={ranking[0]['score']})")
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
    print(f" Directorios/Archivos: {fuzz if fuzz else 'No disponible'}")
    print(f" Vulnerabilidades    : {vulns if vulns else 'No disponible'}")
    print(f" Leaks GitHub        : {leaks_github if leaks_github else 'No disponible'}")
    print(f" Leaks Pastebin      : {leaks_pastebin if leaks_pastebin else 'No disponible'}")
    print("\n[ WHOIS ]")
    for k, v in whois_info.items():
        print(f"  {k}: {v if v else 'No disponible'}")

    guardado_ok = guardar_tabla_resultados(args.output, dominio, ranking, candidatas_sin_score=ips_sin_score,
                                            waf_detectado=waf_info["identificado"])
    if guardado_ok:
        print(f"\n[*] Tabla de resultados ({len(ranking)} candidata(s) con evidencia) guardada en: {args.output}")

if __name__ == "__main__":
    main()
