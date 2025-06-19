
import requests
import concurrent.futures
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fuzz_directorios(ip_real, use_https=False, max_threads=20):
    protocol = "https" if use_https else "http"
    target_base = f"{protocol}://{ip_real}"
    print(f"\n[🔍] Iniciando fuzzing de directorios en: {target_base}\n")

    # Puedes reemplazar esta lista por una wordlist externa
    wordlist = [
        "admin", "login", "dashboard", "config", "config.php", "uploads", "backup", "api",
        ".git", ".env", "wp-admin", "server-status", "cpanel", "test", "dev", "old", "private"
    ]

    found = []

    def check_path(path):
        url = f"{target_base}/{path}"
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CloudGhost Fuzzer)",
            "X-Original-URL": f"/{path}",
            "X-Custom-IP-Authorization": "127.0.0.1"
        }
        try:
            response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                result = f"[+] {url} [Status: {response.status_code}]"
                print(result)
                found.append(result)

                # Intento básico de bypass si es 403
                if response.status_code == 403:
                    bypass_url = f"{url}/."
                    bypass = requests.get(bypass_url, headers=headers, timeout=5, verify=False)
                    if bypass.status_code in [200, 301, 302]:
                        print(f"[!!] Bypass 403 posible: {bypass_url} [Status: {bypass.status_code}]")
        except requests.RequestException as e:
            pass  # Silenciar errores de conexión

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(check_path, wordlist)

    if not found:
        print("[!] No se encontraron directorios comunes visibles.")
    else:
        print(f"\n[✔] Fuzzing completado. {len(found)} posibles rutas encontradas.\n")

    return found
