import asyncio
import dns.resolver
import struct
import socket
import sys
import threading
import os
import base64
import json
import argparse
import time
import hashlib
from datetime import date, timedelta
import logging

CONFIG_FILE = "config.json"
STATS_FILE = "stats.json"

logging.basicConfig(
    filename='proxy.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


default_config = {
    "host": "0.0.0.0",
    "port": 1080,
    "dns": ["8.8.8.8", "1.1.1.1"],
    "blacklist": ["windowsupdate.com", "update.microsoft.com"],
    "auth_enabled": True,
    "users": {
        "admin": {"pass": hashlib.sha256("123456".encode()).hexdigest(), "quota": 0, "daily_quota": 0, "speed": 0, "expire": ""}
    }
}

config = {}
stats = {"users": {}, "daily_users": {}, "domains": {}}
stop_live_monitor = False
last_config_mtime = 0

failed_attempts = {}
MAX_FAILS = 10
BAN_DURATION = 86400



def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_data():
    global config, stats, last_config_mtime
    if os.path.exists(CONFIG_FILE):
        try:
            mtime = os.path.getmtime(CONFIG_FILE)
            if mtime > last_config_mtime:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config.update(json.load(f))
                last_config_mtime = mtime
        except:
            if not config:
                config.update(default_config)
                save_data()
    else:
        config.update(default_config)
        save_data()

    needs_save = False
    for u in list(config.get("users", {}).keys()):
        if isinstance(config["users"][u], str):
            old_pass = config["users"][u]
            config["users"][u] = {
                "pass": hash_password(old_pass),
                "quota": 0,
                "daily_quota": 0,
                "speed": 0,
                "expire": ""
            }
            needs_save = True
    
    if needs_save:
        save_data()
        
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r', encoding='utf-8') as f:
                stats.update(json.load(f))
                if "daily_users" not in stats:
                    stats["daily_users"] = {}
        except:
            pass

def save_data():
    global last_config_mtime
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4)
    last_config_mtime = os.path.getmtime(CONFIG_FILE)
    
    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=4)

async def config_watcher():
    while True:
        await asyncio.sleep(5)
        load_data()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_blacklisted(domain):
    if not domain:
        return False
    domain_lower = domain.lower()
    for blocked in config["blacklist"]:
        if blocked in domain_lower:
            return True
    return False

def check_auth(username, password):
    if not config["auth_enabled"]:
        return True
    user_data = config["users"].get(username)
    if user_data and isinstance(user_data, dict):
        if user_data.get("pass") == hash_password(password):
            exp = user_data.get("expire", "")
            if exp and date.today().isoformat() > exp:
                return False
            return True
    return False

def is_ip_banned(ip):
    if ip in failed_attempts:
        data = failed_attempts[ip]
        if data['count'] >= MAX_FAILS:
            if time.time() - data['last_attempt'] < BAN_DURATION:
                return True
            else:
                del failed_attempts[ip]  
    return False

def record_failed_attempt(ip):
    if ip not in failed_attempts:
        failed_attempts[ip] = {'count': 1, 'last_attempt': time.time()}
    else:
        failed_attempts[ip]['count'] += 1
        failed_attempts[ip]['last_attempt'] = time.time()
    
    logging.warning(f"Failed auth attempt from IP: {ip} (Fails: {failed_attempts[ip]['count']})")
    
    if failed_attempts[ip]['count'] == MAX_FAILS:
        logging.error(f"IP BANNED (Brute-Force): {ip}")

def clear_failed_attempt(ip):
    if ip in failed_attempts:
        del failed_attempts[ip]


async def update_stats(user, domain, bytes_count):
    if user not in stats["users"]:
        stats["users"][user] = 0
    if domain not in stats["domains"]:
        stats["domains"][domain] = 0
        
    today = date.today().isoformat()
    if user not in stats["daily_users"]:
        stats["daily_users"][user] = {"date": today, "bytes": 0}
    elif stats["daily_users"][user].get("date") != today:
        stats["daily_users"][user] = {"date": today, "bytes": 0}
        
    stats["users"][user] += bytes_count
    stats["domains"][domain] += bytes_count
    stats["daily_users"][user]["bytes"] += bytes_count

async def relay_data(reader, writer, user, domain):
    user_conf = config["users"].get(user, {})
    speed_limit = user_conf.get("speed", 0) * 1024
    quota = user_conf.get("quota", 0) * 1024 * 1024
    daily_quota = user_conf.get("daily_quota", 0) * 1024 * 1024
    
    try:
        while True:
            today = date.today().isoformat()
            
            if quota > 0 and stats["users"].get(user, 0) >= quota:
                break
                
            d_stats = stats["daily_users"].get(user, {})
            if daily_quota > 0 and d_stats.get("date") == today and d_stats.get("bytes", 0) >= daily_quota:
                break
                
            start_time = time.time()
            data = await reader.read(4096)
            
            if not data:
                break
                
            writer.write(data)
            await writer.drain()
            
            data_length = len(data)
            await update_stats(user, domain, data_length)
            
            if speed_limit > 0:
                elapsed_time = time.time() - start_time
                expected_time = data_length / speed_limit
                if elapsed_time < expected_time:
                    await asyncio.sleep(expected_time - elapsed_time)
    except:
        pass
    finally:
        writer.close()

async def udp_handler(udp_sock, client_addr):
    loop = asyncio.get_running_loop()
    udp_sock.setblocking(False)
    client_ip = client_addr[0]
    client_udp_port = None
    
    try:
        while True:
            data, addr = await loop.sock_recvfrom(udp_sock, 4096)
            
            if addr[0] == client_ip:
                client_udp_port = addr[1]
                atyp = data[3]
                offset = 4
                if atyp == 0x01:
                    t_ip = socket.inet_ntoa(data[offset:offset+4])
                    offset += 4
                elif atyp == 0x03:
                    d_len = data[offset]
                    offset += 1
                    t_ip = data[offset:offset+d_len].decode('utf-8')
                    offset += d_len
                else: continue
                
                t_port = struct.unpack('>H', data[offset:offset+2])[0]
                payload = data[offset+2:]
                await loop.sock_sendto(udp_sock, payload, (t_ip, t_port))
            
            elif client_udp_port:
                t_ip_bytes = socket.inet_aton(addr[0])
                t_port_bytes = struct.pack('>H', addr[1])
                header = b'\x00\x00\x00\x01' + t_ip_bytes + t_port_bytes
                await loop.sock_sendto(udp_sock, header + data, (client_ip, client_udp_port))
    except:
        udp_sock.close()

async def custom_dns_resolve(domain):
    try:
        parts = domain.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return domain
            
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = config["dns"]
        answer = resolver.resolve(domain, 'A')
        return answer[0].to_text()
    except:
        return None

async def handle_socks5(reader, writer, initial_data):
    try:
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        
        if is_ip_banned(client_ip):
            writer.close()
            return

        
        num_methods = initial_data[1]
        methods = await reader.read(num_methods)
        current_user = "anonymous"

        if config["auth_enabled"]:
            if b'\x02' not in methods:
                writer.write(b'\x05\xff')
                await writer.drain()
                writer.close()
                return
            
            writer.write(b'\x05\x02')
            await writer.drain()

            auth_version = await reader.read(1)
            if not auth_version or auth_version[0] != 0x01:
                writer.close()
                return

            ulen = (await reader.read(1))[0]
            username = (await reader.read(ulen)).decode('utf-8')
            plen = (await reader.read(1))[0]
            password = (await reader.read(plen)).decode('utf-8')

            if check_auth(username, password):
                clear_failed_attempt(client_ip) 
                writer.write(b'\x01\x00')
                await writer.drain()
                current_user = username
            else:
                record_failed_attempt(client_ip) 
                writer.write(b'\x01\x01')
                await writer.drain()
                writer.close()
                return
        else:
            if b'\x00' in methods:
                writer.write(b'\x05\x00')
                await writer.drain()
            else:
                writer.write(b'\x05\xff')
                await writer.drain()
                writer.close()
                return

        request = await reader.read(4)
        if len(request) < 4 or request[1] not in (0x01, 0x03):
            writer.close()
            return
            
        cmd = request[1]
        client_addr = writer.get_extra_info('peername')

        if cmd == 0x01:
            address_type = request[3]
            target_domain = ""
            target_ip = ""

            if address_type == 0x01:
                raw_ip = await reader.read(4)
                target_ip = socket.inet_ntoa(raw_ip)
                target_domain = target_ip
            elif address_type == 0x03:
                domain_len = (await reader.read(1))[0]
                target_domain = (await reader.read(domain_len)).decode('utf-8')
            else:
                writer.close()
                return

            raw_port = await reader.read(2)
            target_port = struct.unpack('>H', raw_port)[0]

            if is_blacklisted(target_domain):
                logging.info(f"Blocked access to {target_domain} by user '{current_user}'")
                writer.write(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            resolved_ip = await custom_dns_resolve(target_domain)
            if not resolved_ip:
                writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

            remote_reader, remote_writer = await asyncio.open_connection(resolved_ip, target_port)
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

            await asyncio.gather(
                relay_data(reader, remote_writer, current_user, target_domain),
                relay_data(remote_reader, writer, current_user, target_domain)
            )

        elif cmd == 0x03:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(("0.0.0.0", 0))
            b_port = udp_sock.getsockname()[1]
            
            b_ip_bytes = socket.inet_aton("0.0.0.0")
            b_port_bytes = struct.pack('>H', b_port)
            writer.write(b'\x05\x00\x00\x01' + b_ip_bytes + b_port_bytes)
            await writer.drain()
            
            u_task = asyncio.create_task(udp_handler(udp_sock, client_addr))
            try:
                while True:
                    keep = await reader.read(1)
                    if not keep:
                        break
            except:
                pass
            finally:
                u_task.cancel()
                udp_sock.close()

    except:
        pass
    finally:
        writer.close()

async def handle_http_connect(reader, writer, initial_data):
    try:
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "Unknown"
        
        if is_ip_banned(client_ip):
            writer.close()
            return
        
        header_data = initial_data
        while b'\r\n\r\n' not in header_data:
            chunk = await reader.read(4096)
            if not chunk:
                break
            header_data += chunk

        headers_text = header_data.decode('utf-8', errors='ignore')
        lines = headers_text.split('\r\n')
        first_line = lines[0].split(' ')
        current_user = "anonymous"
        
        if len(first_line) >= 2 and first_line[0] == 'CONNECT':
            if config["auth_enabled"]:
                auth_passed = False
                for line in lines:
                    if line.lower().startswith('proxy-authorization: basic '):
                        encoded_creds = line.split(' ')[2]
                        try:
                            decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                            u, p = decoded_creds.split(':', 1)
                            if check_auth(u, p):
                                clear_failed_attempt(client_ip)
                                auth_passed = True
                                current_user = u
                            else:
                                record_failed_attempt(client_ip)
                        except:
                            record_failed_attempt(client_ip)
                        break
                
                if not auth_passed:
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n')
                    writer.write(b'Proxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                    await writer.drain()
                    writer.close()
                    return

            host_port = first_line[1].split(':')
            target_domain = host_port[0]
            target_port = int(host_port[1]) if len(host_port) > 1 else 443

            if is_blacklisted(target_domain):
                writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                await writer.drain()
                writer.close()
                return

            resolved_ip = await custom_dns_resolve(target_domain)
            if not resolved_ip:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                writer.close()
                return

            remote_reader, remote_writer = await asyncio.open_connection(resolved_ip, target_port)
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            await asyncio.gather(
                relay_data(reader, remote_writer, current_user, target_domain),
                relay_data(remote_reader, writer, current_user, target_domain)
            )
        else:
            writer.close()
    except:
        pass
    finally:
        writer.close()

async def proxy_handler(reader, writer):
    try:
        initial_data = await reader.read(2)
        if not initial_data:
            writer.close()
            return

        if initial_data[0] == 0x05:
            await handle_socks5(reader, writer, initial_data)
        elif initial_data[0] in [b'C'[0], b'G'[0], b'P'[0]]:
            await handle_http_connect(reader, writer, initial_data)
        else:
            writer.close()
    except:
        writer.close()

async def run_server():
    try:
        server = await asyncio.start_server(proxy_handler, config["host"], config["port"])
        logging.info(f"Proxy Server started gracefully on {config['host']}:{config['port']}")
        asyncio.create_task(config_watcher())
        async with server:
            await server.serve_forever()
    except OSError:
        print(f"\n[!] Port {config['port']} is already in use by another instance.")
        print("[!] Management mode only. Settings will sync to the background server automatically.\n")
        asyncio.create_task(config_watcher())
        while True:
            await asyncio.sleep(3600)

def wait_for_exit():
    global stop_live_monitor
    input()
    stop_live_monitor = True

def terminal_ui():
    global stop_live_monitor
    while True:
        clear_screen()
        # هدر اختصاصی PaddleProxy
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        RESET = "\033[0m"

        print(f"{CYAN}{'='*45}{RESET}")
        print(f"{CYAN}       PADDLE PROXY - Management Console{RESET}")
        print(f"{CYAN}{'='*45}{RESET}")
        print(f" Status: {GREEN}Running{RESET} on {config['host']}:{config['port']}")
        print(f" Active DNS: {YELLOW}{', '.join(config['dns'])}{RESET}")
        print(f" Auth Mode: {'Enabled' if config['auth_enabled'] else 'Disabled'}")
        print(f"{CYAN}{'='*45}{RESET}")
        
        print(" 1. Manage Users (Add/Update/List)")
        print(" 2. Live Traffic Monitor")
        print(" 3. Add to Blacklist")
        print(" 4. View/Clear Blacklist")
        print(" 5. Toggle Authentication")
        print(" 6. Change Port (Requires Restart)")
        print(" 7. Manage DNS Servers")
        print(" 8. Banned IPs Management")
        print(f" {YELLOW}9. Exit Management (Keep Server Running){RESET}")
        print(f" {RED}0. FULL STOP (Stop Server & Exit){RESET}")
        print(f"{CYAN}{'='*45}{RESET}")
        
        choice = input(" Select an option: ")
        
        if choice == '1':
            clear_screen()
            print(f"{CYAN}--- PaddleProxy: User Management ---{RESET}")
            user_list = list(config["users"].keys())
            for idx, u in enumerate(user_list):
                exp = config["users"][u].get("expire", "")
                status = f"(Exp: {exp})" if exp else "(No Expiration)"
                print(f" [{idx+1}] {u} {status}")
            print(f" [{len(user_list)+1}] Create New User")
            print(f" [{len(user_list)+2}] Remove User")
            print("-" * 37)
            
            u_choice = input(" Select user number (or Enter to cancel): ")
            if not u_choice.isdigit() or int(u_choice) < 1 or int(u_choice) > len(user_list) + 2:
                continue
                
            u_idx = int(u_choice) - 1
            
            if u_idx == len(user_list) + 1:
                del_idx = input(" Enter number to remove: ")
                if del_idx.isdigit() and 1 <= int(del_idx) <= len(user_list):
                    del_u = user_list[int(del_idx) - 1]
                    del config["users"][del_u]
                    save_data()
                    print(f" User {del_u} removed.")
                    time.sleep(1)
                continue
                
            if u_idx == len(user_list):
                u = input(" New Username: ")
                if not u or u in config["users"]:
                    print(" Invalid or existing username.")
                    time.sleep(1)
                    continue
                config["users"][u] = {"pass": "", "quota": 0, "daily_quota": 0, "speed": 0, "expire": ""}
            else:
                u = user_list[u_idx]

            clear_screen()
            print(f"--- Updating {u} ---")
            p = input(" New Password (blank to keep): ")
            q = input(f" Total Quota MB (Current: {config['users'][u].get('quota', 0)}): ")
            dq = input(f" Daily Quota MB (Current: {config['users'][u].get('daily_quota', 0)}): ")
            s = input(f" Speed KB/s (Current: {config['users'][u].get('speed', 0)}): ")
            ex = input(f" Days valid (0 = No Expire): ")
            
            if p: config["users"][u]["pass"] = hash_password(p)
            if q.isdigit(): config["users"][u]["quota"] = int(q)
            if dq.isdigit(): config["users"][u]["daily_quota"] = int(dq)
            if s.isdigit(): config["users"][u]["speed"] = int(s)
            if ex.isdigit():
                config["users"][u]["expire"] = (date.today() + timedelta(days=int(ex))).isoformat() if int(ex) > 0 else ""
                
            save_data()
            print(f"\n {GREEN}PaddleProxy: User updated!{RESET}")
            time.sleep(1)
                
        elif choice == '2':
            stop_live_monitor = False
            threading.Thread(target=wait_for_exit, daemon=True).start()
            while not stop_live_monitor:
                clear_screen()
                print(f"{CYAN}{'='*45}{RESET}")
                print(f"       LIVE TRAFFIC MONITOR - PaddleProxy")
                print(f"           (Press ENTER to return)")
                print(f"{CYAN}{'='*45}{RESET}")
                today = date.today().isoformat()
                for u, b in stats["users"].items():
                    u_conf = config["users"].get(u, {})
                    mb_total = b / (1024*1024)
                    quota_total = u_conf.get("quota", 0)
                    d_stats = stats["daily_users"].get(u, {})
                    mb_daily = d_stats.get("bytes", 0) / (1024*1024) if d_stats.get("date") == today else 0.0
                    quota_daily = u_conf.get("daily_quota", 0)
                    exp = u_conf.get("expire", "")
                    
                    status = f"{GREEN}Active{RESET}"
                    if (quota_total > 0 and mb_total >= quota_total) or (exp and exp < today): status = f"{RED}Limit/Expired{RESET}"
                    elif quota_daily > 0 and mb_daily >= quota_daily: status = f"{YELLOW}Daily Limit{RESET}"

                    print(f" [{u}] Status: {status}")
                    print(f"   Total: {mb_total:.2f} / {quota_total or '∞'} MB")
                    print(f"   Daily: {mb_daily:.2f} / {quota_daily or '∞'} MB")
                time.sleep(1)
                
        elif choice == '3':
            domain = input(" Domain to block: ")
            if domain and domain not in config["blacklist"]:
                config["blacklist"].append(domain)
                save_data()
                
        elif choice == '4':
            print(f" Blacklisted: {config['blacklist']}")
            cmd = input(" Type 'clear' to reset or Enter to return: ")
            if cmd.lower() == 'clear':
                config["blacklist"].clear()
                save_data()
                
        elif choice == '5':
            config["auth_enabled"] = not config["auth_enabled"]
            save_data()
            
        elif choice == '6':
            p = input(" New Port: ")
            if p.isdigit():
                config["port"] = int(p)
                save_data()
                print(f" {YELLOW}Saved. Restart server to apply.{RESET}")
                time.sleep(2)

        elif choice == '7':
            clear_screen()
            print("--- DNS Management ---")
            for i, d in enumerate(config["dns"]): print(f" [{i+1}] {d}")
            print(" A: Add | C: Clear All")
            dns_choice = input("> ").upper()
            if dns_choice == 'A':
                new_dns = input(" New DNS IP: ")
                if new_dns: config["dns"].append(new_dns); save_data()
            elif dns_choice == 'C':
                new_dns = input(" Primary DNS IP: ")
                if new_dns: config["dns"] = [new_dns]; save_data()
                    
        elif choice == '8':
            clear_screen()
            print(f"{RED}--- Banned IPs (PaddleProxy Protection) ---{RESET}")
            now = time.time()
            banned_ips = [ip for ip, d in failed_attempts.items() if d['count'] >= 5 and now - d['last_attempt'] < 86400]
            if not banned_ips: print(" No IPs currently banned."); input("\nEnter to return...")
            else:
                for idx, ip in enumerate(banned_ips):
                    rem = int((86400 - (now - failed_attempts[ip]['last_attempt'])) / 60)
                    print(f" [{idx+1}] {ip} ({rem} min left)")
                u_idx = input(" Number to unban (or Enter): ")
                if u_idx.isdigit() and 0 <= int(u_idx)-1 < len(banned_ips):
                    clear_failed_attempt(banned_ips[int(u_idx)-1])
                    print(" Unbanned!")
                    time.sleep(1)

        elif choice == '9':
            clear_screen()
            script_name = os.path.basename(sys.argv[0])
            print(f" {CYAN}PaddleProxy Management closed.{RESET}")
            print(f" {GREEN}Server is still running in background.{RESET}")
            print("="*45)
            print(f"{RED}Commands for background restart:{RESET}")
            print(f" Windows: pythonw {script_name} -b")
            print(f" Linux:   nohup python3 {script_name} -b &")
            os._exit(0)
            
        elif choice == '0':
            print(f" {RED}PaddleProxy: Stopping all services...{RESET}")
            save_data()
            os._exit(0)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--background', action='store_true')
    args = parser.parse_args()

    load_data()

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    if not args.background:
        tui_thread = threading.Thread(target=terminal_ui, daemon=True)
        tui_thread.start()
    else:
        print(f"Running in background mode on {config['host']}:{config['port']}")
    
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        save_data()
        os._exit(0)