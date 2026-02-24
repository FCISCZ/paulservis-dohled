#!/usr/bin/env python3
"""
Paulservis monitoring — sberny skript
SSH na VPN1, VPN5, MK_netflix → sber dat → status.json

Pouziti:
    MK_MONITOR_PASS=xxx python3 collect.py [--config config.yaml] [--output status.json]

Env promenne:
    MK_MONITOR_PASS  — heslo pro ucet monitor na vsech MK
"""

import subprocess
import json
import yaml
import re
import os
import sys
import argparse
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed


# =============================================================================
# STEP LOG — zaznamenava co se delalo, jak dlouho, co selhalo
# =============================================================================

def step_start():
    """Vraci casovou znacku pro mereni trvani kroku."""
    return time.monotonic()


def step_log(steps, name, t0, status="ok", detail="", error=""):
    """Prida krok do logu s trvanim."""
    steps.append({
        "step": name,
        "status": status,
        "duration_s": round(time.monotonic() - t0, 2),
        "time": datetime.now(timezone.utc).isoformat(),
        "detail": detail,
        "error": error,
    })


# =============================================================================
# SSH
# =============================================================================

def ssh_cmd(host, port, user, password, command, timeout=20):
    """Spusti prikaz na MikroTiku pres SSH. Vraci (stdout, error_msg)."""
    try:
        result = subprocess.run(
            ["sshpass", "-p", password, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=10",
             "-o", "ServerAliveInterval=5",
             "-p", str(port),
             f"{user}@{host}",
             command],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout, None
        err_msg = result.stderr.strip()
        if not err_msg and result.stdout and result.stdout.strip():
            err_msg = f"exit code {result.returncode}, stdout: {result.stdout.strip()[:200]}"
        return None, err_msg or f"exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "sshpass not installed"
    except Exception as e:
        return None, str(e)


def ssh_multi(host, port, user, password, commands, timeout=30):
    """Spusti vice prikazu v jedne SSH session (oddelene ;). Vraci raw vystup."""
    joined = "; ".join(commands)
    return ssh_cmd(host, port, user, password, joined, timeout=timeout)


# =============================================================================
# PARSERY RouterOS vystupu
# =============================================================================

def parse_kv(output):
    """Parsuje key: value format (napr. /system resource print)."""
    result = {}
    if not output:
        return result
    for line in output.strip().split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace("-", "_").replace(" ", "_")
            val = val.strip()
            if val:
                result[key] = val
    return result


def parse_identity(output):
    """Parsuje /system identity print."""
    if not output:
        return ""
    kv = parse_kv(output)
    return kv.get("name", output.strip())


def parse_l2tp_peers(output):
    """Parsuje /interface l2tp-server print — vraci list aktivnich peeru.
    Kazdy peer: {name, client_address, uptime, caller_id, running}
    """
    if not output:
        return []

    peers = []
    lines = output.strip().split("\n")

    # Najdi radek s hlavickou — ten co zacina "#" a ma sloupce (ne "Columns:" popis)
    header_line = None
    header_idx = -1
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("#") and "NAME" in line:
            header_line = line
            header_idx = i
            break

    if header_line is None:
        return []

    # Pozice sloupcu z hlavicky (v7 ma: NAME, USER, MTU, CLIENT-ADDRESS, UPTIME)
    cols = {}
    for col_name in ["NAME", "USER", "MTU", "CLIENT-ADDRESS", "UPTIME", "CALLER-ID", "ENCODING"]:
        pos = header_line.find(col_name)
        if pos >= 0:
            cols[col_name] = pos

    # Parsuj datove radky
    for line in lines[header_idx + 1:]:
        if not line.strip() or line.strip().startswith("--"):
            continue

        # Odstran index a flagy na zacatku
        # Format: " 0 R ppp_cam_03 ..."
        stripped = line.lstrip()
        # Preskoc prazdne
        if not stripped:
            continue

        peer = {"running": "R" in line[:6] if len(line) > 5 else False}

        # Precti hodnoty podle pozic sloupcu
        for col_name, pos in cols.items():
            # Najdi konec sloupce (zacatek dalsiho nebo konec radku)
            next_pos = len(line)
            for other_name, other_pos in cols.items():
                if other_pos > pos and other_pos < next_pos:
                    next_pos = other_pos
            val = line[pos:next_pos].strip() if pos < len(line) else ""

            key = col_name.lower().replace("-", "_")
            if val:
                peer[key] = val

        if peer.get("name"):
            peers.append(peer)

    return peers


def parse_dhcp_leases(output):
    """Parsuje /ip dhcp-server lease print — vraci list lease."""
    if not output:
        return []

    leases = []
    lines = output.strip().split("\n")

    header_idx = -1
    header_line = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") and "ADDRESS" in line and "MAC" in line:
            header_line = line
            header_idx = i
            break

    if header_idx < 0:
        return []

    cols = {}
    for col_name in ["ADDRESS", "MAC-ADDRESS", "HOST-NAME", "SERVER", "STATUS",
                      "LAST-SEEN", "EXPIRES-AFTER"]:
        pos = header_line.find(col_name)
        if pos >= 0:
            cols[col_name] = pos

    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        lease = {}
        for col_name, pos in cols.items():
            next_pos = len(line)
            for other_name, other_pos in cols.items():
                if other_pos > pos and other_pos < next_pos:
                    next_pos = other_pos
            val = line[pos:next_pos].strip() if pos < len(line) else ""
            key = col_name.lower().replace("-", "_")
            if val:
                lease[key] = val
        if lease.get("address") or lease.get("mac_address"):
            leases.append(lease)

    return leases


def parse_ping(output):
    """Parsuje vysledek /ping — vraci True (zije), False (nezije), None (chyba)."""
    if not output:
        return None
    # Zkus summary radek (count>1)
    m = re.search(r"received=(\d+)", output)
    if m:
        return int(m.group(1)) > 0
    # Pro count=1 neni summary — hledej odpoved s casem (SIZE, TTL, TIME)
    if re.search(r"\d+ms", output):
        return True
    # Timeout
    if "timeout" in output.lower():
        return False
    return None


# =============================================================================
# PARALELNI PING — davkovy ping pres vice SSH session
# =============================================================================

PING_COUNT = 15
PING_SESSIONS = 5


def ping_batch(host, port, user, password, ips, count=PING_COUNT, timeout=90):
    """Pingne davku IP v jedne SSH session. Vraci (dict {ip: bool/None}, error_msg)."""
    if not ips:
        return {}, ""
    ping_cmds = []
    for ip in ips:
        ping_cmds.append(f':put ">>>{ip}<<<"; /ping {ip} count={count} interval=1')
    out, err = ssh_multi(host, port, user, password, ping_cmds, timeout=timeout)
    results = {}
    if out:
        chunks = re.split(r">>>([\d.]+)<<<", out)
        for i in range(1, len(chunks) - 1, 2):
            ip = chunks[i]
            ping_out = chunks[i + 1]
            results[ip] = parse_ping(ping_out)
    return results, err or ""


# =============================================================================
# SBER DAT — VPN SERVER
# =============================================================================

def collect_vpn_server(src_cfg, password, vpn_boxes):
    """Sebere data z jednoho VPN serveru (VPN1 nebo VPN5).
    Vraci (server_data, boxes_updates, error, steps).
    """
    host = src_cfg["host"]
    port = src_cfg["port"]
    user = src_cfg["user"]
    src_id = src_cfg.get("_id", "?")
    steps = []

    print(f"  [{src_id}] Pripojuji na {host}:{port}...")

    # 1. System info
    t0 = step_start()
    out, err = ssh_cmd(host, port, user, password,
                       "/system identity print; :put \"===SEP===\"; /system resource print")
    if err:
        step_log(steps, "system_info", t0, "error",
                 f"SSH {host}:{port}", err)
        print(f"  [{src_id}] CHYBA: {err}")
        return None, {}, err, steps

    parts = out.split("===SEP===") if out else ["", ""]
    identity = parse_identity(parts[0]) if len(parts) > 0 else ""
    resource = parse_kv(parts[1]) if len(parts) > 1 else {}

    server = {
        "status": "online",
        "identity": identity,
        "routeros": resource.get("version", "").split(" ")[0],
        "uptime": resource.get("uptime", ""),
        "board_name": resource.get("board_name", ""),
    }
    step_log(steps, "system_info", t0, "ok",
             f"{identity}, uptime {server['uptime']}")
    print(f"  [{src_id}] Online — {identity}, uptime {server['uptime']}")

    # 2. L2TP peers
    t0 = step_start()
    out, err = ssh_cmd(host, port, user, password,
                       "/interface l2tp-server print")
    peers = parse_l2tp_peers(out) if out else []
    step_log(steps, "l2tp_peers", t0,
             "ok" if not err else "error",
             f"{len(peers)} peeru",
             err or "")
    print(f"  [{src_id}] L2TP peeru: {len(peers)}")

    # Mapuj peers na cisla boxu
    peer_map = {}
    for p in peers:
        num = None
        for field in ["name", "user"]:
            val = p.get(field, "")
            m = re.search(r"ppp_cam_(\d+)", val)
            if m:
                num = m.group(1).zfill(2)
                break
        if num:
            peer_map[num] = p

    # 3. DHCP leases
    t0 = step_start()
    out, err = ssh_cmd(host, port, user, password,
                       "/ip dhcp-server lease print")
    leases = parse_dhcp_leases(out) if out else []
    normalized_leases = []
    for l in leases:
        normalized_leases.append({
            "ip": l.get("address", ""),
            "mac": l.get("mac_address", ""),
            "hostname": l.get("host_name", ""),
            "last_seen": l.get("last_seen", ""),
            "expires": l.get("expires_after", ""),
        })
    server["dhcp_leases"] = normalized_leases
    step_log(steps, "dhcp_leases", t0,
             "ok" if not err else "error",
             f"{len(leases)} lease",
             err or "")
    print(f"  [{src_id}] DHCP lease: {len(leases)}")

    # 4. Bridge host + ARP → auto-discovery kamer
    t0 = step_start()
    out_bh, err_bh = ssh_cmd(host, port, user, password,
                        "/interface bridge host print", timeout=15)
    out_arp, err_arp = ssh_cmd(host, port, user, password,
                         "/ip arp print where interface=bridge1", timeout=15)

    arp_mac_to_ip = {}
    if out_arp:
        for line in out_arp.strip().split("\n"):
            m = re.search(r"([\d.]+)\s+([0-9A-Fa-f:]{17})", line)
            if m:
                arp_mac_to_ip[m.group(2).upper()] = m.group(1)

    tunnel_macs = {}
    if out_bh:
        for line in out_bh.strip().split("\n"):
            m = re.search(r"([0-9A-Fa-f:]{17})\s+(<(?:l2tp|pptp)-ppp_cam_\d+>)", line)
            if m:
                mac = m.group(1).upper()
                iface = m.group(2)
                if iface not in tunnel_macs:
                    tunnel_macs[iface] = set()
                tunnel_macs[iface].add(mac)

    tunnel_cameras = {}
    for box in vpn_boxes:
        num = box["num"]
        iface_candidates = [
            f"<l2tp-ppp_cam_{num}>", f"<l2tp-ppp_cam_{int(num)}>",
            f"<pptp-ppp_cam_{num}>", f"<pptp-ppp_cam_{int(num)}>",
        ]
        iface = None
        for candidate in iface_candidates:
            if candidate in tunnel_macs:
                iface = candidate
                break
        mk_ip = f"192.168.50.{int(num)}"
        cam_ips = []
        macs = tunnel_macs.get(iface, set()) if iface else set()
        for mac in macs:
            ip = arp_mac_to_ip.get(mac, "")
            if ip and ip != mk_ip and ip != "192.168.50.254":
                cam_ips.append(ip)
        tunnel_cameras[num] = sorted(cam_ips)

    discovered = sum(len(v) for v in tunnel_cameras.values())
    disc_err = ""
    if err_bh:
        disc_err += f"bridge: {err_bh} "
    if err_arp:
        disc_err += f"arp: {err_arp}"
    step_log(steps, "discovery", t0,
             "ok" if not disc_err else "error",
             f"{discovered} kamer, {len(arp_mac_to_ip)} ARP zaznamu",
             disc_err)
    print(f"  [{src_id}] Objeveno kamer za boxy: {discovered}")

    # 5. Ping vsechno — paralelne (5 SSH session, count=15)
    t0 = step_start()
    all_ping_ips = []
    for box in vpn_boxes:
        mk_ip = f"192.168.50.{int(box['num'])}"
        all_ping_ips.append(mk_ip)
        for cam_ip in tunnel_cameras.get(box["num"], []):
            all_ping_ips.append(cam_ip)

    ping_alive = {}
    ping_err = ""
    mk_alive = 0
    cam_alive = 0
    batches = []
    if all_ping_ips:
        # Rozdeleni do davek pro paralelni SSH session
        batch_size = max(1, (len(all_ping_ips) + PING_SESSIONS - 1) // PING_SESSIONS)
        batches = [all_ping_ips[i:i + batch_size]
                   for i in range(0, len(all_ping_ips), batch_size)]
        # Timeout: count=15 * 1s interval + overhead per IP
        batch_timeout = max(90, batch_size * 18)

        print(f"  [{src_id}] Ping {len(all_ping_ips)} IP v {len(batches)} session (count={PING_COUNT})...")
        errors = []
        with ThreadPoolExecutor(max_workers=PING_SESSIONS) as executor:
            futures = {
                executor.submit(ping_batch, host, port, user, password,
                                batch, PING_COUNT, batch_timeout): batch
                for batch in batches
            }
            for future in as_completed(futures):
                results, err = future.result()
                ping_alive.update(results)
                if err:
                    errors.append(err)

        if errors:
            ping_err = "; ".join(errors)

        mk_alive = sum(1 for b in vpn_boxes if ping_alive.get(f"192.168.50.{int(b['num'])}"))
        cam_alive = sum(1 for ip, v in ping_alive.items() if v and not any(
            ip == f"192.168.50.{int(b['num'])}" for b in vpn_boxes))
        print(f"  [{src_id}] MK boxy ping: {mk_alive}/{len(vpn_boxes)} zije")
        print(f"  [{src_id}] Kamery ping: {cam_alive}/{discovered} zije")

    # Sestav detail — vcetne seznamu selhanych IP
    ping_detail = f"{len(all_ping_ips)} IP v {len(batches) if all_ping_ips else 0} session (count={PING_COUNT}), MK {mk_alive}/{len(vpn_boxes)}, kam {cam_alive}/{discovered}"
    failed_ips = [ip for ip in all_ping_ips if ping_alive.get(ip) is False]
    none_ips = [ip for ip in all_ping_ips if ip not in ping_alive]
    if failed_ips:
        ping_detail += " | OFFLINE: " + ", ".join(failed_ips)
    if none_ips:
        ping_detail += " | bez odpovedi: " + ", ".join(none_ips)

    step_log(steps, "ping", t0,
             "ok" if not ping_err and not failed_ips else "error" if ping_err else "warn",
             ping_detail,
             ping_err)

    # 6. Sestav box updates
    box_updates = {}
    for box in vpn_boxes:
        num = box["num"]
        peer = peer_map.get(num)
        mk_ip = f"192.168.50.{int(num)}"
        ping_ok = ping_alive.get(mk_ip)

        # Ping je rozhodujici — L2TP peer tabulka jen doplnkova info
        if ping_ok is True:
            status = "online"
        elif ping_ok is False:
            status = "offline"
        elif peer:
            # Ping se nevykonal/nevyhodnotil, ale L2TP peer existuje (fallback)
            status = "online"
        else:
            status = "offline"

        update = {
            "mk_status": status,
            "uptime": peer.get("uptime", "") if peer else "",
            "client_ip": peer.get("client_address", "") if peer else "",
        }

        cam_updates = []
        discovered_cam_ips = tunnel_cameras.get(num, [])
        if discovered_cam_ips:
            for cam_ip in discovered_cam_ips:
                cam_ping = ping_alive.get(cam_ip)
                cam_updates.append({
                    "ip": cam_ip,
                    "status": "online" if cam_ping else "offline" if cam_ping is False else "nevycteno",
                })
        else:
            for cam in box.get("cams", []):
                cam_updates.append({
                    "ip": cam.get("ip", ""),
                    "status": "nevycteno",
                })
        update["cam_statuses"] = cam_updates
        box_updates[f"{box['vpn']}_{num}"] = update

    return server, box_updates, None, steps


# =============================================================================
# SBER DAT — LOKALNI ZARIZENI (pres MK_netflix)
# =============================================================================

def collect_local(src_cfg, password, local_devices):
    """Pingne lokalni zarizeni pres MK_netflix. Vraci (device_updates, error, steps)."""
    host = src_cfg["host"]
    port = src_cfg["port"]
    user = src_cfg["user"]
    steps = []

    print(f"  [mk_netflix] Pripojuji na {host}:{port}...")

    # Seber vsechny IP co chceme pingnout
    all_ips = []
    for dev in local_devices:
        if dev.get("mk_ip"):
            all_ips.append(dev["mk_ip"])
        for cam in dev.get("cams", []):
            if cam.get("ip"):
                all_ips.append(cam["ip"])
        for tech in dev.get("tech", []):
            if tech.get("ip"):
                all_ips.append(tech["ip"])

    if not all_ips:
        step_log(steps, "ping_local", step_start(), "ok", "zadne IP k pingnuti")
        return {}, None, steps

    # Ping vsechny v jedne SSH session
    t0 = step_start()
    ping_cmds = []
    for ip in all_ips:
        ping_cmds.append(f':put ">>>{ip}<<<"; /ping {ip} count=3 interval=1')

    out, err = ssh_multi(host, port, user, password, ping_cmds,
                         timeout=max(60, len(all_ips) * 4))
    if err:
        step_log(steps, "ping_local", t0, "error",
                 f"SSH {host}:{port}, {len(all_ips)} IP", err)
        print(f"  [mk_netflix] CHYBA: {err}")
        return {}, err, steps

    # Parsuj vysledky
    ip_alive = {}
    if out:
        chunks = re.split(r">>>([\d.]+)<<<", out)
        for i in range(1, len(chunks) - 1, 2):
            ip = chunks[i]
            ping_out = chunks[i + 1]
            ip_alive[ip] = parse_ping(ping_out)

    alive_count = sum(1 for v in ip_alive.values() if v)
    local_detail = f"{alive_count}/{len(all_ips)} zije"
    failed_local = [ip for ip in all_ips if ip_alive.get(ip) is False]
    none_local = [ip for ip in all_ips if ip not in ip_alive]
    if failed_local:
        local_detail += " | OFFLINE: " + ", ".join(failed_local)
    if none_local:
        local_detail += " | bez odpovedi: " + ", ".join(none_local)

    step_log(steps, "ping_local", t0,
             "ok" if not failed_local else "warn",
             local_detail)
    print(f"  [mk_netflix] Lokalni: {alive_count}/{len(all_ips)} zije")

    # Sestav updates
    dev_updates = {}
    for dev in local_devices:
        num = dev["num"]
        mk_ip = dev.get("mk_ip")

        update = {}
        if mk_ip:
            alive = ip_alive.get(mk_ip)
            update["mk_status"] = "online" if alive else ("offline" if alive is False else "nevycteno")
        else:
            first_cam = dev["cams"][0] if dev.get("cams") else None
            if first_cam:
                alive = ip_alive.get(first_cam["ip"])
                update["mk_status"] = "online" if alive else ("offline" if alive is False else "nevycteno")

        cam_updates = []
        for cam in dev.get("cams", []):
            ip = cam.get("ip", "")
            alive = ip_alive.get(ip)
            cam_updates.append({
                "ip": ip,
                "status": "online" if alive else ("offline" if alive is False else "nevycteno"),
            })
        update["cam_statuses"] = cam_updates

        tech_updates = []
        for tech in dev.get("tech", []):
            ip = tech.get("ip", "")
            alive = ip_alive.get(ip)
            tech_updates.append({
                "ip": ip,
                "status": "online" if alive else ("offline" if alive is False else "nevycteno"),
            })
        update["tech_statuses"] = tech_updates
        dev_updates[f"lok_{num}"] = update

    return dev_updates, None, steps


# =============================================================================
# SBER DAT — LOKALNI SITE (MK za gateway, pristup pres /system ssh + expect)
# =============================================================================

def ssh_hop_expect(gw_host, gw_port, gw_user, gw_password,
                   target_ip, target_port, target_user, target_password,
                   commands, identity_match="", timeout=30):
    """SSH hop pres gateway MK na cilovy MK pomoci /system ssh + expect.
    Vraci (stdout, error_msg)."""
    # Matchovani promptu — identita cile v "] >"
    prompt_match = f'{identity_match}] >' if identity_match else '] >'

    # Sestav expect skript
    cmd_block = ""
    for cmd in commands:
        cmd_block += f'send "{cmd}\\r"\n'
        cmd_block += f'expect "{prompt_match}"\n'

    expect_script = f'''set timeout {timeout}
spawn sshpass -p "{gw_password}" ssh -p {gw_port} -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 {gw_user}@{gw_host} "/system ssh address={target_ip} port={target_port} user={target_user}"
expect {{
    "assword:" {{ send "{target_password}\\r" }}
    timeout {{ puts "EXPECT_TIMEOUT_LOGIN"; exit 1 }}
}}
expect {{
    "{prompt_match}" {{ }}
    timeout {{ puts "EXPECT_TIMEOUT_PROMPT"; exit 1 }}
}}
{cmd_block}send "/quit\\r"
expect eof
'''
    try:
        result = subprocess.run(
            ["expect", "-c", expect_script],
            capture_output=True, text=True, timeout=timeout + 15
        )
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            if "EXPECT_TIMEOUT" in (result.stdout or ""):
                return None, "expect timeout (login nebo prompt)"
            return None, err or f"expect exit code {result.returncode}"
        return result.stdout, None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    except FileNotFoundError:
        return None, "expect not installed"
    except Exception as e:
        return None, str(e)


def collect_local_site(src_id, src_cfg, sources, password):
    """Sebere system info + DHCP z MK za gateway (pres /system ssh + expect).
    Vraci (server_data, error, steps)."""
    gw_id = src_cfg.get("gateway")
    gw_cfg = sources.get(gw_id, {})
    target_ip = src_cfg["target_ip"]
    target_port = src_cfg.get("target_port", 22)
    target_user = src_cfg.get("target_user", "monitor")
    steps = []

    print(f"  [{src_id}] Pripojuji pres {gw_id} na {target_ip}:{target_port}...")

    t0 = step_start()
    commands = [
        "/system identity print",
        "/system resource print",
        "/ip dhcp-server lease print",
    ]
    out, err = ssh_hop_expect(
        gw_host=gw_cfg["host"], gw_port=gw_cfg["port"],
        gw_user=gw_cfg["user"], gw_password=password,
        target_ip=target_ip, target_port=target_port,
        target_user=target_user, target_password=password,
        commands=commands, timeout=30
    )
    if err:
        step_log(steps, "system_info", t0, "error",
                 f"expect hop {gw_id}→{target_ip}", err)
        print(f"  [{src_id}] CHYBA: {err}")
        return None, err, steps

    # Parsuj vystup — hledame vysledky prikazu v expect transkriptu
    identity = ""
    routeros = ""
    uptime = ""
    dhcp_out = ""

    if out:
        # identity
        m = re.search(r"name:\s*(.+)", out)
        if m:
            identity = m.group(1).strip()
        # resource
        resource = parse_kv(out)
        routeros = resource.get("version", "").split(" ")[0]
        uptime = resource.get("uptime", "")
        # DHCP — hledame tabulku s lease
        dhcp_match = re.search(r"(Flags:.*?(?:#.*?ADDRESS.*?MAC.*?$.*?))", out,
                               re.MULTILINE | re.DOTALL)
        if dhcp_match:
            dhcp_out = dhcp_match.group(0)
        else:
            # Fallback: vsechno od "Flags:" do konce
            idx = out.find("Flags:")
            if idx >= 0:
                dhcp_out = out[idx:]

    server = {
        "status": "online",
        "identity": identity,
        "routeros": routeros,
        "uptime": uptime,
    }
    step_log(steps, "system_info", t0, "ok",
             f"{identity}, uptime {uptime}")
    print(f"  [{src_id}] Online — {identity}, uptime {uptime}")

    # DHCP
    t0 = step_start()
    leases = parse_dhcp_leases(dhcp_out)
    normalized_leases = []
    for l in leases:
        normalized_leases.append({
            "ip": l.get("address", ""),
            "mac": l.get("mac_address", ""),
            "hostname": l.get("host_name", ""),
            "last_seen": l.get("last_seen", ""),
            "expires": l.get("expires_after", ""),
        })
    server["dhcp_leases"] = normalized_leases
    step_log(steps, "dhcp_leases", t0, "ok", f"{len(leases)} lease")
    print(f"  [{src_id}] DHCP lease: {len(leases)}")

    return server, None, steps


# =============================================================================
# SNMP — NVR
# =============================================================================

def collect_nvr_snmp(nvr_cfg, sources, password):
    """Vycte SNMP data z NVR (Uniview) pres MK /tool snmp-get.
    SSH na VPN server → snmp-get na local_ip NVR. Vraci (dict nebo None, step)."""
    snmp = nvr_cfg.get("snmp")
    if not snmp:
        return None, None

    nvr_ip = nvr_cfg.get("local_ip", "")
    community = snmp.get("community", "cist")
    if not nvr_ip:
        return None, None

    vpn_id = nvr_cfg.get("vpn", "vpn1")
    src = sources.get(vpn_id)
    if not src:
        return None, None

    print(f"  [NVR {nvr_cfg['id']}] SNMP {nvr_ip} (pres {vpn_id})...")

    oids = {
        "devinfo": "1.3.6.1.4.1.25506.20.1.0",
        "disktotal": "1.3.6.1.4.1.25506.20.2.0",
        "diskdetail": "1.3.6.1.4.1.25506.20.3.0",
    }

    t0 = step_start()
    try:
        cmds = []
        for name, oid in oids.items():
            cmds.append(f':put ">>>{name}<<<"; :put [/tool snmp-get address={nvr_ip} community={community} oid={oid} as-value]')

        out, err = ssh_multi(src["host"], src["port"], src["user"], password,
                             cmds, timeout=30)
        if err or not out:
            msg = err or "prazdny vystup"
            print(f"  [NVR {nvr_cfg['id']}] SNMP nedostupne: {msg}")
            s = {"step": f"snmp_{nvr_cfg['id']}", "status": "error",
                 "duration_s": round(time.monotonic() - t0, 2),
                 "time": datetime.now(timezone.utc).isoformat(),
                 "detail": f"{nvr_ip} pres {vpn_id}", "error": msg}
            return None, s

        data = {"snmp_time": datetime.now(timezone.utc).isoformat(), "ip": nvr_ip}

        chunks = re.split(r">>>([\w]+)<<<", out)
        raw = {}
        for i in range(1, len(chunks) - 1, 2):
            chunk = chunks[i + 1]
            m = re.search(r"value=(.*)", chunk)
            if m:
                raw[chunks[i]] = m.group(1).strip()

        if not raw:
            print(f"  [NVR {nvr_cfg['id']}] SNMP nedostupne")
            s = {"step": f"snmp_{nvr_cfg['id']}", "status": "error",
                 "duration_s": round(time.monotonic() - t0, 2),
                 "time": datetime.now(timezone.utc).isoformat(),
                 "detail": f"{nvr_ip} pres {vpn_id}", "error": "zadna data v odpovedi"}
            return None, s

        devinfo = raw.get("devinfo", "")
        m = re.search(r"DevModel:\s*(\S+)", devinfo)
        if m:
            data["model"] = m.group(1)
        m = re.search(r"SoftwareVersion:\s*(\S+)", devinfo)
        if m:
            data["fw"] = m.group(1)
        m = re.search(r"DevSeqNumber:\s*(\S+)", devinfo)
        if m:
            data["sn"] = m.group(1)

        disktotal = raw.get("disktotal", "")
        m = re.search(r"DiskTotalNum:\s*(\d+)", disktotal)
        if m:
            data["disk_total_num"] = int(m.group(1))
        m = re.search(r"DiskTotalCapacity:\s*(\d+)", disktotal)
        if m:
            data["capacity_tb"] = round(int(m.group(1)) / 1024 / 1024, 2)

        diskdetail = raw.get("diskdetail", "")
        disks = []
        for dm in re.finditer(r"DiskID:\s*(\d+):\s*Disk Space:\s*(\d+)\(KB\).*?Status:\s*(\d+)", diskdetail):
            disk_id = int(dm.group(1))
            space_kb = int(dm.group(2))
            status_code = int(dm.group(3))
            disks.append({
                "id": disk_id,
                "tb": round(space_kb / 1024 / 1024, 2),
                "status": "aktivni" if status_code == 3 else "prazdny",
            })
        if disks:
            data["disks"] = disks

        print(f"  [NVR {nvr_cfg['id']}] SNMP OK — {data.get('model', '?')}, {len(disks)} disku")
        s = {"step": f"snmp_{nvr_cfg['id']}", "status": "ok",
             "duration_s": round(time.monotonic() - t0, 2),
             "time": datetime.now(timezone.utc).isoformat(),
             "detail": f"{data.get('model', '?')}, {len(disks)} disku",
             "error": ""}
        return data, s

    except Exception as e:
        print(f"  [NVR {nvr_cfg['id']}] SNMP chyba: {e}")
        s = {"step": f"snmp_{nvr_cfg['id']}", "status": "error",
             "duration_s": round(time.monotonic() - t0, 2),
             "time": datetime.now(timezone.utc).isoformat(),
             "detail": f"{nvr_ip} pres {vpn_id}", "error": str(e)}
        return None, s


# =============================================================================
# SNMP — LTE SIGNAL (MikroTik boxy)
# =============================================================================

# MikroTik enterprise OIDy pro LTE signal
LTE_OIDS = {
    "rssi": "1.3.6.1.4.1.14988.1.1.16.1.1.2",
    "rsrq": "1.3.6.1.4.1.14988.1.1.16.1.1.3",
    "rsrp": "1.3.6.1.4.1.14988.1.1.16.1.1.4",
    "sinr": "1.3.6.1.4.1.14988.1.1.16.1.1.7",
}
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"  # ifTable ifDescr


def collect_lte_snmp(vpn_id, src_cfg, password, lte_boxes):
    """Vycte LTE signal ze vsech LTE boxu na jednom VPN serveru.
    Vsechno v jedne SSH session. Vraci (dict {box_key: lte_data}, step)."""
    if not lte_boxes:
        return {}, None

    host = src_cfg["host"]
    port = src_cfg["port"]
    user = src_cfg["user"]
    t0 = step_start()

    print(f"  [{vpn_id}] LTE SNMP: {len(lte_boxes)} boxu...")

    # Krok 1: Zjisti ifIndex lte1 — zkousime indexy ODDELENE SSH sessions.
    # snmp-get na neexistujici index vraci "interrupted" a zabije zbytek
    # prikazu v retezci (CCR2004 bug). Proto kazdy index = vlastni SSH.
    FAST_INDEXES = [6, 7]

    box_ifindex = {}

    def _parse_ifindex(output, boxes, idx):
        """Parsuj ifIndex odpovedi pro jeden index."""
        if not output:
            return
        for box in boxes:
            num = box["num"]
            marker = f">>ifidx_{num}_{idx}<<"
            pos = output.find(marker)
            if pos >= 0:
                chunk = output[pos + len(marker):]
                next_marker = chunk.find(">>")
                if next_marker > 0:
                    chunk = chunk[:next_marker]
                if "lte1" in chunk:
                    box_ifindex[num] = idx

    err = None
    for idx in FAST_INDEXES:
        remaining = [b for b in lte_boxes if b["num"] not in box_ifindex]
        if not remaining:
            break
        cmds = []
        for box in remaining:
            num = box["num"]
            ip = f"192.168.50.{int(num)}"
            cmds.append(f':put ">>ifidx_{num}_{idx}<<"; /tool snmp-get address={ip} community=cist oid={IF_DESCR_OID}.{idx}')
        out, err = ssh_multi(host, port, user, password, cmds,
                             timeout=max(60, len(remaining) * 8))
        _parse_ifindex(out, remaining, idx)

    # Fallback: boxy kde jsme nenasli lte1 na 6/7 — zkusime 1-10 (po jednom)
    missing = [b for b in lte_boxes if b["num"] not in box_ifindex]
    if missing and not err:
        for idx in range(1, 11):
            if idx in FAST_INDEXES:
                continue
            still_missing = [b for b in missing if b["num"] not in box_ifindex]
            if not still_missing:
                break
            cmds_fb = []
            for box in still_missing:
                num = box["num"]
                ip = f"192.168.50.{int(num)}"
                cmds_fb.append(f':put ">>ifidx_{num}_{idx}<<"; /tool snmp-get address={ip} community=cist oid={IF_DESCR_OID}.{idx}')
            out_fb, _ = ssh_multi(host, port, user, password, cmds_fb,
                                  timeout=max(60, len(still_missing) * 8))
            _parse_ifindex(out_fb, still_missing, idx)

    if err and not box_ifindex:
        print(f"  [{vpn_id}] LTE ifIndex CHYBA: {err}")
        s = {"step": f"lte_snmp_{vpn_id}", "status": "error",
             "duration_s": round(time.monotonic() - t0, 2),
             "time": datetime.now(timezone.utc).isoformat(),
             "detail": f"{len(lte_boxes)} boxu", "error": err}
        return {}, s

    if not box_ifindex:
        print(f"  [{vpn_id}] LTE: zadny box nema lte1 interface")
        s = {"step": f"lte_snmp_{vpn_id}", "status": "error",
             "duration_s": round(time.monotonic() - t0, 2),
             "time": datetime.now(timezone.utc).isoformat(),
             "detail": f"0/{len(lte_boxes)} ifIndex nalezen", "error": "zadny lte1"}
        return {}, s

    print(f"  [{vpn_id}] LTE ifIndex: {len(box_ifindex)}/{len(lte_boxes)} nalezeno")

    # Krok 2: Vycti LTE signal
    cmds2 = []
    for box in lte_boxes:
        num = box["num"]
        idx = box_ifindex.get(num)
        if not idx:
            continue
        ip = f"192.168.50.{int(num)}"
        for name, oid in LTE_OIDS.items():
            cmds2.append(f':put ">>lte_{num}_{name}<<"; /tool snmp-get address={ip} community=cist oid={oid}.{idx}')

    out2, err2 = ssh_multi(host, port, user, password, cmds2,
                           timeout=max(60, len(cmds2) * 3))

    # Parsuj signal
    results = {}
    ok_count = 0
    fail_detail = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for box in lte_boxes:
        num = box["num"]
        key = f"{vpn_id}_{num}"
        idx = box_ifindex.get(num)
        if not idx:
            fail_detail.append(f"box {num}: ifIndex nenalezen")
            continue

        lte_data = {"snmp_time": now_iso, "ifindex": idx}
        got_any = False

        if out2:
            for name in LTE_OIDS:
                marker = f">>lte_{num}_{name}<<"
                pos = out2.find(marker)
                if pos >= 0:
                    chunk = out2[pos + len(marker):]
                    next_marker = chunk.find(">>")
                    if next_marker > 0:
                        chunk = chunk[:next_marker]
                    m = re.search(r"integer\s+(-?\d+)", chunk)
                    if m:
                        lte_data[name] = int(m.group(1))
                        got_any = True

        if got_any:
            results[key] = lte_data
            ok_count += 1
        else:
            fail_detail.append(f"box {num}: prazdna odpoved")

    detail = f"{ok_count}/{len(lte_boxes)} boxu"
    if fail_detail:
        detail += " | " + ", ".join(fail_detail)
    print(f"  [{vpn_id}] LTE SNMP: {ok_count}/{len(lte_boxes)} OK")

    s = {"step": f"lte_snmp_{vpn_id}",
         "status": "ok" if ok_count == len(lte_boxes) else "warn" if ok_count > 0 else "error",
         "duration_s": round(time.monotonic() - t0, 2),
         "time": now_iso,
         "detail": detail,
         "error": err2 or ""}
    return results, s


def load_lte_history(path):
    """Nacte historii LTE signalu z JSON souboru."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def update_lte_history(history, new_data, max_age_days=7):
    """Prida nove mereni do historie a orize stare zaznamy."""
    cutoff = datetime.now(timezone.utc).timestamp() - max_age_days * 86400

    for key, lte in new_data.items():
        entry = {"t": lte["snmp_time"]}
        for field in ("rssi", "rsrp", "rsrq", "sinr"):
            if field in lte:
                entry[field] = lte[field]

        if key not in history:
            history[key] = []
        history[key].append(entry)

    # Orez stare zaznamy
    for key in list(history.keys()):
        filtered = []
        for rec in history[key]:
            try:
                t = datetime.fromisoformat(rec["t"].replace("Z", "+00:00")).timestamp()
                if t > cutoff:
                    filtered.append(rec)
            except (ValueError, KeyError):
                pass
        if filtered:
            history[key] = filtered
        else:
            del history[key]

    return history


def save_lte_history(history, path):
    """Zapise historii LTE signalu do JSON souboru."""
    with open(path, "w") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# =============================================================================
# HLAVNI LOGIKA — sestav status.json
# =============================================================================

def build_status(config, vpn_results, local_results, nvr_snmp, run_meta=None,
                  lte_snmp=None, lte_history=None, local_site_results=None):
    """Sestavi status.json z konfigurace + zivych dat."""
    now = datetime.now(timezone.utc).isoformat()

    status = {
        "timestamp": now,
        "check_interval_min": 15,
        "run": run_meta or {},
        "collection": {},
        "nvr": [],
        "vpn_servers": [],
        "boxes": [],
    }

    # --- Collection status + kroky ---
    for src_id, (server_data, box_upd, err, steps) in vpn_results.items():
        status["collection"][src_id] = {
            "status": "ok" if server_data else "error",
            "error": err or "",
            "time": now,
            "steps": steps,
        }
    local_updates, local_err, local_steps = local_results
    status["collection"]["mk_netflix"] = {
        "status": "ok" if local_updates else "error",
        "error": local_err or "",
        "time": now,
        "steps": local_steps,
    }

    # --- NVR ---
    for nvr_cfg in config.get("nvr", []):
        nvr = {
            "id": nvr_cfg["id"],
            "name": nvr_cfg["name"],
            "role": nvr_cfg.get("role", ""),
            "ip": nvr_cfg["ip"],
            "local_ip": nvr_cfg.get("local_ip") or "—",
            "vpn": nvr_cfg["vpn"],
            "status": "online",  # TODO: ping/snmp check
            "streams": None,
        }
        # SNMP data
        snmp_data = nvr_snmp.get(nvr_cfg["id"])
        if snmp_data:
            nvr["snmp"] = snmp_data
            nvr["snmp_status"] = "vycteno"
        elif nvr_cfg.get("snmp"):
            nvr["snmp_status"] = "nevycteno"
        else:
            nvr["snmp_status"] = "neni"

        status["nvr"].append(nvr)

    # --- VPN servers ---
    for src_id in ["vpn1", "vpn5"]:
        src_cfg = config["sources"][src_id]
        server_data, _, _, _ = vpn_results.get(src_id, (None, {}, None, []))

        vpn = {
            "id": src_id,
            "name": src_cfg.get("identity", src_id.upper()),
            "ip": src_cfg["host"],
            "port": src_cfg["port"],
            "model": src_cfg.get("model", ""),
            "bridge_ip": src_cfg.get("bridge_ip", ""),
            "status": "online" if server_data else "offline",
            "last_check": now,
            "check_interval_min": 15,
        }
        if server_data:
            vpn["routeros"] = server_data.get("routeros", "")
            vpn["uptime"] = server_data.get("uptime", "")
            vpn["identity"] = server_data.get("identity", "")
            pool = src_cfg.get("dhcp_pool", "")
            vpn["dhcp"] = {
                "pool_start": pool.split("-")[0] if "-" in pool else "",
                "pool_end": pool.split("-")[1] if "-" in pool else "",
                "leases": server_data.get("dhcp_leases", []),
            }
        # known_ips z NVR + walker + gateway
        known = []
        for nvr_cfg in config.get("nvr", []):
            if nvr_cfg.get("vpn") == src_id and nvr_cfg.get("local_ip"):
                known.append({"ip": nvr_cfg["local_ip"], "typ": "nvr", "popis": nvr_cfg["name"]})
        if src_cfg.get("walker_ip"):
            known.append({"ip": src_cfg["walker_ip"], "typ": "walker", "popis": "Walker (RDP)"})
        known.append({"ip": src_cfg.get("bridge_ip", "").split("/")[0], "typ": "gateway", "popis": f"Bridge {src_id.upper()}"})
        vpn["known_ips"] = known

        status["vpn_servers"].append(vpn)

    # --- Lokalni site (DHCP) ---
    status["local_sites"] = []
    if local_site_results:
        for src_id, (server_data, error, steps) in local_site_results.items():
            src_cfg = config["sources"][src_id]
            site = {
                "id": src_id,
                "name": src_cfg.get("identity", src_id),
                "ip": src_cfg.get("bridge_ip", "").split("/")[0],
                "model": src_cfg.get("model", ""),
                "status": "online" if server_data else "offline",
                "last_check": now,
            }
            if server_data:
                site["routeros"] = server_data.get("routeros", "")
                site["uptime"] = server_data.get("uptime", "")
                pool = src_cfg.get("dhcp_pool", "")
                site["dhcp"] = {
                    "pool_start": pool.split("-")[0] if "-" in pool else "",
                    "pool_end": pool.split("-")[1] if "-" in pool else "",
                    "leases": server_data.get("dhcp_leases", []),
                }
            status["collection"][src_id] = {
                "status": "ok" if server_data else "error",
                "error": error or "",
                "time": now,
                "steps": steps,
            }
            status["local_sites"].append(site)

    # --- VPN boxy ---
    all_box_updates = {}
    for src_id in ["vpn1", "vpn5"]:
        _, box_upd, _, _ = vpn_results.get(src_id, (None, {}, None, []))
        if box_upd:
            all_box_updates.update(box_upd)

    for box_cfg in config.get("vpn_boxes", []):
        key = f"{box_cfg['vpn']}_{box_cfg['num']}"
        upd = all_box_updates.get(key, {})

        box = {
            "num": box_cfg["num"],
            "vpn": box_cfg["vpn"],
            "nvr": box_cfg["nvr"],
            "mk_status": upd.get("mk_status", "nevycteno"),
            "mk_expected": "run",
            "uptime": upd.get("uptime", ""),
            "client_ip": upd.get("client_ip", ""),
            "lokace": box_cfg.get("lokace", ""),
            "comment": box_cfg.get("comment", ""),
            "historie": box_cfg.get("historie", []),
            "cams": [],
        }

        # Merge camera data: discovered (z bridge host) ma prednost pred config
        live_cams = upd.get("cam_statuses", [])
        if live_cams:
            # Pouzij objevene kamery (realne IP z bridge host + ARP)
            for lc in live_cams:
                cam = {
                    "ip": lc.get("ip", ""),
                    "mac": lc.get("mac", ""),
                    "model": "",
                    "ip_typ": "",
                    "status": lc.get("status", "nevycteno"),
                    "expected": "run",
                }
                box["cams"].append(cam)
        else:
            # Fallback: config kamery (nevycteno)
            for cam_cfg in box_cfg.get("cams", []):
                cam = {
                    "ip": cam_cfg.get("ip", ""),
                    "mac": cam_cfg.get("mac", ""),
                    "model": cam_cfg.get("model", ""),
                    "ip_typ": cam_cfg.get("ip_typ", ""),
                    "status": "nevycteno",
                    "expected": "run",
                }
                box["cams"].append(cam)

        # LTE signal data
        if lte_snmp and key in (lte_snmp or {}):
            lte = lte_snmp[key]
            box["lte"] = {
                "rssi": lte.get("rssi"),
                "rsrp": lte.get("rsrp"),
                "rsrq": lte.get("rsrq"),
                "sinr": lte.get("sinr"),
                "snmp_time": lte.get("snmp_time", ""),
            }
        elif box_cfg.get("lte"):
            box["lte"] = {"rssi": None, "rsrp": None, "rsrq": None, "sinr": None,
                          "snmp_time": ""}

        # LTE historie pro sparkline
        if lte_history and key in (lte_history or {}):
            box["lte_history"] = lte_history[key]

        status["boxes"].append(box)

    # --- Lokalni zarizeni ---
    dev_updates = local_updates
    for dev_cfg in config.get("local_devices", []):
        key = f"lok_{dev_cfg['num']}"
        upd = (dev_updates or {}).get(key, {})

        box = {
            "num": dev_cfg["num"],
            "typ": "lokalni",
            "vpn": None,
            "nvr": dev_cfg["nvr"],
            "mk_status": upd.get("mk_status", "nevycteno"),
            "mk_expected": "run",
            "lokace": dev_cfg.get("lokace", ""),
            "comment": dev_cfg.get("comment", ""),
            "historie": dev_cfg.get("historie", []),
            "cams": [],
        }

        if dev_cfg.get("mk_ip"):
            box["mk_ip"] = dev_cfg["mk_ip"]
            box["mk_model"] = dev_cfg.get("mk_model", "")
            box["mk_routeros"] = dev_cfg.get("mk_routeros", "")
            box["mk_identity"] = dev_cfg.get("mk_identity", "")

        cam_statuses = {c["ip"]: c for c in upd.get("cam_statuses", [])}
        for cam_cfg in dev_cfg.get("cams", []):
            ip = cam_cfg.get("ip", "")
            live = cam_statuses.get(ip, {})
            cam = {
                "ip": ip,
                "mac": cam_cfg.get("mac", ""),
                "model": cam_cfg.get("model", ""),
                "ip_typ": cam_cfg.get("ip_typ", ""),
                "status": live.get("status", "nevycteno"),
                "expected": "run",
            }
            box["cams"].append(cam)

        # Tech zarizeni
        tech_statuses = {t["ip"]: t for t in upd.get("tech_statuses", [])}
        tech_list = []
        for tech_cfg in dev_cfg.get("tech", []):
            ip = tech_cfg.get("ip", "")
            live = tech_statuses.get(ip, {})
            tech_list.append({
                "ip": ip,
                "mac": tech_cfg.get("mac", ""),
                "model": tech_cfg.get("model", ""),
                "comment": tech_cfg.get("comment", ""),
                "ip_typ": tech_cfg.get("ip_typ", ""),
                "status": live.get("status", "nevycteno"),
                "expected": "run",
            })
        if tech_list:
            box["tech"] = tech_list

        status["boxes"].append(box)

    return status


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Paulservis monitoring collector")
    parser.add_argument("--config", default="config.yaml", help="Cesta ke config.yaml")
    parser.add_argument("--output", default="status.json", help="Vystupni soubor")
    parser.add_argument("--dry-run", action="store_true", help="Jen vypis co by se delalo")
    args = parser.parse_args()

    password = os.environ.get("MK_MONITOR_PASS", "")
    if not password:
        print("CHYBA: Nastav MK_MONITOR_PASS env promennou")
        sys.exit(1)

    # Nacti config
    config_path = os.path.join(os.path.dirname(__file__) or ".", args.config)
    with open(config_path) as f:
        config = yaml.safe_load(f)

    print(f"=== Paulservis monitoring — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"Config: {config_path}")
    print(f"VPN boxu: {len(config.get('vpn_boxes', []))}")
    print(f"Lokalnich: {len(config.get('local_devices', []))}")
    print(f"NVR: {len(config.get('nvr', []))}")
    print()

    if args.dry_run:
        print("DRY RUN — konec")
        return

    run_start = datetime.now(timezone.utc)
    run_t0 = time.monotonic()

    # --- Sber z VPN serveru ---
    vpn_results = {}
    for src_id in ["vpn1", "vpn5"]:
        src_cfg = config["sources"][src_id]
        src_cfg["_id"] = src_id
        boxes = [b for b in config.get("vpn_boxes", []) if b["vpn"] == src_id]
        server_data, box_updates, error, steps = collect_vpn_server(src_cfg, password, boxes)
        vpn_results[src_id] = (server_data, box_updates if server_data else {}, error, steps)

    # --- Sber lokalnich zarizeni ---
    mk_net_cfg = config["sources"]["mk_netflix"]
    local_devs = config.get("local_devices", [])
    local_updates, local_err, local_steps = collect_local(mk_net_cfg, password, local_devs)
    local_results = (local_updates, local_err, local_steps)

    # --- Sber lokalnich site (DHCP pres gateway hop) ---
    local_site_results = {}
    for src_id, src_cfg in config.get("sources", {}).items():
        if src_cfg.get("gateway") and src_cfg.get("dhcp_pool"):
            server_data, error, steps = collect_local_site(
                src_id, src_cfg, config["sources"], password)
            local_site_results[src_id] = (server_data, error, steps)

    # --- SNMP NVR ---
    nvr_snmp = {}
    snmp_steps = []
    for nvr_cfg in config.get("nvr", []):
        snmp_data, snmp_step = collect_nvr_snmp(nvr_cfg, config["sources"], password)
        if snmp_data:
            nvr_snmp[nvr_cfg["id"]] = snmp_data
        if snmp_step:
            snmp_steps.append(snmp_step)

    # --- LTE SNMP (paralelne VPN1 + VPN5) ---
    lte_history_path = os.path.join(os.path.dirname(__file__) or ".", "lte_history.json")
    lte_history = load_lte_history(lte_history_path)
    lte_snmp = {}
    lte_steps = []

    lte_tasks = {}
    for src_id in ["vpn1", "vpn5"]:
        src_cfg = config["sources"][src_id]
        _, box_upd, _, _ = vpn_results.get(src_id, (None, {}, None, []))
        lte_boxes = [b for b in config.get("vpn_boxes", [])
                     if b["vpn"] == src_id and b.get("lte")
                     and box_upd.get(f"{src_id}_{b['num']}", {}).get("mk_status") != "offline"]
        skipped = sum(1 for b in config.get("vpn_boxes", [])
                      if b["vpn"] == src_id and b.get("lte")
                      and box_upd.get(f"{src_id}_{b['num']}", {}).get("mk_status") == "offline")
        if skipped:
            print(f"  [{src_id}] LTE: preskoceno {skipped} offline boxu")
        if lte_boxes:
            lte_tasks[src_id] = (src_cfg, lte_boxes)

    if lte_tasks:
        print(f"  LTE SNMP: paralelne {len(lte_tasks)} VPN...")
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(collect_lte_snmp, src_id, cfg, password, boxes): src_id
                for src_id, (cfg, boxes) in lte_tasks.items()
            }
            for future in as_completed(futures):
                lte_data, lte_step = future.result()
                lte_snmp.update(lte_data)
                if lte_step:
                    lte_steps.append(lte_step)

    # Aktualizuj a uloz historii
    if lte_snmp:
        lte_history = update_lte_history(lte_history, lte_snmp)
    save_lte_history(lte_history, lte_history_path)

    # --- Run metadata ---
    run_end = datetime.now(timezone.utc)
    run_meta = {
        "started": run_start.isoformat(),
        "finished": run_end.isoformat(),
        "duration_s": round(time.monotonic() - run_t0, 2),
        "runner": "github-actions" if os.environ.get("GITHUB_ACTIONS") else "local",
        "trigger": os.environ.get("GITHUB_EVENT_NAME", "manual"),
        "snmp_steps": snmp_steps,
        "lte_steps": lte_steps,
    }

    # --- Sestav a zapis status.json ---
    print()
    print("Sestavuji status.json...")
    status = build_status(config, vpn_results, local_results, nvr_snmp, run_meta,
                          lte_snmp=lte_snmp, lte_history=lte_history,
                          local_site_results=local_site_results)

    output_path = args.output
    with open(output_path, "w") as f:
        json.dump(status, f, indent=2, ensure_ascii=False)

    box_count = len(status["boxes"])
    online = sum(1 for b in status["boxes"] if b["mk_status"] == "online")
    print(f"Hotovo — {online}/{box_count} boxu online")
    print(f"Zapsano do {output_path}")


if __name__ == "__main__":
    main()
