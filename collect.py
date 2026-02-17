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
        return None, result.stderr.strip() or f"exit code {result.returncode}"
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

    # 5. Ping vsechno
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
    if all_ping_ips:
        ping_cmds = []
        for ip in all_ping_ips:
            ping_cmds.append(f':put ">>>{ip}<<<"; /ping {ip} count=3 interval=1')
        out, ping_err_raw = ssh_multi(host, port, user, password, ping_cmds,
                             timeout=max(60, len(all_ping_ips) * 4))
        if ping_err_raw:
            ping_err = ping_err_raw
        if out:
            chunks = re.split(r">>>([\d.]+)<<<", out)
            for i in range(1, len(chunks) - 1, 2):
                ip = chunks[i]
                ping_out = chunks[i + 1]
                ping_alive[ip] = parse_ping(ping_out)

        mk_alive = sum(1 for b in vpn_boxes if ping_alive.get(f"192.168.50.{int(b['num'])}"))
        cam_alive = sum(1 for ip, v in ping_alive.items() if v and not any(
            ip == f"192.168.50.{int(b['num'])}" for b in vpn_boxes))
        print(f"  [{src_id}] MK boxy ping: {mk_alive}/{len(vpn_boxes)} zije")
        print(f"  [{src_id}] Kamery ping: {cam_alive}/{discovered} zije")

    step_log(steps, "ping", t0,
             "ok" if not ping_err else "error",
             f"{len(all_ping_ips)} IP, MK {mk_alive}/{len(vpn_boxes)}, kam {cam_alive}/{discovered}",
             ping_err)

    # 6. Sestav box updates
    box_updates = {}
    for box in vpn_boxes:
        num = box["num"]
        peer = peer_map.get(num)
        mk_ip = f"192.168.50.{int(num)}"
        ping_ok = ping_alive.get(mk_ip)

        if peer and peer.get("running", False):
            status = "online"
        elif peer:
            status = "online"
        elif ping_ok:
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
    step_log(steps, "ping_local", t0, "ok",
             f"{alive_count}/{len(all_ips)} zije")
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
        dev_updates[f"lok_{num}"] = update

    return dev_updates, None, steps


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
# HLAVNI LOGIKA — sestav status.json
# =============================================================================

def build_status(config, vpn_results, local_results, nvr_snmp, run_meta=None):
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

    # --- SNMP NVR ---
    nvr_snmp = {}
    snmp_steps = []
    for nvr_cfg in config.get("nvr", []):
        snmp_data, snmp_step = collect_nvr_snmp(nvr_cfg, config["sources"], password)
        if snmp_data:
            nvr_snmp[nvr_cfg["id"]] = snmp_data
        if snmp_step:
            snmp_steps.append(snmp_step)

    # --- Run metadata ---
    run_end = datetime.now(timezone.utc)
    run_meta = {
        "started": run_start.isoformat(),
        "finished": run_end.isoformat(),
        "duration_s": round(time.monotonic() - run_t0, 2),
        "runner": "github-actions" if os.environ.get("GITHUB_ACTIONS") else "local",
        "trigger": os.environ.get("GITHUB_EVENT_NAME", "manual"),
        "snmp_steps": snmp_steps,
    }

    # --- Sestav a zapis status.json ---
    print()
    print("Sestavuji status.json...")
    status = build_status(config, vpn_results, local_results, nvr_snmp, run_meta)

    output_path = args.output
    with open(output_path, "w") as f:
        json.dump(status, f, indent=2, ensure_ascii=False)

    box_count = len(status["boxes"])
    online = sum(1 for b in status["boxes"] if b["mk_status"] == "online")
    print(f"Hotovo — {online}/{box_count} boxu online")
    print(f"Zapsano do {output_path}")


if __name__ == "__main__":
    main()
