# Projekt: paulservis_dohled

## Cil
Chraneny webovy system pro Paulservis — sprava a monitoring mobilnich kamer, MK routeru a site.
Pristup jen pro opravnene uzivatele (max 10 lidi).

## Klicovy koncept: BOXY

### Dva typy zarizeni

**TYP A: VPN BOX (vzdaleny)**
- Kamera + MK router + baterka, cestuje jako celek
- MK vytvari VPN tunel na hlavni MK
- MK IP = pevny identifikator boxu (nemeni se)
- Kamera IP se muze menit
- Pristup k NVR pres VPN

**TYP B: LOKALNI KAMERA (primy pristup)**
- Kamera primo v lokalni siti (bez MK)
- Prima pristup k NVR (bez VPN)
- Identifikator = IP nebo MAC kamery (IP se muze menit)

**NVR (most mezi svetama)**
- eth0: 192.168.50.x (uzavrena sit kamer a VPN boxu)
- eth1: hlavni sit FC (routing → lokalni kamery)
- Vidi vsechny kamery — VPN i lokalni

### Karta zarizeni
- Typ: vpn_box / lokalni
- Identifikator: MK IP (vpn_box) nebo MAC kamery (lokalni)
- Aktualni lokace
- MK: model, verze, MAC (jen u vpn_box)
- Kamera: model, MAC, aktualni IP, ip_typ (static/dhcp)
- Pozn: nektere kamery jedou JEN na DHCP — MK jim na 50.x dela maly DHCP
- Stav: online/offline (z live monitoringu)
- Historie presunu

### Priklad
```
VPN BOX "50.101"              LOKALNI "kamera_07"
  MK IP: 192.168.50.101        Kamera IP: 192.168.1.85
  MK: hAP lite, v7.16          MAC: AA:BB:CC:77:88:99
  Kamera: IPC2124SR3            Model: IPC2322LB
  Kam IP: 192.168.50.201       Lokace: sklad, u tebe v siti
  Lokace: lampa 45887           Stav: ONLINE
  Stav: ONLINE
```

## Dve vrstvy systemu

### 1. ZIVY MONITORING (automaticky, kazdych 15 min)
```
GitHub Actions (scheduled workflow, interval 15 min)
    | SSH na VPN1 + VPN5 (port 50022)
    | RouterOS: VPN peers, ping kamer, DHCP leases, system resource
    v
Python skript (collect.py) → aktualizuje status.json (co zije, co ne)
    | git commit + push (automaticky)
    v
GitHub Pages dashboard (index.html) zobrazuje live stav
```

### 2. SPRAVA / ZASAHY (manualni, pres dashboard)
- Uzivatel v dashboardu klikne: "Presun kameru A na lampu 45887 za MK H"
- Dashboard posle zmenu pres GitHub API (commit do YAML/JSON souboru)
- Git historie = automaticky audit trail (kdo, kdy, co zmenil)
- Zadna databaze — Git JE databaze

## Datova struktura (v repu)

```
data/
  boxy/
    50_101.yaml        # karta boxu (IP = nazev souboru)
    50_102.yaml
    ...
  status.json          # live stav (generovany CI, prepisuje se)
```

### Priklad 50_101.yaml:
```yaml
typ: vpn_box                   # nebo "lokalni"
id: "50_101"                   # MK IP u vpn_box, MAC u lokalni
nazev: "Husova lampa 45887"

mk:                            # jen u vpn_box
  ip: 192.168.50.101           # pevna
  model: hAP lite
  mac: "AA:BB:CC:11:22:01"
  routeros: "7.16"

kamera:
  model: "Uniview IPC2124SR3"
  mac: "AA:BB:CC:DD:EE:01"
  ip: 192.168.50.201           # muze se menit
  ip_typ: dhcp                 # static nebo dhcp (nektere kamery jedou jen na DHCP)

lokace: "lampa c. 45887, ul. Husova, Chabarovice"

historie:
  - datum: 2026-02-15
    lokace: "lampa c. 45887, ul. Husova"
    poznamka: "presun ze Sibrky"
  - datum: 2026-01-10
    lokace: "parkoviste Sibrka"
    poznamka: "prvni instalace"
```

## Sit

### Tri MikroTiky (zmapovano 2026-02-15)

```
MASTER: 213.192.1.20 "hotelak master switch VPN"
  Model: RB1100AHx4 Dude Edition, RouterOS v7.13
  Role: skalovani a routing — NESAHAT
  │
  ├── VPN1: 93.99.200.101 "hotelak VPN 01"
  │   Model: CCR2004-16G-2S+, RouterOS v7.13
  │   Bridge1: 192.168.50.254/24
  │   L2TP tunely (12): cam_03,05,09,12,24,84,85,86,87,88,89,94
  │   NVR:
  │     - 93.99.200.99  NVR FC hlavni (aktivni)
  │     - ???            druhe NVR (zjistit)
  │   Ostatni:
  │     - Walker = Windows PC, RDP pristup k sitovym prvkum
  │   Pozn: NVR Stavba (.100) a NVR Prestanov (.102) se presunuly na VPN5
  │
  └── VPN5: 93.99.200.105 "hotelak VPN 02"
      Model: RB1100AHx4, RouterOS v7.12.1
      Bridge1: 192.168.50.254/24
      L2TP tunely (19): cam_02,04,07,08,24,25,28,86-93,95-98
      WireGuard: 10.20.30.1 (wg1)
      NVR (presunuto z VPN1):
        - 93.99.200.100 NVR Stavba (aktivni)
        - 93.99.200.102 NVR Chabarovice (aktivni)
```

- Celkem 31 aktivnich VPN tunelu (12 + 19)
- Oba VPN MK maji STEJNOU IP 192.168.50.254 — ODDELENE site
- Cisla kamer se prekryvaji (24,86,87,88,89 na obou) = jine fyzicke kamery
- NVR verejna IP z bloku 93.99.200.96/27
- Vsechny MK jsou RouterOS v7 (7.12-7.13)
- VPN boxy volaji na jednu z bran (VPN1 nebo VPN5)
- **Failover**: zmena IP na boxu → prepne na druhy VPN MK (stejna podsit 50.0/24)

### Typy zarizeni v siti
- **VPN boxy**: MK + kamera + baterka, VPN tunel na jednu z bran
- **Lokalni kamery**: primo v siti, bez VPN, primy pristup k NVR
- **NVR**: dve sitovky — jedna na 50.0/24 (kamery), druha v hlavni siti

### Dulezity kontext
- FC je ISP — "domaci sit" = sit ISP providera
- Paulservis kamerova infra = vlastni verejna podsit, UPLNE MIMO FC ISP sit
- NVR druha sitovka je v FC ISP siti → lokalni kamery jedou po ISP siti
- Hlavni MK (nad VPN1/VPN5) resi jen verejky a skalovani — nesahat na nej

### Monitoring (3 pristupove body)
- **VPN1** (93.99.200.101:50022) — SSH → jeho VPN peers, ping kamer, DHCP leases
- **VPN5** (93.99.200.105:50022) — SSH → jeho VPN peers, ping kamer, DHCP leases
- **Lokalni kamery** — pristup pres FC ISP sit (TBD: novy MK s verejkou / MK_netflix / jiny)
  - Tyto kamery jsou na NVR druhe sitovce (FC ISP sit)
  - Potreba najit/urcit pristupovy bod do ISP site pro monitoring

## RouterOS verze
- Vsechny 3 MK jsou RouterOS v7 (7.12-7.13), ale VPN boxy mohou mit v6
- Pristup: **SSH** (port 50022, zapnuto 2026-02-15)
- REST API NEPOUZIVAT (jen v7, nutny dalsi port na verejce)
- Skript musi detekovat verzi a prizpusobit prikazy:
  - IPsec: v6 = `/ip ipsec remote-peers print` / v7 = `/ip ipsec active-peers print`
  - Ostatni prikazy (resource, dhcp, ping, identity) jsou stejne

## Technologie
- **GitHub Actions**: scheduled workflow (sber dat kazdych 15 min) + commit/push status.json
- **GitHub Pages**: hosting statickeho dashboardu, zdarma
- **Git jako databaze**: YAML soubory = karty boxu, git log = audit trail
- **RouterOS SSH**: prikazy pro sber dat

## Pristupove udaje
| Sluzba | Pristup | Poznamka |
|--------|---------|---------|
| Master MK | 213.192.1.20:50022 | SSH, admin/alfa2005, NESAHAT |
| VPN1 | 93.99.200.101:50022 | SSH, admin/alfa2005 |
| VPN5 | 93.99.200.105:50022 | SSH, admin/alfa2005 |
| GitHub Actions | secrets v repo Settings | MK_MONITOR_PASS |
| Sit kamery | 192.168.50.0/24 | Vsechno za VPN |

## GitHub
- Repo: https://github.com/FCISCZ/paulservis-dohled
- GitHub Pages: https://fciscz.github.io/paulservis-dohled/
- Lokalni klon: /home/fc/prace/paulservis_dohled/

## Stav
- PROTOTYP — vizualni koncept na GitHub Pages, ceka na schvaleni FC + Pavel

## Zavislosti
- Projekt MK_netflix (VPN server = hlavni MK)
- Projekt paulservis_www (hlavni web firmy)
