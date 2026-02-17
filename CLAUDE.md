# Projekt: paulservis_dohled

## Cil
Monitoring Paulservis kamerovych systemu — automaticky sber dat + webovy dashboard.

## Repo a pristup
- Repo: https://github.com/FCISCZ/paulservis-dohled
- Dashboard: https://fciscz.github.io/paulservis-dohled/
- Lokalni klon: /home/fc/prace/paulservis_dohled/

## Jak to funguje
```
GitHub Actions (cron */30 + workflow_dispatch)
  → collect.py: SSH na VPN1, VPN5, MK_netflix + SNMP na NVR
  → status.json (git push)
  → GitHub Pages dashboard (index.html)
```
- **collect.py** — sber dat (SSH ping, L2TP peers, DHCP, bridge host, ARP, SNMP)
- **config.yaml** — inventar vsech zarizeni (VPN boxy, lokalni kamery, NVR)
- **index.html** — dashboard (single-page, nacita status.json)
- **status.json** — ziva data (generovano CI, neupravovat rucne)

## Sit (3 pristupove body)
| Zarizeni | IP | Port | Ucet |
|----------|-----|------|------|
| VPN1 "hotelak VPN 01" | 93.99.200.101 | 50022 | monitor |
| VPN5 "hotelak VPN 02" | 93.99.200.105 | 50022 | monitor |
| MK_netflix (jump host) | 93.99.172.72 | 2222 | monitor |
| Master MK (NESAHAT) | 213.192.1.20 | 50022 | admin/alfa2005 |

- VPN1: 12 L2TP tunelu, NVR Paulservis (50.253) + NVR FC (50.50)
- VPN5: 19 L2TP tunelu, NVR Stavba (50.51) + NVR Chabarovice (50.52)
- Oba VPN MK maji 192.168.50.254 — ODDELENE site, cisla boxu se prekryvaji
- Lokalni kamery pres MK_netflix (FC ISP sit)
- SNMP community: "cist" (Uniview OID 1.3.6.1.4.1.25506.20.{1,2,3}.0)

## NVR
| NVR | Local IP | Verejna IP | VPN | SNMP |
|-----|----------|------------|-----|------|
| Paulservis | 50.253 | ? (NAT) | vpn1 | OK |
| FC | 50.50 | 93.99.200.99 | vpn1 | OK |
| Stavba | 50.51 | 93.99.200.100 | vpn5 | NEFUNGUJE |
| Chabarovice | 50.52 | 93.99.200.102 | vpn5 | OK |

## Dashboard funkce
- Prehled boxu (VPN + lokalni), razeni, filtry
- Debug panel (tlacitko DEBUG) — kroky sberu, casovani, chyby
- Vynutit sber (heslo "prosinec") — banner se sledovanim workflow
- NVR karty s SNMP (disky, model, firmware)
- VPN site prehled (IP mapa, DHCP leases)

## Dulezite technicke detaily
- Ping count=3 (1 z 3 staci = online), vic by prekrocilo timeout
- Workflow timeout: 10 min (sber trva ~4 min)
- git pull --rebase v workflow pred push (race condition s commity)
- Vynutit sber: XOR sifrovany token, heslo "prosinec", sessionStorage
- GitHub cron */30 je nespolehlivy (throttling) → workflow_dispatch je okamzity

## TODO
- Pavel: zapnout SNMP na NVR Stavba (50.51)
- Doplnit lokace u VPN5 boxu v config.yaml

## Stav
PROVOZNI — automaticky sber kazdych 30 min, dashboard na GitHub Pages.
