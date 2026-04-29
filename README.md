
<div align="center">

```
 ██████╗ ███████╗██╗███╗   ██╗████████╗      ██████╗████████╗███████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝     ██╔════╝╚══██╔══╝██╔════╝
██║   ██║███████╗██║██╔██╗ ██║   ██║        ██║        ██║   █████╗  
██║   ██║╚════██║██║██║╚██╗██║   ██║        ██║        ██║   ██╔══╝  
╚██████╔╝███████║██║██║ ╚████║   ██║        ╚██████╗   ██║   ██║     
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝         ╚═════╝   ╚═╝   ╚═╝   
```

<img src="https://readme-typing-svg.demolab.com?font=Share+Tech+Mono&size=18&pause=1000&color=00FF88&center=true&vCenter=true&width=600&lines=OSINT+%7C+CTF+%7C+RECON+%7C+BUG+BOUNTY;Claude+AI+Powered+Investigation+Skill;HackTheBox+%7C+TryHackMe+%7C+CTFtime;Geolocation+%7C+Username+%7C+Email+%7C+Metadata" alt="Typing SVG" />

<br/>

[![Author](https://img.shields.io/badge/-%40Razzkr-black?style=for-the-badge&logo=github&logoColor=00ff88&labelColor=0d1117&color=0d1117)](https://github.com/Razzkr)
[![Claude](https://img.shields.io/badge/-Claude%20Skill-black?style=for-the-badge&logo=anthropic&logoColor=ff6600&labelColor=0d1117&color=0d1117)](https://anthropic.com)
[![CTF](https://img.shields.io/badge/-CTF%20Ready-black?style=for-the-badge&logo=hackthebox&logoColor=9fef00&labelColor=0d1117&color=0d1117)](https://hackthebox.com)
[![License](https://img.shields.io/badge/-MIT%20License-black?style=for-the-badge&logoColor=ffffff&labelColor=0d1117&color=0d1117)](LICENSE)

<br/>

> **Drop one file. Turn Claude into a god-mode OSINT investigator.**
> Built for CTF challenges, bug bounty recon, and authorized red team engagements.

</div>

---

<div align="center">

```
┌─────────────────────────────────────────────────────────────────┐
│                     RECON ARSENAL                               │
│                                                                 │
│   [01] IMAGE        [02] USERNAME      [03] EMAIL               │
│   Geolocation       Person Hunt        Breach Intel             │
│   Metadata          Social Media       Header Trace             │
│                                                                 │
│   [04] DOMAIN       [05] METADATA      [06] STEGANOGRAPHY       │
│   WHOIS · DNS       EXIF · DOCX        LSB · Binwalk            │
│   Wayback · Cert    PDF · Video        Steghide · Zsteg         │
│                                                                 │
│   [07] BREACH       [08] GEOLOCATION   [09] CTF CHECKLIST       │
│   HIBP · Dehashed   GeoSpy · SunCalc   Pivot Map                │
│   IntelX · Pastes   StreetView         Flag Formats             │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

## `> INSTALL`

```bash
# Clone
git clone https://github.com/Razzkr/osint-ctf
cd osint-ctf

# Install skill into Claude Code
mkdir -p ~/.claude/skills/osint-ctf
cp skills/SKILL.md ~/.claude/skills/osint-ctf/SKILL.md
```

**Requires:** [Claude Code](https://docs.anthropic.com/en/docs/claude-code) · `npm install -g @anthropic-ai/claude-code`

---

## `> USAGE`

```bash
claude
```

Then just ask naturally — the skill auto-triggers:

```
osint ctf: username is "shadow_99", find everything
```
```
geolocate this image: /home/kali/challenge.jpg
```
```
trace this email: target@domain.com
```
```
osint this domain: example.com
```
```
find metadata in: document.pdf
```

---

## `> CAPABILITY MAP`

<details>
<summary><b>🖼️ [01] IMAGE & GEOLOCATION</b></summary>

```bash
# Metadata extraction
exiftool -a -u -g1 image.jpg        # GPS, device, timestamp
binwalk image.jpg                   # embedded files
steghide extract -sf image.jpg      # steganography check

# Reverse image search
# Google Images  → images.google.com
# Yandex         → yandex.com/images   (BEST for faces)
# TinEye         → tineye.com
# PimEyes        → pimeyes.com         (faces)
# GeoSpy AI      → geospy.ai

# Geolocation analysis
# Sun angle      → suncalc.org
# Street View    → maps.google.com
# Mapillary      → mapillary.com
```

</details>

<details>
<summary><b>👤 [02] USERNAME & PERSON</b></summary>

```bash
sherlock <username>                 # 400+ sites
holehe <email>                      # account existence
maigret <username>                  # deeper OSINT

# Manual
# https://whatsmyname.app
# https://namechk.com
# https://usersearch.org
# https://socialsearcher.com

# Deleted content recovery
# Twitter  → twstalker.com
# Reddit   → camas.unddit.com
# GitHub   → git log --format='%ae'
```

</details>

<details>
<summary><b>📧 [03] EMAIL INVESTIGATION</b></summary>

```bash
holehe email@domain.com             # registered services
h8mail -t email@domain.com          # breach lookup

# Tools
# epieos.com     → Google ID + Maps reviews
# hunter.io      → verify + colleagues
# haveibeenpwned.com
# dehashed.com
# intelx.io
```

</details>

<details>
<summary><b>🌐 [04] DOMAIN & WEBSITE</b></summary>

```bash
subfinder -d domain.com             # subdomains
amass enum -d domain.com
dnsx -d domain.com -a -mx -txt
whois domain.com

# Resources
# crt.sh/?q=%.domain.com            certificate transparency
# securitytrails.com                historical DNS
# web.archive.org                   Wayback Machine
# shodan.io                         internet scan data
# censys.io
```

</details>

<details>
<summary><b>📄 [05] METADATA</b></summary>

```bash
exiftool -a -u -g1 file.*           # all file types
pdfinfo file.pdf
unzip -o file.docx -d out/
cat out/docProps/core.xml           # author, company, dates
mediainfo video.mp4
strings file | grep -i flag
binwalk -e file                     # extract embedded
foremost -i file                    # file carving
```

</details>

<details>
<summary><b>🔐 [06] STEGANOGRAPHY</b></summary>

```bash
steghide extract -sf image.jpg
stegseek image.jpg /usr/share/wordlists/rockyou.txt
zsteg image.png                     # LSB PNG
stegsolve                           # visual analysis
hexdump -C file | grep -i flag
strings file | grep -i "flag\|CTF\|HTB\|THM"
```

</details>

<details>
<summary><b>💥 [07] BREACH INTELLIGENCE</b></summary>

```
haveibeenpwned.com
dehashed.com
intelx.io
breachdirectory.org
leak-lookup.com

# Paste sites
pastebin.com/search?q=target
controlc.com
rentry.co
```

</details>

<details>
<summary><b>📍 [08] GEOLOCATION FROM VIDEO</b></summary>

```bash
# Extract frames
ffmpeg -i video.mp4 -vf fps=1 frame%04d.png

# Analyse each frame:
# - Reverse image search
# - Language on signs/text
# - Architecture style
# - Vegetation + terrain
# - Weather → timeanddate.com/weather/historic
```

</details>

<details>
<summary><b>✅ [09] CTF CHECKLIST</b></summary>

```
[ ] Read challenge description 3x — every word is a clue
[ ] Identify type: person / image / domain / email / metadata
[ ] Run exiftool on ALL provided files immediately
[ ] Check metadata before anything else
[ ] Reverse image search with ALL engines (results differ)
[ ] Search breach databases for any email/username found
[ ] Wayback Machine on every URL
[ ] Check for steganography on images/audio
[ ] Pivot on EVERY new data point found
[ ] Check ctftime.org/writeups if stuck
```

</details>

---

## `> PIVOT MAP`

```
USERNAME ──────► sherlock + social media search
    │
    └──► EMAIL ──► epieos + holehe + breach check
              │
              └──► REAL NAME ──► LinkedIn + Facebook + voter records
                        │
                        └──► PHONE ──► truecaller + reverse lookup
                                  │
                                  └──► LOCATION ──► geolocation + street view

IMAGE ─────────► exiftool ──► GPS coords ──► Google Maps
    │
    └──► reverse image search ──► original source ──► metadata

DOMAIN ────────► whois ──► registrant email ──► reverse whois ──► all domains
    │
    └──► crt.sh ──► subdomains ──► shodan ──► open ports ──► services
```

---

## `> TOOL INSTALL`

```bash
# Python tools
pip install holehe h8mail shodan

# Go tools  
go install github.com/sherlock-project/sherlock@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Apt
sudo apt install -y exiftool binwalk steghide foremost mediainfo ffmpeg stegseek

# Claude Code
npm install -g @anthropic-ai/claude-code
```

---

## `> STRUCTURE`

```
osint-ctf/
├── skills/
│   └── SKILL.md          ← drop into ~/.claude/skills/osint-ctf/
├── README.md
└── LICENSE
```

---

<div align="center">

```
[ RECON ] ──► [ ENUMERATE ] ──► [ VALIDATE ] ──► [ REPORT ]
  passive         surface           live            deliver
```

[![HTB](https://img.shields.io/badge/-HackTheBox-9fef00?style=flat-square&logo=hackthebox&logoColor=black)](https://hackthebox.com)
[![THM](https://img.shields.io/badge/-TryHackMe-red?style=flat-square&logo=tryhackme&logoColor=white)](https://tryhackme.com)
[![CTFtime](https://img.shields.io/badge/-CTFtime-blue?style=flat-square)](https://ctftime.org)

**Built by [@Razzkr](https://github.com/Razzkr) · For authorized engagements only**

</div>
