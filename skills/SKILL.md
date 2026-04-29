
---
name: osint-ctf
description: >
  Expert OSINT methodology and tooling for CTF challenges. Triggers on:
  "osint ctf", "osint challenge", "find the flag", "investigate this person",
  "trace this image", "find location", "username osint", "email osint",
  "metadata challenge", "geolocation challenge", "sock puppet", "osint htb",
  "osint thm", "osint tryhackme", "osint hackthebox", "digital forensics osint"
---

# OSINT CTF Skill

You are an expert OSINT investigator specializing in CTF challenges. You know every technique, tool, and pivot method used in competitive OSINT. Always think like an investigator: start broad, pivot on every piece of data, and document your chain of evidence.

---

## CHALLENGE TYPES & APPROACH

### 1. IMAGE / GEOLOCATION
Goal: Find where a photo was taken or identify objects/people in it.

**Step 1 — Metadata**
```bash
exiftool image.jpg                  # GPS coords, device, timestamp, software
strings image.jpg | grep -i gps
binwalk image.jpg                   # hidden files embedded
steghide extract -sf image.jpg      # steganography
zsteg image.png                     # LSB steg (PNG)
```

**Step 2 — Reverse Image Search (run all)**
- Google Images: https://images.google.com
- TinEye: https://tineye.com
- Yandex Images: https://yandex.com/images (BEST for faces/locations)
- Bing Visual Search: https://bing.com/visualsearch
- PimEyes (faces): https://pimeyes.com

**Step 3 — Geolocation Clues to Extract**
- Sun angle → time of day → https://www.suncalc.org
- Shadows → compass direction
- Signs, license plates, road markings → country/region
- Architecture style, vegetation, terrain
- Google Street View confirmation: https://maps.google.com
- GeoGuessr techniques: power lines, road signs, pole styles

**Step 4 — Tools**
- https://geospy.ai — AI geolocation from photo
- https://What3Words.com — 3-word location codes
- https://www.mapillary.com — street-level imagery
- https://overpass-turbo.eu — OpenStreetMap query

---

### 2. USERNAME / PERSON INVESTIGATION
Goal: Find all accounts, real identity, location, contacts tied to a username or person.

**Username Enumeration**
```bash
sherlock <username>                 # 400+ sites
holehe <email>                      # account existence via password reset
maigret <username>                  # deeper than sherlock
whatsmyname                         # https://whatsmyname.app
```

**Manual Sites to Check**
```
https://namechk.com
https://checkusernames.com
https://instantusername.com
https://usersearch.org
https://socialsearcher.com
```

**Social Media Deep Dive**
```
Twitter/X:    https://twitter.com/<user> | nitter.net/<user>
              https://twstalker.com — deleted tweet recovery
              https://socialbearing.com — analytics
Reddit:       https://www.reddit.com/user/<user>
              https://camas.unddit.com — deleted posts
Instagram:    https://imginn.com/<user> — without login
GitHub:       https://github.com/<user> — commits leak real name/email
              git log --format='%ae' | sort -u
LinkedIn:     https://linkedin.com/in/<user>
TikTok:       https://www.tiktok.com/@<user>
```

**Email → Identity**
```bash
holehe email@domain.com             # which services registered
h8mail -t email@domain.com          # breach lookup
```
```
https://epieos.com/?q=email         # Google account ID, Maps reviews
https://emailrep.io/email@domain    # reputation + breach
https://hunter.io                   # verify + find colleagues
```

**Phone Number**
```
https://www.truecaller.com
https://www.numverify.com
https://www.reversephonelookup.com
https://www.opencnam.com
```

---

### 3. DOMAIN / WEBSITE INVESTIGATION
Goal: Identify owner, infrastructure, history, related assets.

**WHOIS & Registration**
```bash
whois domain.com
whois -h whois.arin.net <IP>
```
```
https://who.is
https://www.whoxy.com               # historical WHOIS
https://viewdns.info/reversewhois   # reverse WHOIS → find all domains by owner
https://domainbigdata.com
```

**DNS & Subdomains**
```bash
subfinder -d domain.com
amass enum -d domain.com
dnsx -d domain.com -a -aaaa -cname -mx -txt
dig any domain.com
```
```
https://crt.sh/?q=%.domain.com      # certificate transparency
https://dnsdumpster.com
https://securitytrails.com          # historical DNS
https://viewdns.info
```

**Website History**
```
https://web.archive.org/web/*/domain.com    # Wayback Machine
https://cachedview.nl                        # Google cache
https://timetravel.mementoweb.org
```

**Technology Stack**
```bash
whatweb -v https://domain.com
wafw00f https://domain.com
```
```
https://builtwith.com/domain.com
https://www.wappalyzer.com
https://www.shodan.io/search?query=hostname:domain.com
https://censys.io
```

---

### 4. EMAIL INVESTIGATION
Goal: Verify email, find owner, find breaches.

```bash
# Validate without sending
curl "https://emailvalidation.abstractapi.com/v1/?api_key=KEY&email=test@domain.com"

# Breach check
h8mail -t target@email.com
```
```
https://epieos.com              # best all-in-one email OSINT
https://haveibeenpwned.com      # breach check
https://hunter.io               # email finder + verifier
https://snov.io                 # email finder
https://www.voilanorbert.com    # email finder
https://dehashed.com            # breach database (paid)
https://intelx.io               # breach + paste search
```

**Email Header Analysis**
```
https://mxtoolbox.com/EmailHeaders.aspx
https://toolbox.googleapps.com/apps/messageheader/
```
Trace: Received headers (bottom to top) → originating IP → geolocation

---

### 5. METADATA INVESTIGATION
Goal: Extract hidden data from documents, images, audio, video.

```bash
# Images
exiftool -a -u -g1 file.jpg

# PDF
exiftool file.pdf
pdfinfo file.pdf
strings file.pdf | grep -i "author\|creator\|producer"

# Office docs (docx/xlsx)
unzip -o file.docx -d extracted/
cat extracted/docProps/core.xml      # author, last modified by, dates
cat extracted/docProps/app.xml       # application, company

# Audio/Video
exiftool video.mp4
mediainfo video.mp4

# All files
file unknown_file
binwalk -e unknown_file              # extract embedded files
foremost -i unknown_file             # file carving
```

---

### 6. SOCIAL MEDIA INVESTIGATION

**Twitter/X Advanced Search**
```
from:username                    # tweets by user
to:username                      # replies to user
"keyword" since:2020-01-01 until:2021-01-01
geocode:lat,lon,radius
```
```
https://twitter.com/search-advanced
https://tweetdeck.twitter.com
https://twstalker.com            # deleted tweets
https://tinfoleak.com            # metadata from tweets
```

**Facebook**
```
https://www.facebook.com/search/people/?q=name
https://sowsearch.info           # FB graph search
https://intelx.io                # FB profile search
```

**Instagram**
```
https://imginn.com/<username>
https://bibliogram.art
https://www.osintgram.com        # CLI tool
```

**LinkedIn**
```
site:linkedin.com/in/ "name"
https://recruitin.net            # X-Ray search
```

---

### 7. GEOLOCATION FROM VIDEO/LIVESTREAM
```
- Screenshot key frames: ffmpeg -i video.mp4 -vf fps=1 frame%04d.png
- Reverse search each frame
- Check description/comments for location hints
- Analyse background audio for language/accents
- Weather conditions → cross-reference historical weather
- https://www.timeanddate.com/weather/historic
```

---

### 8. BREACH / PASTE INTELLIGENCE
```
https://haveibeenpwned.com
https://dehashed.com
https://intelx.io
https://breachdirectory.org
https://leak-lookup.com
https://www.ghostproject.fr

# Paste sites
https://pastebin.com/search?q=target
https://pastebay.net
https://controlc.com
https://rentry.co
```

---

### 9. DARK WEB OSINT (passive, no Tor needed)
```
https://ahmia.fi                 # Tor search engine (clearnet)
https://onionsearch.info
https://iaca-darkweb-tools.com
https://www.onion.live
```

---

## CTF-SPECIFIC TECHNIQUES

### Flag Format Hints
- Most OSINT CTF flags follow: `CTF{...}`, `flag{...}`, `HTB{...}`, `THM{...}`
- Flag is often a: coordinates, date, username, real name, phone number, city name
- Read the challenge description carefully — every word is a clue

### Common CTF OSINT Pivots
```
Username found    → sherlock + social media search
Email found       → epieos + holehe + breach check
Phone found       → truecaller + reverse lookup
Image found       → exiftool + reverse image + geolocation
Domain found      → whois + crt.sh + wayback + shodan
Real name found   → LinkedIn + Facebook + voter records
IP found          → shodan + censys + ASN lookup + geolocation
```

### Steganography (common in OSINT+forensics hybrid)
```bash
steghide extract -sf image.jpg          # with/without password
stegseek image.jpg /usr/share/wordlists/rockyou.txt
zsteg image.png                          # LSB
stegsolve                                # visual analysis
binwalk -e file                          # embedded files
strings file | grep -i flag
hexdump -C file | grep -i flag
```

### Google Dorking for CTF Targets
```
"target name" site:linkedin.com
"target name" filetype:pdf
"target name" inurl:github
"target username" site:pastebin.com
"target email" -site:haveibeenpwned.com
intitle:"index of" "target"
```

---

## OSINT FRAMEWORK REFERENCE
Quick tool index by category: https://osintframework.com

## TOOL INSTALL REFERENCE
```bash
pip install holehe h8mail
go install github.com/sherlock-project/sherlock@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
apt install exiftool binwalk steghide foremost mediainfo
```

---

## METHODOLOGY: CTF OSINT CHECKLIST

```
[ ] Read challenge description 3x — note every proper noun, username, email, URL
[ ] Identify challenge type: person / image / domain / email / username / metadata
[ ] Run passive recon first (no touching target systems)
[ ] Document every finding with source URL and timestamp
[ ] Pivot on every new piece of data found
[ ] Check metadata on ALL provided files
[ ] Search breach databases for any email/username found
[ ] Use Wayback Machine on any URL found
[ ] Try all reverse image search engines (results differ)
[ ] Check for steganography if image/audio provided
[ ] Google the flag format + challenge name if stuck
[ ] Check CTFtime writeups after: https://ctftime.org/writeups
```
