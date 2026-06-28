# SD-WAN Combined Collector

A single tool that connects **once** to a Cisco Catalyst SD-WAN Manager
(vManage) and runs two collection stages behind one login:

1. **Stage 1** &mdash; full operational data collection.
2. **Stage 2** &mdash; configuration backup collection.

Both stages share the same authenticated session (one `j_security_check` +
CSRF token), so the user authenticates only once. Each stage still produces its
own, unmodified output files; the tool then bundles the two resulting archives
into a single combined zip for easy sharing.

> **Privacy:** This tool does **not** collect any passwords, secrets, or
> sensitive details about your network. It gathers only high-level operational
> information about the features and configuration adopted in your environment.
> Credentials you enter are used solely to authenticate to your SD-WAN Manager
> for the session and are never stored.


---

## Repository layout

```
sdwan-collector/
├── combined.py              # Orchestrator: single login -> Stage 1 + Stage 2 -> combined zip
├── webapp.py                # Flask web app
├── templates/
│   └── index.html           # Web UI
├── requirements.txt         # Dependencies
├── tools/
│   ├── stage1.py            # Stage 1 collection (exposes run())
│   ├── stage1_endpoints.txt # Stage 1 endpoint list
│   ├── stage2.py            # Stage 2 collection wrapper
│   ├── cisco_sdwan/         # Stage 2 backup engine (third-party, Cisco Systems)
│   └── THIRD_PARTY_LICENSE  # License for the bundled backup engine
├── LICENSE                  # This project's license (MIT)
├── NOTICE                   # Third-party attributions
└── .gitignore
```

Generated archives are written to a local `runs/` folder (git-ignored).

---

## Requirements

- Python 3.10 – 3.12

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

### Web app (recommended)

```bash
python webapp.py                     # http://0.0.0.0:5050
# python webapp.py --host 127.0.0.1 --port 8080
```

Open the URL, enter the SD-WAN Manager **IP address, port (optional), username,
and password**, and submit. After login the collection runs in the background
while the UI streams the **API endpoints used**. When finished, the combined
archive is saved locally and you are prompted to share the output file with the
Cisco team (a download link is also provided).

### Command line

```bash
python combined.py
# or non-interactively:
python combined.py -a 10.0.0.1 --port 8443 -u admin -p admin
```

The combined archive path is printed on completion.

---

## How the single login works

1. `authenticate()` performs one login (`/j_security_check` →
   `/dataservice/client/token`) and fetches server facts once.
2. The resulting cookie + `X-XSRF-TOKEN` are passed to Stage 1 as a ready-to-use
   request header.
3. The same session is injected into Stage 2's API client, bypassing its
   built-in login, so no second authentication occurs.

---

## Output

- Stage 1 archive: produced exactly as the original Stage 1 tool.
- Stage 2 archive: `runs/stage2_<timestamp>.zip`.
- **Combined bundle:** `runs/sdwan_collection_<timestamp>.zip` &mdash; contains
  both archives stored without recompression, so the originals remain intact
  inside.

---

## Licensing

This project is released under the
[Cisco Sample Code License, Version 1.1](LICENSE). The Sample Code is provided
by Cisco "as is", is not supported by Cisco TAC, and is intended for example
purposes only.

It bundles a third-party SD-WAN configuration backup engine under
`tools/cisco_sdwan/`, © Cisco Systems, Inc., distributed under the MIT License
(see `tools/THIRD_PARTY_LICENSE`). See [NOTICE](NOTICE) for full third-party
attributions.
