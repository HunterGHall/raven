# raven

One numbered menu that drives the OSINT tools in this folder (sherlock, maigret, blackbird, holehe, h8mail, theHarvester, spiderfoot, and more).

Only investigate targets you are authorised to.

## Setup

```bash
python main.py
```

Then in the menu: `9) Dependencies / install` → create `.venv` → `install ALL tools` → `check all tools`.

Tools run from `C:\dev\raven\.venv` if it exists. Set `RAVEN_PYTHON` to use a different Python.

## Use

- `1` Set target: pick a type (username, email, phone, domain, ip, url), then type the value.
- `2` Run one tool: pick a tool, then answer its prompts (target, options, extra args).
- `3` Auto-run every tool that fits the target type, optionally in parallel and with pivoting.
- `4` / `5` / `6` / `7`: view findings, pivot on them, view a tool's output, write a report.
- `10` Settings: Instagram sessionid, Shodan key, theHarvester sources.
- `11` Interactive tools: `ghunt login`, recon-ng.

Phones need a country code: `+1 5551234567`.

## Output

Everything goes to `output/<target>/`: one log per tool, `findings.json` (emails, IPs, URLs and subdomains pulled from the logs), and `report.md`.

## Scripted

```bash
python main.py -c "target domain example.com" -c "auto -j 4" -c "report"
```

## Needs setup first

- ghunt: log in once (menu `11`).
- toutatis: Instagram sessionid (menu `10`).
- shodan: API key (menu `10`).
