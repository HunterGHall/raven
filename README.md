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

## Credits

raven is only a front end. All the real work is done by these projects, cloned into this folder. Credit and licences belong to their authors.

| Tool | Repo |
| --- | --- |
| blackbird | [p1ngul1n0/blackbird](https://github.com/p1ngul1n0/blackbird) |
| dnstwist | [elceef/dnstwist](https://github.com/elceef/dnstwist) |
| EyeWitness | [RedSiege/EyeWitness](https://github.com/RedSiege/EyeWitness) |
| GHunt | [mxrch/GHunt](https://github.com/mxrch/GHunt) |
| h8mail | [khast3x/h8mail](https://github.com/khast3x/h8mail) |
| holehe | [megadose/holehe](https://github.com/megadose/holehe) |
| ignorant | [megadose/ignorant](https://github.com/megadose/ignorant) |
| instaloader | [instaloader/instaloader](https://github.com/instaloader/instaloader) |
| maigret | [soxoj/maigret](https://github.com/soxoj/maigret) |
| metagoofil | [opsdisk/metagoofil](https://github.com/opsdisk/metagoofil) (maintained fork of [laramies/metagoofil](https://github.com/laramies/metagoofil)) |
| Photon | [s0md3v/Photon](https://github.com/s0md3v/Photon) |
| recon-ng | [lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) |
| sherlock | [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) |
| shodan-python | [achillean/shodan-python](https://github.com/achillean/shodan-python) |
| social-analyzer | [qeeqbox/social-analyzer](https://github.com/qeeqbox/social-analyzer) |
| SpiderFoot | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) |
| Sublist3r | [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) |
| theHarvester | [laramies/theHarvester](https://github.com/laramies/theHarvester) |
| toutatis | [megadose/toutatis](https://github.com/megadose/toutatis) |
| waybackpy | [akamhy/waybackpy](https://github.com/akamhy/waybackpy) |

## Needs setup first

- ghunt: log in once (menu `11`).
- toutatis: Instagram sessionid (menu `10`).
- shodan: API key (menu `10`).
