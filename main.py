#!/usr/bin/env python3
"""raven - one REPL that drives every OSINT tool in this folder.

    python main.py            # interactive
    python main.py -c "target example.com" -c "auto"   # scripted

Each tool runs as a subprocess out of its own checkout (PYTHONPATH + cwd),
output is tee'd to output/<target>/<tool>.txt, and emails / domains / IPs /
URLs spotted in that output are collected so one tool's results can feed the
next (`found`, `auto --follow`, `pivot`).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output"
CONF = ROOT / ".raven.json"

# --------------------------------------------------------------------------
# target typing
# --------------------------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,}$")


def detect(t: str) -> str:
    if t.startswith(("http://", "https://")):
        return "url"
    if EMAIL_RE.fullmatch(t):
        return "email"
    if IP_RE.fullmatch(t):
        return "ip"
    if PHONE_RE.match(t) and sum(c.isdigit() for c in t) >= 7:
        return "phone"
    if DOMAIN_RE.match(t):
        return "domain"
    return "username"


def split_phone(t: str) -> tuple[str, str]:
    """-> (country_code, national_number) for ignorant."""
    try:
        import phonenumbers  # type: ignore
        p = phonenumbers.parse(t if t.startswith("+") else "+" + t)
        return str(p.country_code), str(p.national_number)
    except Exception:
        pass
    m = re.match(r"^\+?(\d{1,3})[\s().-]+(.+)$", t.strip())
    if not m:
        raise ValueError("phone needs a country code: '+1 5551234567' (or pip install phonenumbers)")
    return m.group(1), re.sub(r"\D", "", m.group(2))


def slug(t: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@+-]+", "_", t)[:80]


# --------------------------------------------------------------------------
# tool registry
# --------------------------------------------------------------------------
@dataclass
class Ctx:
    target: str
    kind: str
    outdir: Path
    cfg: dict

    @property
    def host(self) -> str:  # domain/ip from url or bare target
        return re.sub(r"^https?://|[/:].*$", "", self.target) if self.kind == "url" else self.target

    @property
    def url(self) -> str:
        return self.target if self.kind == "url" else f"https://{self.target}"


@dataclass
class Opt:
    flag: str
    label: str
    kind: str = "bool"  # bool | text | int | multi (comma list -> repeated flag) | choice
    default: object = None
    choices: tuple[str, ...] = ()


def extras(tool: "Tool", answers: dict | None = None) -> list[str]:
    """CLI fragments for the tool's options; answers=None -> defaults (used by auto)."""
    out: list[str] = []
    for o in tool.opts:
        v = (answers or {}).get(o.flag, o.default)
        if o.kind == "bool":
            if v:
                out.append(o.flag)
        elif o.kind == "multi":
            for item in str(v or "").replace(",", " ").split():
                out += [o.flag, item]
        elif v not in (None, ""):
            out += [o.flag, str(v)]
    return out


def ask_opts(tool: "Tool") -> dict:
    """prompt for each option; blank keeps the default."""
    ans: dict = {}
    for o in tool.opts:
        d = o.default
        if o.kind == "bool":
            s = input(f"  {o.label}? [{'Y/n' if d else 'y/N'}] ").strip().lower()
            ans[o.flag] = d if not s else s.startswith("y")
        elif o.kind == "choice":
            print(f"  {o.label}:")
            for i, c in enumerate(o.choices, 1):
                print(f"     {i}) {c}")
            s = input(f"  number (blank = {d or 'none'}) ").strip()
            ans[o.flag] = o.choices[int(s) - 1] if s.isdigit() and 1 <= int(s) <= len(o.choices) else d
        else:
            hint = f" [{d}]" if d not in (None, "") else " (blank = skip)"
            s = input(f"  {o.label}{hint}: ").strip()
            ans[o.flag] = s or d
    return ans


@dataclass
class Tool:
    name: str
    dir: str
    desc: str
    kinds: tuple[str, ...]
    run: tuple  # ("script", relpath) | ("func", "module:fn") | ("mod", "module")
    args: Callable[[Ctx], list[str]]
    probe: tuple[str, ...] = ()  # imports that must work for the tool to run
    auto: bool = True
    needs: Callable[[dict], str | None] = lambda cfg: None  # -> reason it can't run
    interactive: bool = False
    cwd_out: bool = False  # run inside the output dir (tool drops files in cwd)
    install: str = ""  # requirements file relative to dir; empty -> pip install dir
    opts: tuple = ()  # Opt(...) shown by the menu; defaults apply under `auto`


def _need_session(cfg):
    return None if cfg.get("instagram_session") else "no Instagram sessionid (set instagram_session <id>)"


def _need_shodan(cfg):
    key = Path.home() / ".shodan" / "api_key"
    return None if key.exists() else "no Shodan key (keys shodan <KEY>)"


def _need_ghunt(cfg):
    creds = Path.home() / ".malfrats" / "ghunt" / "creds.m"
    return None if creds.exists() else "not logged in (run: interactive ghunt login)"


def _ign(c: Ctx):
    cc, num = split_phone(c.target)
    return [cc, num, "--no-color", "--no-clear", "--only-used"]


TOOLS: dict[str, Tool] = {t.name: t for t in [
    # ---- usernames
    Tool("sherlock", "sherlock", "username across ~400 sites", ("username",),
         ("mod", "sherlock_project"),
         lambda c: ["--print-found", "--timeout", "15", "--output", str(c.outdir / "sherlock.found.txt"), c.target],
         probe=("requests", "colorama", "sherlock_project")),
    Tool("maigret", "maigret", "username dossier, 2500+ sites", ("username",),
         ("mod", "maigret"), lambda c: [c.target, "--no-progressbar"], probe=("aiohttp", "maigret"),
         cwd_out=True),
    Tool("blackbird", "blackbird", "username/email on WhatsMyName sites", ("username", "email"),
         ("script", "blackbird.py"),
         lambda c: ["-e" if c.kind == "email" else "-u", c.target],
         probe=("requests", "rich")),
    Tool("social-analyzer", "social-analyzer", "profile detection w/ scoring", ("username",),
         ("script", "app.py"),
         lambda c: ["--username", c.target, "--mode", "fast", "--output", "json", "--metadata", "--top", "100"],
         probe=("requests", "bs4", "langdetect")),
    # ---- email / phone
    Tool("holehe", "holehe", "which sites an email is registered on", ("email",),
         ("func", "holehe.core:main"), lambda c: [c.target, "--only-used", "--no-color", "--no-clear"],
         probe=("trio", "httpx", "holehe")),
    Tool("h8mail", "h8mail", "breach lookup for an email", ("email",),
         ("mod", "h8mail"), lambda c: ["-t", c.target], probe=("requests", "h8mail")),
    Tool("ghunt", "GHunt", "Google account intel for a gmail", ("email",),
         ("func", "ghunt.ghunt:main"), lambda c: ["email", c.target], probe=("httpx", "ghunt"),
         needs=_need_ghunt),
    Tool("ignorant", "ignorant", "which sites a phone number is on", ("phone",),
         ("func", "ignorant.core:main"), _ign, probe=("trio", "httpx", "ignorant")),
    # ---- instagram
    Tool("toutatis", "toutatis", "Instagram profile -> email/phone hints", ("username",),
         ("func", "toutatis.core:main"),
         lambda c: ["-u", c.target, "-s", c.cfg.get("instagram_session", "")],
         probe=("requests", "toutatis"), needs=_need_session),
    Tool("instaloader", "instaloader", "Instagram profile metadata", ("username",),
         ("script", "instaloader.py"),
         lambda c: ["--no-pictures", "--no-videos", "--no-compress-json", c.target],
         probe=("requests", "instaloader"), auto=False, cwd_out=True),
    # ---- domains
    Tool("theHarvester", "theHarvester", "emails/hosts/IPs for a domain", ("domain",),
         ("func", "theHarvester.theHarvester:main"),
         lambda c: ["-d", c.target, "-b", c.cfg.get("harvester_sources", "crtsh,hackertarget,otx,rapiddns,urlscan"),
                    "-l", "300", "-f", str(c.outdir / "theHarvester")],
         probe=("aiohttp", "theHarvester")),
    Tool("sublist3r", "Sublist3r", "subdomain enumeration", ("domain",),
         ("script", "sublist3r.py"),
         lambda c: ["-d", c.target, "-n", "-o", str(c.outdir / "sublist3r.subdomains.txt")],
         probe=("requests", "dns")),
    Tool("dnstwist", "dnstwist", "typosquat / lookalike domains", ("domain",),
         ("script", "dnstwist.py"), lambda c: ["--registered", c.target], probe=("dns",)),
    Tool("spiderfoot", "spiderfoot", "passive multi-module scan", ("domain", "ip", "email", "username"),
         ("script", "sf.py"),
         lambda c: ["-s", c.target, "-u", "passive", "-q", "-o", "tab"], probe=("cherrypy", "netaddr")),
    Tool("metagoofil", "metagoofil", "documents + metadata for a domain", ("domain",),
         ("script", "metagoofil.py"),
         lambda c: ["-d", c.target, "-t", "pdf,doc,docx,xls,xlsx,ppt,pptx", "-l", "20", "-n", "10",
                    "-o", str(c.outdir / "metagoofil")],
         probe=("requests", "googlesearch"), auto=False),
    Tool("shodan", "shodan-python", "host exposure for an IP/domain", ("ip", "domain"),
         ("func", "shodan.__main__:main"),
         lambda c: ["host", c.target if c.kind == "ip" else _resolve(c.target)],
         probe=("requests", "click", "shodan"), needs=_need_shodan),
    # ---- urls
    Tool("photon", "Photon", "crawler: urls, emails, keys, subdomains", ("url", "domain"),
         ("script", "photon.py"),
         lambda c: ["-u", c.url, "-o", str(c.outdir / "photon")],
         probe=("requests", "tld")),
    Tool("waybackpy", "waybackpy", "known URLs in the Wayback Machine", ("url", "domain"),
         ("func", "waybackpy.cli:main"), lambda c: ["--url", c.url, "--known-urls"],
         probe=("requests", "click", "waybackpy")),
    Tool("eyewitness", "EyeWitness", "screenshots of web targets", ("url", "domain"),
         ("script", "Python/EyeWitness.py"),
         lambda c: ["--web", "--single", c.url, "-d", str(c.outdir / "eyewitness"), "--no-prompt"],
         probe=("selenium",), install="Python/requirements.txt"),
    # ---- framework (interactive only)
    Tool("recon-ng", "recon-ng", "modular recon framework (interactive)", ("domain", "username", "email"),
         ("script", "recon-ng"), lambda c: [], probe=("dns",), auto=False, interactive=True,
         install="REQUIREMENTS"),
]}


B, T, N, M, C = "bool", "text", "int", "multi", "choice"
OPTS: dict[str, tuple[Opt, ...]] = {
    "sherlock": (
        Opt("--nsfw", "Include NSFW sites"),
        Opt("--site", "Only these sites (comma list, e.g. GitHub,Reddit)", M),
        Opt("--timeout", "Per-site timeout (s)", N, 15),
        Opt("--print-all", "Also print sites where it was NOT found"),
        Opt("--proxy", "Proxy URL (socks5://127.0.0.1:9050)", T),
        Opt("--csv", "Also write CSV"),
        Opt("--xlsx", "Also write XLSX"),
    ),
    "maigret": (
        Opt("-a", "Check ALL sites (default: top 500)"),
        Opt("--top-sites", "Number of top sites", N),
        Opt("--tags", "Only site tags (e.g. photo,dating,us)", T),
        Opt("--timeout", "Timeout (s)", N),
        Opt("--pdf", "PDF report"),
        Opt("--html", "HTML report"),
        Opt("--proxy", "Proxy URL", T),
        Opt("--use-disabled-sites", "Include disabled sites"),
    ),
    "blackbird": (
        Opt("--no-update", "Skip site-list update (needs data/wmn-data.json already)"),
        Opt("--permute", "Try username permutations"),
        Opt("--no-nsfw", "Exclude NSFW sites"),
        Opt("--filter", "Site filter expression", T),
        Opt("--pdf", "PDF report"),
        Opt("--csv", "CSV report"),
        Opt("--proxy", "Proxy", T),
        Opt("--timeout", "Timeout (s)", N),
    ),
    "social-analyzer": (
        Opt("--mode", "Mode", C, "fast", ("fast", "slow", "special")),
        Opt("--top", "Top N websites", N, 100),
        Opt("--websites", "Specific websites (space/comma list; overrides top)", T),
        Opt("--filter", "Confidence filter", C, "good", ("good", "maybe", "bad", "good,maybe", "all")),
        Opt("--countries", "Countries (e.g. us br)", T),
        Opt("--extract", "Extract profile links/patterns"),
    ),
    "holehe": (
        Opt("-NP", "Skip password-recovery checks"),
        Opt("-C", "Write CSV"),
        Opt("-T", "Timeout (s)", N, 10),
    ),
    "h8mail": (
        Opt("-bc", "Local breach-compilation path", T),
        Opt("-k", "API keys (service=key,...)", T),
        Opt("--loose", "Loose matching"),
        Opt("-o", "Output CSV file", T),
    ),
    "ignorant": (Opt("-T", "Timeout (s)", N, 10),),
    "instaloader": (
        Opt("--no-posts", "Skip posts (metadata only)", B, True),
        Opt("--stories", "Also stories (needs login)"),
        Opt("--login", "Your Instagram login username", T),
    ),
    "theHarvester": (
        Opt("-l", "Result limit", N, 300),
        Opt("-s", "Start at result N", N),
        Opt("-n", "DNS lookup of found hosts"),
        Opt("-c", "DNS brute force"),
        Opt("-r", "Take over check"),
    ),
    "sublist3r": (
        Opt("-b", "Bruteforce subdomains"),
        Opt("-p", "Scan ports (comma list, e.g. 80,443)", T),
        Opt("-t", "Bruteforce threads", N),
        Opt("-e", "Engines (comma list)", T),
        Opt("-v", "Verbose"),
    ),
    "dnstwist": (
        Opt("--mxcheck", "Check MX can intercept mail"),
        Opt("--geoip", "GeoIP lookup"),
        Opt("--ssdeep", "Fuzzy-hash page similarity"),
        Opt("--whois", "WHOIS lookup"),
        Opt("--format", "Output", C, "cli", ("cli", "json", "csv", "list")),
    ),
    "spiderfoot": (
        Opt("-u", "Use case", C, "passive", ("all", "footprint", "investigate", "passive")),
        Opt("-m", "Only these modules (comma list)", T),
        Opt("-o", "Output format", C, "tab", ("tab", "csv", "json")),
    ),
    "metagoofil": (
        Opt("-t", "File types", T, "pdf,doc,docx,xls,xlsx,ppt,pptx"),
        Opt("-l", "Search results per type", N, 20),
        Opt("-n", "Files to download per type", N, 10),
        Opt("-e", "Delay between searches (s)", N),
    ),
    "photon": (
        Opt("-l", "Crawl depth", N, 2),
        Opt("-t", "Threads", N),
        Opt("-d", "Delay between requests (s)", N),
        Opt("--keys", "Look for API keys/secrets", B, True),
        Opt("--dns", "Enumerate DNS / subdomains", B, True),
        Opt("--wayback", "Seed from archive.org"),
        Opt("--only-urls", "Only extract URLs"),
        Opt("--exclude", "Exclude URLs matching regex", T),
        Opt("-p", "Proxy IP:PORT", T),
    ),
    "waybackpy": (
        Opt("--newest", "Newest snapshot instead of listing all"),
        Opt("--oldest", "Oldest snapshot instead of listing all"),
        Opt("--save", "Save the URL to the archive now"),
    ),
    "eyewitness": (
        Opt("--timeout", "Timeout (s)", N),
        Opt("--threads", "Threads", N),
        Opt("--prepend-https", "Prepend https:// to bare hosts"),
        Opt("--no-dns", "Skip DNS resolution"),
    ),
}
for _n, _o in OPTS.items():
    TOOLS[_n.lower() if _n.lower() in TOOLS else _n].opts = _o

# prompt shown when the menu asks a tool for its target
TARGET_PROMPT = {"username": "username", "email": "email address", "domain": "domain (example.com)",
                 "ip": "IP address", "url": "URL", "phone": "phone with country code (+1 5551234567)"}


def _resolve(host: str) -> str:
    import socket
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


# --------------------------------------------------------------------------
# python interpreter + subprocess plumbing
# --------------------------------------------------------------------------
def interpreter() -> str:
    if os.environ.get("RAVEN_PYTHON"):
        return os.environ["RAVEN_PYTHON"]
    venv = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    return str(venv) if venv.exists() else sys.executable


def child_env(tool: Tool) -> dict:
    env = os.environ.copy()
    d = str(ROOT / tool.dir)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [d, env.get("PYTHONPATH", "")]))
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    env.setdefault("NO_COLOR", "1")
    # piped output defaults to 80 cols; tools hard-wrap long URLs/emails there and corrupt harvesting
    env["COLUMNS"], env["LINES"] = "1000", "50"
    return env


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def command(tool: Tool, argv: list[str]) -> list[str]:
    py, (kind, spec) = interpreter(), tool.run
    if kind == "script":
        return [py, "-u", str(ROOT / tool.dir / spec), *argv]
    if kind == "mod":
        return [py, "-u", "-m", spec, *argv]
    mod, fn = spec.split(":")
    boot = f"import sys; sys.argv[0]={tool.name!r}; from {mod} import {fn} as f; sys.exit(f())"
    return [py, "-u", "-c", boot, *argv]


def probe(tool: Tool) -> list[str]:
    """modules from tool.probe that the interpreter can't import."""
    code = ("import importlib,sys\n"
            "for m in sys.argv[1:]:\n"
            "    try: importlib.import_module(m)\n"
            "    except Exception as e: print(f'{m} ({type(e).__name__}: {e})'.replace('\\n',' ')[:160])")
    try:
        r = subprocess.run([interpreter(), "-c", code, *tool.probe], capture_output=True, text=True,
                           env=child_env(tool), timeout=60)
        return [l for l in r.stdout.splitlines() if l] or ([r.stderr.strip()[-200:]] if r.returncode else [])
    except Exception as e:
        return [f"probe failed: {e}"]


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.cfg: dict = {}
        try:
            self.cfg = json.loads(CONF.read_text())
        except Exception:
            pass
        self.target: str | None = None
        self.kind: str | None = None
        self.found: dict[str, dict[str, str]] = {}  # type -> value -> source tool
        self.lock = threading.Lock()
        self.procs: set[subprocess.Popen] = set()

    # -- persistence
    def save_cfg(self):
        CONF.write_text(json.dumps(self.cfg, indent=2))

    @property
    def outdir(self) -> Path:
        d = OUT / slug(self.target or "_")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_found(self):
        if self.target:
            (self.outdir / "findings.json").write_text(json.dumps(self.found, indent=2))

    def set_target(self, t: str, kind: str | None = None):
        self.target, self.kind = t, kind or detect(t)
        self.found = {}
        fp = self.outdir / "findings.json"
        if fp.exists():
            try:
                self.found = json.loads(fp.read_text())
            except Exception:
                pass

    # -- harvesting
    def harvest(self, text: str, source: str):
        base = self.target if self.kind == "domain" else None
        sub = re.compile(r"\b[a-z0-9][a-z0-9._-]*\." + re.escape(base) + r"\b", re.I) if base else None
        got = {
            "email": EMAIL_RE.findall(text),
            "ip": IP_RE.findall(text),
            "url": [u.rstrip(".,;:") for u in URL_RE.findall(text)],
            "subdomain": [s.lower() for s in sub.findall(text)] if sub else [],
        }
        with self.lock:
            for k, vals in got.items():
                bucket = self.found.setdefault(k, {})
                for v in vals:
                    if k == "email" and v.lower().endswith((".png", ".jpg", ".gif", ".svg")):
                        continue
                    bucket.setdefault(v, source)
            self.save_found()


S = Session()


# --------------------------------------------------------------------------
# running tools
# --------------------------------------------------------------------------
def check_runnable(tool: Tool, kind: str) -> str | None:
    if kind not in tool.kinds:
        return f"takes {'/'.join(tool.kinds)}, target is {kind}"
    if not (ROOT / tool.dir).is_dir():
        return "checkout missing"
    if (why := tool.needs(S.cfg)):
        return why
    return None


def run_tool(tool: Tool, ctx: Ctx, extra: list[str] | None = None, echo: bool = True,
             prefix: str = "", answers: dict | None = None) -> int:
    try:
        argv = tool.args(ctx) + extras(tool, answers) + (extra or [])
    except ValueError as e:
        print(f"{prefix}[{tool.name}] {e}")
        return 2
    cmd = command(tool, argv)
    logf = ctx.outdir / f"{tool.name}.txt"
    cwd = ctx.outdir if tool.cwd_out else ROOT / tool.dir
    if echo:
        print(f"\n=== {tool.name}: {' '.join(shlex.quote(a) for a in argv)[:200]}")
    else:
        print(f"{prefix}[{tool.name}] started (log fills as it runs; slow ones like maigret take minutes)")
    t0, buf, p = time.time(), [], None
    try:
        if tool.interactive:
            return subprocess.call(cmd, cwd=cwd, env=child_env(tool))
        p = subprocess.Popen(cmd, cwd=cwd, env=child_env(tool), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        S.procs.add(p)
        with open(logf, "w", encoding="utf-8") as lf:
            for line in p.stdout:  # type: ignore[union-attr]
                clean = ANSI_RE.sub("", line)
                lf.write(clean)
                buf.append(clean)
                if echo:
                    print(prefix + clean, end="")
            p.wait()
        S.procs.discard(p)
    except KeyboardInterrupt:
        if p:
            p.kill()
        print(f"\n[{tool.name}] interrupted")
        return 130
    except FileNotFoundError as e:
        print(f"{prefix}[{tool.name}] cannot launch: {e}")
        return 127
    text = "".join(buf)
    S.harvest(text, tool.name)
    tail = text.lower()
    if p.returncode and (m := re.search(r"No module named '([\w.]+)'", text)):
        mod = m.group(1)
        print(f"{prefix}[{tool.name}] missing module '{mod}' in {interpreter()}\n"
              f"{prefix}   fix: {interpreter()} -m pip install {mod.split('.')[0]}   (or: install {tool.name})")
    print(f"{prefix}[{tool.name}] exit {p.returncode} in {time.time() - t0:.0f}s -> {logf.relative_to(ROOT)}")
    return p.returncode or 0


def ctx_for(target: str, kind: str) -> Ctx:
    d = OUT / slug(target)
    d.mkdir(parents=True, exist_ok=True)
    return Ctx(target, kind, d, S.cfg)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def need_target() -> bool:
    if not S.target:
        print("no target. `target <username|email|domain|ip|url|+cc phone>`")
        return False
    return True


def cmd_target(a):
    if not a:
        print(f"target: {S.target} ({S.kind})" if S.target else "no target")
        return
    t = " ".join(a)
    kind = None
    if a[0] in ("username", "email", "domain", "ip", "url", "phone") and len(a) > 1:
        kind, t = a[0], " ".join(a[1:])
    S.set_target(t, kind)
    print(f"target = {S.target}  [{S.kind}]   (outputs: {S.outdir.relative_to(ROOT)})")
    plan = [n for n, tl in TOOLS.items() if tl.auto and not check_runnable(tl, S.kind)]
    print("auto would run:", ", ".join(plan) or "nothing")


def cmd_tools(a):
    print(f"{'tool':16} {'takes':26} {'auto':5} notes")
    for n, t in TOOLS.items():
        note = []
        if not (ROOT / t.dir).is_dir():
            note.append("missing")
        elif (why := t.needs(S.cfg)):
            note.append(why)
        if t.interactive:
            note.append("interactive")
        print(f"{n:16} {'/'.join(t.kinds):26} {'yes' if t.auto else '-':5} {t.desc}" + (f"  [{'; '.join(note)}]" if note else ""))


def cmd_run(a):
    """run <tool> [extra args...]"""
    if not a:
        return print("run <tool> [args]   (see `tools`)")
    name, extra = a[0].lower(), a[1:]
    tool = next((t for n, t in TOOLS.items() if n.lower() == name), None)
    if not tool:
        return print(f"unknown tool {name!r}")
    if not need_target() and not tool.interactive:
        return
    kind = S.kind or "domain"
    if (why := check_runnable(tool, kind)) and not tool.interactive:
        return print(f"{tool.name}: {why}")
    run_tool(tool, ctx_for(S.target or "_", kind), extra)


def plan_for(target: str, kind: str, only=None, skip=()):
    out = []
    for n, t in TOOLS.items():
        if only and n not in only:
            continue
        if n in skip or not (t.auto or (only and n in only)):
            continue
        why = check_runnable(t, kind)
        if why:
            print(f"  skip {n}: {why}")
        else:
            out.append(t)
    return out


def run_batch(target: str, kind: str, tools: list[Tool], jobs: int):
    ctx = ctx_for(target, kind)
    if jobs <= 1:
        for t in tools:
            run_tool(t, ctx)
        return
    print(f"running {len(tools)} tools, {jobs} at a time (output goes to files; summary below)")
    with ThreadPoolExecutor(jobs) as ex:
        list(ex.map(lambda t: run_tool(t, ctx, echo=False), tools))


def cmd_auto(a):
    """auto [-j N] [--follow] [--only a,b] [--skip a,b]"""
    if not need_target():
        return
    ap = argparse.ArgumentParser(prog="auto", add_help=False)
    ap.add_argument("-j", type=int, default=1)
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--skip", default="")
    try:
        o = ap.parse_args(a)
    except SystemExit:
        return print(cmd_auto.__doc__)
    only = [x for x in o.only.split(",") if x] or None
    skip = [x for x in o.skip.split(",") if x]
    tools = plan_for(S.target, S.kind, only, skip)
    if not tools:
        return print("nothing to run")
    run_batch(S.target, S.kind, tools, o.j)
    if o.follow:
        cmd_pivot(["--yes", "--max", "10", "-j", str(o.j)])
    cmd_found([])


def cmd_found(a):
    if not S.found or not any(S.found.values()):
        return print("nothing harvested yet")
    for k, vals in S.found.items():
        if not vals or (a and k not in a):
            continue
        print(f"-- {k} ({len(vals)})")
        for i, (v, src) in enumerate(vals.items()):
            if i >= 40:
                print(f"   ... {len(vals) - 40} more in {S.outdir.relative_to(ROOT)}/findings.json")
                break
            print(f"   {v}   <{src}>")


def cmd_pivot(a):
    """pivot [--yes] [--max N] [-j N]  : run tools on harvested emails/subdomains (not the target itself)"""
    if not need_target():
        return
    ap = argparse.ArgumentParser(prog="pivot", add_help=False)
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--max", type=int, default=10)
    ap.add_argument("-j", type=int, default=1)
    o = ap.parse_args(a)
    queue = [(v, "email") for v in list(S.found.get("email", {}))
             if v.lower() != (S.target or "").lower()]
    queue += [(v, "domain") for v in list(S.found.get("subdomain", {}))]
    queue = queue[: o.max]
    if not queue:
        return print("no pivots (need harvested emails/subdomains; run theHarvester/sublist3r first)")
    pivot_tools = {"email": ["holehe", "h8mail"], "domain": ["eyewitness"]}
    print("pivot candidates:")
    for v, k in queue:
        print(f"  {k:7} {v:40} -> {', '.join(pivot_tools[k])}")
    if not o.yes and input("run these? [y/N] ").strip().lower() != "y":
        return
    parent_found, parent_t, parent_k = S.found, S.target, S.kind
    for v, k in queue:
        tools = plan_for(v, k, only=pivot_tools[k])
        if tools:
            S.target, S.kind = v, k  # harvest into the pivot's own findings
            S.found = {}
            run_batch(v, k, tools, o.j)
            for kk, vals in S.found.items():
                for vv, src in vals.items():
                    parent_found.setdefault(kk, {}).setdefault(vv, f"{src}@{v}")
    S.target, S.kind, S.found = parent_t, parent_k, parent_found
    S.save_found()


def cmd_deps(a):
    names = list(TOOLS) if not a or a[0] == "all" else a
    print(f"interpreter: {interpreter()}")
    for n in names:
        t = TOOLS.get(n)
        if not t:
            print(f"{n}: unknown")
            continue
        miss = probe(t)
        print(f"{n:16} {'ok' if not miss else 'MISSING ' + ', '.join(miss)}")


def cmd_install(a):
    """install <tool|all>  : pip install a tool's requirements into raven's interpreter"""
    if not a:
        return print(cmd_install.__doc__)
    names = list(TOOLS) if a[0] == "all" else a
    py = interpreter()
    for n in names:
        t = TOOLS.get(n)
        if not t:
            print(f"{n}: unknown")
            continue
        d = ROOT / t.dir
        req = d / (t.install or "requirements.txt")
        if req.exists():
            cmd = [py, "-m", "pip", "install", "-r", str(req)]
        else:
            cmd = [py, "-m", "pip", "install", str(d)]
        print(f"$ {' '.join(cmd)}")
        if subprocess.call(cmd) != 0 and req.exists():
            # one bad pin (e.g. cryptography<4 on a new Python) aborts the whole -r install:
            # retry package by package, unpinned, so everything installable still lands.
            print(f"-- {n}: bulk install failed, retrying each package unpinned")
            failed = []
            for line in req.read_text(errors="replace").splitlines():
                line = line.split("#")[0].split(";")[0].strip()
                if not line or line.startswith("-"):
                    continue
                pkg = re.split(r"[<>=!~ ]", line, maxsplit=1)[0]
                print(f"   pip install {pkg}")
                if subprocess.call([py, "-m", "pip", "install", "-q", pkg]) != 0:
                    failed.append(pkg)
            if failed:
                print(f"-- {n}: pip could not install: {', '.join(failed)}")
        miss = probe(t)  # trust an import, not pip's exit code
        print(f"-- {n}: " + ("verified, imports OK" if not miss else "STILL BROKEN -> " + "; ".join(miss)))


def cmd_venv(a):
    """venv : create raven/.venv (tools then run from it automatically)"""
    v = ROOT / ".venv"
    if v.exists():
        return print(f"{v} already exists")
    subprocess.check_call([sys.executable, "-m", "venv", str(v)])
    print(f"created {v}; now `install all` (or per tool)")


def cmd_set(a):
    """set <key> [value]  keys: instagram_session, harvester_sources"""
    if not a:
        return print(json.dumps({k: ("***" if "session" in k else v) for k, v in S.cfg.items()}, indent=2) or "{}")
    if len(a) == 1:
        S.cfg.pop(a[0], None)
    else:
        S.cfg[a[0]] = " ".join(a[1:])
    S.save_cfg()
    print("saved")


def cmd_keys(a):
    """keys shodan <KEY> : initialise the Shodan CLI"""
    if len(a) == 2 and a[0] == "shodan":
        subprocess.call(command(TOOLS["shodan"], ["init", a[1]]), env=child_env(TOOLS["shodan"]),
                        cwd=ROOT / TOOLS["shodan"].dir)
    else:
        print(cmd_keys.__doc__)


def cmd_interactive(a):
    """interactive <tool> [args] : run a tool attached to your terminal (logins, prompts, recon-ng, ghunt login)"""
    if not a or a[0] not in TOOLS:
        return print(cmd_interactive.__doc__)
    t = TOOLS[a[0]]
    subprocess.call(command(t, a[1:]), env=child_env(t), cwd=ROOT / t.dir)


def cmd_report(a):
    if not need_target():
        return
    lines = [f"# raven report: {S.target} ({S.kind})", f"_generated {time.ctime()}_", ""]
    for k, vals in S.found.items():
        if vals:
            lines += [f"## {k} ({len(vals)})", *[f"- {v}  _({s})_" for v, s in vals.items()], ""]
    for f in sorted(S.outdir.glob("*.txt")):
        txt = f.read_text(encoding="utf-8", errors="replace")
        lines += [f"## {f.stem}", "```", txt[-4000:].rstrip(), "```", ""]
    rp = S.outdir / "report.md"
    rp.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {rp.relative_to(ROOT)}")


def cmd_ls(a):
    if not need_target():
        return
    for f in sorted(S.outdir.rglob("*")):
        if f.is_file():
            print(f"{f.relative_to(ROOT)}  ({f.stat().st_size} B)")


def cmd_show(a):
    if not need_target() or not a:
        return print("show <tool>")
    f = S.outdir / f"{a[0]}.txt"
    print(f.read_text(encoding="utf-8", errors="replace") if f.exists() else "no output yet")


HELP = """\
target <value>        set target; type is auto-detected (username, email, domain, ip, url, phone)
                      force a type:  target username example.com   |   phone: target +1 5551234567
tools                 list tools, what they accept, and what's blocking them
auto [opts]           run every tool that fits the target
                        -j N       run N at a time        --follow   then pivot on what was found
                        --only a,b --skip a,b
run <tool> [args]     run one tool; extra args are passed straight through
pivot [--yes]         run holehe/h8mail on harvested emails, eyewitness on subdomains
found [type]          emails / ips / urls / subdomains harvested from tool output
show <tool>           print a tool's saved output        ls   list files for this target
report                write output/<target>/report.md
deps [tool|all]       check which tools can import their dependencies
venv / install <t|all>  create .venv and pip install tool requirements
set <key> [value]     config: instagram_session, harvester_sources
keys shodan <KEY>     initialise Shodan
interactive <tool> .. attach a tool to your terminal (ghunt login, recon-ng ...)
!<cmd>                shell escape        help / exit
"""

COMMANDS = {
    "target": cmd_target, "use": cmd_target, "tools": cmd_tools, "run": cmd_run, "auto": cmd_auto,
    "found": cmd_found, "pivot": cmd_pivot, "deps": cmd_deps, "install": cmd_install, "venv": cmd_venv,
    "set": cmd_set, "keys": cmd_keys, "interactive": cmd_interactive, "report": cmd_report,
    "ls": cmd_ls, "show": cmd_show, "help": lambda a: print(HELP), "?": lambda a: print(HELP),
}


def dispatch(line: str) -> bool:
    line = line.strip()
    if not line or line.startswith("#"):
        return True
    if line in ("exit", "quit", "q"):
        return False
    if line.startswith("!"):
        subprocess.call(line[1:], shell=True)
        return True
    try:
        parts = shlex.split(line, posix=(os.name != "nt"))
    except ValueError as e:
        print(e)
        return True
    parts = [p.strip('"') if os.name == "nt" else p for p in parts]
    fn = COMMANDS.get(parts[0].lower())
    if not fn:
        # bare tool name == run it, bare value == set target
        if parts[0].lower() in {n.lower() for n in TOOLS}:
            fn, parts = cmd_run, ["run", *parts]
        else:
            print(f"unknown command {parts[0]!r} (try `help`)")
            return True
    try:
        fn(parts[1:])
    except KeyboardInterrupt:
        print("\n^C")
    except Exception as e:  # keep the REPL alive
        print(f"error: {type(e).__name__}: {e}")
    return True


def ask(prompt: str) -> str:
    return input(prompt).strip()


def pick(title: str, options: list[str]) -> int | None:
    """numbered chooser; returns index or None for back (0 / blank)."""
    print(f"\n{title}")
    for i, o in enumerate(options, 1):
        print(f"  {i:>2}) {o}")
    print("   0) back")
    while True:
        s = ask("> ")
        if s in ("", "0"):
            return None
        if s.isdigit() and 1 <= int(s) <= len(options):
            return int(s) - 1
        print("pick a number from the list")


def menu_tool_list(only_runnable: bool = True) -> list[Tool]:
    kind = S.kind
    return [t for t in TOOLS.values() if not only_runnable or not kind or kind in t.kinds or t.interactive]


KINDS = ["username", "email", "phone", "domain", "ip", "url"]


def pick_kind(kinds=KINDS) -> str | None:
    i = pick("Target type", [k for k in kinds])
    return None if i is None else list(kinds)[i]


def m_target():
    kind = pick_kind()
    if not kind:
        return
    v = ask(f"{TARGET_PROMPT[kind]}: ")
    if v:
        cmd_target([kind, v])


def m_run_one():
    tools = list(TOOLS.values())
    i = pick("Which tool?", [f"{t.name:15} {t.desc}  [{'/'.join(t.kinds)}]" for t in tools])
    if i is None:
        return
    tool = tools[i]
    # 1. target
    if tool.interactive:
        return cmd_interactive([tool.name])
    kind = tool.kinds[0] if len(tool.kinds) == 1 else pick_kind(tool.kinds)
    if not kind:
        return
    cur = S.target if S.target and S.kind == kind else None
    raw = ask(f"{TARGET_PROMPT[kind]}{f' [{cur}]' if cur else ''}: ") or cur
    if not raw:
        return
    if (why := check_runnable(tool, kind)):
        return print(f"{tool.name}: {why}")
    if (S.target, S.kind) != (raw, kind):
        S.set_target(raw, kind)
    # 2. options
    answers = {}
    if tool.opts:
        print(f"\n{tool.name} options (Enter = default):")
        answers = ask_opts(tool)
    extra = ask("any other raw args (blank for none): ")
    run_tool(tool, ctx_for(raw, kind), shlex.split(extra) if extra else None, answers=answers)


def m_auto():
    if not need_target():
        return
    i = pick("Auto-run all matching tools", ["one at a time", "4 in parallel",
                                             "one at a time, then pivot on findings",
                                             "4 in parallel, then pivot on findings"])
    if i is not None:
        cmd_auto((["-j", "4"] if i in (1, 3) else []) + (["--follow"] if i >= 2 else []))


def m_show():
    if not need_target():
        return
    files = sorted(p.stem for p in S.outdir.glob("*.txt"))
    if not files:
        return print("no output yet")
    i = pick("Show output of", files)
    if i is not None:
        cmd_show([files[i]])


def m_deps():
    i = pick("Dependencies", ["check all tools", "check one tool", "create .venv",
                              "install one tool", "install ALL tools"])
    names = list(TOOLS)
    if i == 0:
        cmd_deps([])
    elif i in (1, 3):
        j = pick("Which tool?", names)
        if j is not None:
            (cmd_deps if i == 1 else cmd_install)([names[j]])
    elif i == 2:
        cmd_venv([])
    elif i == 4:
        cmd_install(["all"])


def m_settings():
    i = pick("Settings", ["Instagram sessionid", "theHarvester sources", "Shodan API key",
                          "show current"])
    if i == 0:
        cmd_set(["instagram_session", ask("sessionid: ")])
    elif i == 1:
        cmd_set(["harvester_sources", ask("comma-separated sources: ")])
    elif i == 2:
        cmd_keys(["shodan", ask("key: ")])
    elif i == 3:
        cmd_set([])


def m_interactive():
    names = [n for n, t in TOOLS.items() if t.interactive or n == "ghunt"]
    i = pick("Attach to terminal (logins, recon-ng)", [f"{n}" + (" login" if n == "ghunt" else "") for n in names])
    if i is not None:
        cmd_interactive([names[i]] + (["login"] if names[i] == "ghunt" else []))


MENU = [
    ("Set target", m_target),
    ("Run ONE tool", m_run_one),
    ("Auto-run all matching tools", m_auto),
    ("Show findings (emails / IPs / URLs / subdomains)", lambda: cmd_found([])),
    ("Pivot on findings", lambda: cmd_pivot([])),
    ("View a tool's output", m_show),
    ("Write report", lambda: cmd_report([])),
    ("List tools", lambda: cmd_tools([])),
    ("Dependencies / install", m_deps),
    ("Settings & API keys", m_settings),
    ("Interactive tools (recon-ng, ghunt login)", m_interactive),
]


def menu_loop():
    while True:
        print(f"\n=== raven ===   target: {S.target or '(none)'}" + (f" [{S.kind}]" if S.target else ""))
        for i, (label, _) in enumerate(MENU, 1):
            print(f"  {i:>2}) {label}")
        print("   0) exit        (or type any command, e.g. `help`)")
        s = ask("> ")
        if s in ("0", "q", "exit"):
            return
        if s.isdigit() and 1 <= int(s) <= len(MENU):
            try:
                MENU[int(s) - 1][1]()
            except KeyboardInterrupt:
                print("\n^C")
            except Exception as e:
                print(f"error: {type(e).__name__}: {e}")
        elif s and not dispatch(s):
            return


def main():
    ap = argparse.ArgumentParser(description="raven OSINT REPL")
    ap.add_argument("-c", "--command", action="append", default=[], help="run command(s) then exit")
    ap.add_argument("target", nargs="?", help="initial target")
    o = ap.parse_args()
    if o.target:
        cmd_target([o.target])
    if o.command:
        for c in o.command:
            if not dispatch(c):
                break
        return
    try:
        import readline  # noqa: F401  (history/editing where available)
    except ImportError:
        pass
    print("raven - only investigate targets you're authorised to.")
    try:
        menu_loop()
    except (EOFError, KeyboardInterrupt):
        print()
    for p in list(S.procs):
        p.kill()


if __name__ == "__main__":
    main()
