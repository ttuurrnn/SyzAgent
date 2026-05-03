"""
SyzDirect Runner — syzbot Reproducer Mining.

Searches syzbot (syzkaller.appspot.com) for crash reports involving a target
function, downloads syz/C reproducers, and packs them into a corpus.db for
use as fuzzing seeds.
"""

import json
import os
import re
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from html.parser import HTMLParser


# ---------------------------------------------------------------------------
# syzbot dashboard helpers
# ---------------------------------------------------------------------------

_SYZBOT_BASE = "https://syzkaller.appspot.com"
_USER_AGENT = "SyzDirect-Runner/1.0"
_REQUEST_DELAY = 2  # seconds between requests to avoid throttling


def _http_get(url: str, timeout: int = 30) -> str | None:
    """Simple HTTP GET returning response body text, or None on error."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        print(f"  [syzbot] HTTP error fetching {url}: {e}")
        return None


class _BugLinkParser(HTMLParser):
    """Extract bug links and titles from syzbot HTML pages."""

    def __init__(self):
        super().__init__()
        self.bugs: list[dict] = []
        self._in_link = False
        self._current: dict = {}

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs_d = dict(attrs)
            href = attrs_d.get("href", "")
            if "/bug?" in href:
                self._in_link = True
                if href.startswith("/"):
                    href = _SYZBOT_BASE + href
                self._current = {"url": href, "title": ""}

    def handle_data(self, data):
        if self._in_link:
            self._current["title"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._in_link:
            self._in_link = False
            if self._current.get("title", "").strip():
                self._current["title"] = self._current["title"].strip()
                self.bugs.append(self._current)
            self._current = {}


class _ReproLinkParser(HTMLParser):
    """Extract reproducer download links from a syzbot bug page.

    syzbot uses URLs like:
      /text?tag=ReproSyz&x=HEXID
      /text?tag=ReproC&x=HEXID
    These may appear with &amp; HTML entity encoding.
    """

    def __init__(self):
        super().__init__()
        self.syz_repros: list[str] = []
        self.c_repros: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs_d = dict(attrs)
            href = attrs_d.get("href", "")
            if "ReproSyz" in href or "repro.syz" in href:
                if href.startswith("/"):
                    href = _SYZBOT_BASE + href
                self.syz_repros.append(href)
            elif "ReproC" in href or "repro.c" in href:
                if href.startswith("/"):
                    href = _SYZBOT_BASE + href
                self.c_repros.append(href)


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def search_syzbot_bugs(target_function: str, max_results: int = 10) -> list[dict]:
    """Search syzbot for bugs whose crash stack mentions *target_function*.

    Strategy: fetch the syzbot upstream bug list pages and search for the
    target function name in bug titles.  If that yields nothing, try a broader
    search via the syzbot search endpoint.

    Returns a list of ``{"url": str, "title": str}`` dicts.
    """
    results: list[dict] = []

    # 1. Try syzbot's own search (undocumented but works)
    search_url = f"{_SYZBOT_BASE}/upstream?search={urllib.request.quote(target_function)}"
    print(f"  [syzbot] Searching: {search_url}")
    html = _http_get(search_url)
    if html:
        parser = _BugLinkParser()
        parser.feed(html)
        for bug in parser.bugs:
            if target_function.lower() in bug["title"].lower():
                results.append(bug)

    # 2. Also search in fixed bugs
    if len(results) < max_results:
        time.sleep(_REQUEST_DELAY)
        fixed_url = f"{_SYZBOT_BASE}/upstream/fixed?search={urllib.request.quote(target_function)}"
        html = _http_get(fixed_url)
        if html:
            parser = _BugLinkParser()
            parser.feed(html)
            for bug in parser.bugs:
                if target_function.lower() in bug["title"].lower():
                    if bug["url"] not in {r["url"] for r in results}:
                        results.append(bug)

    # 3. Broader: search by partial name (e.g., "tcindex" from "tcindex_alloc_perfect_hash")
    if not results:
        parts = target_function.split("_")
        if len(parts) >= 2:
            prefix = "_".join(parts[:2])
            short = parts[0]
            for term in [prefix, short]:
                if len(term) < 4:
                    continue
                time.sleep(_REQUEST_DELAY)
                url = f"{_SYZBOT_BASE}/upstream?search={urllib.request.quote(term)}"
                print(f"  [syzbot] Broadened search: {url}")
                html = _http_get(url)
                if html:
                    parser = _BugLinkParser()
                    parser.feed(html)
                    for bug in parser.bugs:
                        # For broadened search, accept bugs with the search term
                        # in the title (not just the full function name)
                        if (term.lower() in bug["title"].lower() and
                                bug["url"] not in {r["url"] for r in results}):
                            results.append(bug)
                if results:
                    break

    results = results[:max_results]
    print(f"  [syzbot] Found {len(results)} potentially relevant bugs")
    for r in results:
        print(f"    · {r['title'][:80]}")
    return results


def fetch_reproducer(bug_url: str) -> list[dict]:
    """Fetch all reproducers from a syzbot bug page.

    Returns a list of ``{"type": "syz"|"c", "text": str, "url": str}``.
    """
    reproducers: list[dict] = []
    html = _http_get(bug_url)
    if not html:
        return reproducers

    parser = _ReproLinkParser()
    parser.feed(html)

    # Deduplicate URLs
    seen_urls = set()
    unique_syz = []
    for url in parser.syz_repros:
        if url not in seen_urls:
            seen_urls.add(url)
            unique_syz.append(url)

    # Prefer syz reproducers (native syzkaller format)
    seen_texts = set()
    for url in unique_syz[:3]:
        time.sleep(_REQUEST_DELAY)
        text = _http_get(url)
        if text and text.strip() and text.strip() not in seen_texts:
            seen_texts.add(text.strip())
            reproducers.append({"type": "syz", "text": text.strip(), "url": url})

    # Also fetch C reproducers as fallback
    if not reproducers:
        unique_c = []
        for url in parser.c_repros:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_c.append(url)
        for url in unique_c[:2]:
            time.sleep(_REQUEST_DELAY)
            text = _http_get(url)
            if text and text.strip():
                reproducers.append({"type": "c", "text": text.strip(), "url": url})

    return reproducers


def convert_c_to_syz(c_code: str, target_function: str,
                     llm_call_fn=None) -> str | None:
    """Convert a C reproducer to syzkaller program format using LLM.

    If no LLM is available, extract syscall patterns heuristically.
    """
    if llm_call_fn is None:
        try:
            from llm_enhance import _call_llm
            llm_call_fn = _call_llm
        except ImportError:
            return None

    prompt = f"""Convert this C kernel reproducer to syzkaller program format.

TARGET: reaching {target_function} in the kernel.

C REPRODUCER:
{c_code[:6000]}

Output ONLY the syzkaller program text. Example format:
  r0 = socket$nl_route(0x10, 0x3, 0x0)
  sendmsg$nl_route_sched(r0, &(0x7f0000001000)={{...}}, 0x0)

Rules:
- Use syzkaller syscall naming (socket$nl_route, sendmsg$nl_route_sched, etc.)
- Encode binary buffers as ANYBLOB hex strings
- Include all setup steps (socket creation, bind, etc.)
- Output only the program, no explanations."""

    result = llm_call_fn(prompt, timeout=120)
    if result and ("socket" in result or "open" in result or "ioctl" in result
                   or "sendmsg" in result or "write" in result):
        return result.strip()
    return None


def mine_seeds_for_target(target_function: str, syz_db_path: str,
                          output_dir: str, max_bugs: int = 5,
                          llm_call_fn=None) -> str | None:
    """Search syzbot for reproducers related to target_function, pack as corpus.db.

    Args:
        target_function: kernel function name to search for.
        syz_db_path: path to syz-db binary.
        output_dir: directory for output corpus.db.
        max_bugs: maximum number of bugs to fetch reproducers from.
        llm_call_fn: optional LLM call function for C→syz conversion.

    Returns:
        Absolute path to generated corpus.db, or None if nothing found.
    """
    print(f"  [syzbot] Mining reproducers for: {target_function}")

    bugs = search_syzbot_bugs(target_function, max_results=max_bugs)
    if not bugs:
        print(f"  [syzbot] No relevant bugs found on syzbot")
        return None

    programs: list[str] = []

    for i, bug in enumerate(bugs[:max_bugs]):
        print(f"  [syzbot] Fetching reproducers from bug {i+1}/{len(bugs)}: {bug['title'][:60]}")
        time.sleep(_REQUEST_DELAY)
        repros = fetch_reproducer(bug["url"])

        for repro in repros:
            if repro["type"] == "syz":
                programs.append(repro["text"])
                print(f"    ✓ Got syz reproducer ({len(repro['text'])} bytes)")
            elif repro["type"] == "c":
                syz_text = convert_c_to_syz(
                    repro["text"], target_function, llm_call_fn,
                )
                if syz_text:
                    programs.append(syz_text)
                    print(f"    ✓ Converted C reproducer to syz ({len(syz_text)} bytes)")
                else:
                    print(f"    ✗ Failed to convert C reproducer")

    if not programs:
        print(f"  [syzbot] No usable reproducers found")
        return None

    print(f"  [syzbot] Collected {len(programs)} reproducer programs, packing...")

    # Pack into corpus.db
    try:
        from llm_enhance import pack_programs_to_corpus
    except ImportError:
        # Inline packing
        prog_dir = tempfile.mkdtemp(prefix="syzbot_repro_")
        try:
            for i, prog in enumerate(programs):
                with open(os.path.join(prog_dir, f"{i:04d}_syzbot"), "w") as f:
                    f.write(prog + "\n")

            os.makedirs(output_dir, exist_ok=True)
            corpus_db = os.path.join(output_dir, f"syzbot_seed_{target_function}.db")

            result = subprocess.run(
                [syz_db_path, "pack", prog_dir, corpus_db],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                print(f"  [syzbot] syz-db pack failed: {result.stderr[:200]}")
                return None
            return corpus_db
        finally:
            import shutil
            shutil.rmtree(prog_dir, ignore_errors=True)

    os.makedirs(output_dir, exist_ok=True)
    corpus_db = os.path.join(output_dir, f"syzbot_seed_{target_function}.db")
    result = pack_programs_to_corpus(programs, syz_db_path, corpus_db)
    return result


# ---------------------------------------------------------------------------
# CLI entry point for testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_function> [syz_db_path]")
        sys.exit(1)

    target = sys.argv[1]
    syz_db = sys.argv[2] if len(sys.argv) > 2 else None

    bugs = search_syzbot_bugs(target)
    for bug in bugs:
        print(f"\n{'='*60}")
        print(f"Bug: {bug['title']}")
        print(f"URL: {bug['url']}")
        repros = fetch_reproducer(bug["url"])
        for r in repros:
            print(f"  [{r['type']}] {r['text'][:200]}...")
        time.sleep(_REQUEST_DELAY)
