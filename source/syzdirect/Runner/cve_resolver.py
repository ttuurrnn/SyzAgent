#!/usr/bin/env python3
"""
CVE Auto-Resolver for SyzDirect.

Given only a CVE ID, resolves:
  - fix_commit:  the patch commit that fixed the CVE
  - commit:      the vulnerable kernel commit (to build & fuzz)
  - function:    the target function modified by the fix
  - file:        the source file containing that function

Data sources (tried in order):
  1. Linux kernel CVE list (git.kernel.org/pub/scm/linux/security/vulns.git)
  2. NVD API (services.nvd.nist.gov)
  3. GitHub commit search (api.github.com)
"""

import json
import re
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple


class CVEResolveError(Exception):
    """Raised when CVE auto-resolution fails."""


class CVEResolver:
    """Resolve a CVE ID to kernel commit, function, and file."""

    _KERNEL_VULNS_URL = (
        "https://git.kernel.org/pub/scm/linux/security/vulns.git/plain"
        "/cve/published/{year}/{cve_id}.sha1"
    )
    _NVD_API_URL = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    )
    _GITHUB_SEARCH_URL = (
        "https://api.github.com/search/commits?q=repo:torvalds/linux+{cve_id}"
    )
    _KERNEL_PATCH_URL = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        "/patch/?id={commit}"
    )
    _KERNEL_COMMIT_URL = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
        "/commit/?id={commit}"
    )

    _TIMEOUT = 30  # seconds per HTTP request

    def __init__(self, cve_id: str, verbose: bool = True):
        self.cve_id = cve_id.upper().strip()
        self.verbose = verbose
        if not re.match(r"^CVE-\d{4}-\d+$", self.cve_id):
            raise CVEResolveError(f"Invalid CVE ID format: {self.cve_id}")
        self.year = self.cve_id.split("-")[1]

    def resolve(self) -> Dict[str, str]:
        """Resolve CVE → {commit, function, file, fix_commit}.

        Raises CVEResolveError if resolution fails at any stage.
        """
        self._log(f"Resolving {self.cve_id} ...")

        # Stage A: find fix commit
        fix_hash = self._find_fix_commit()
        self._log(f"  Fix commit: {fix_hash}")

        # Stage B: fetch patch, extract function & file
        patch_text = self._fetch_patch(fix_hash)
        func, fpath = self._parse_patch(patch_text)
        self._log(f"  Function:   {func}")
        self._log(f"  File:       {fpath}")

        # Stage C: determine vulnerable commit
        vuln_commit = self._find_vuln_commit(fix_hash, patch_text)
        self._log(f"  Vuln commit: {vuln_commit}")

        return {
            "commit": vuln_commit,
            "function": func,
            "file": fpath,
            "fix_commit": fix_hash,
        }

    # ── Stage A: find fix commit ──────────────────────────────────────────

    def _find_fix_commit(self) -> str:
        """Try multiple sources to find the fix commit hash."""
        for name, method in [
            ("kernel-vulns-repo", self._try_kernel_vulns_repo),
            ("NVD API", self._try_nvd_api),
            ("GitHub search", self._try_github_search),
        ]:
            try:
                result = method()
                if result:
                    self._log(f"  (source: {name})")
                    return result
            except Exception as e:
                self._log(f"  {name} failed: {e}")
        raise CVEResolveError(
            f"Could not find fix commit for {self.cve_id} in any source.\n"
            f"Please provide --commit manually."
        )

    def _try_kernel_vulns_repo(self) -> Optional[str]:
        """Query the official Linux kernel CVE list."""
        # Try .sha1 file first (contains fix commit hashes, one per line)
        url = self._KERNEL_VULNS_URL.format(year=self.year, cve_id=self.cve_id)
        body = self._http_get(url)
        if not body:
            return None
        # File contains one or more commit hashes, take the first
        for line in body.strip().splitlines():
            line = line.strip()
            if re.match(r"^[0-9a-f]{12,40}$", line):
                return line
        return None

    def _try_nvd_api(self) -> Optional[str]:
        """Query NVD API for patch references."""
        url = self._NVD_API_URL.format(cve_id=self.cve_id)
        body = self._http_get(url)
        if not body:
            return None
        data = json.loads(body)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        refs = vulns[0].get("cve", {}).get("references", [])
        # Look for git commit URLs
        commit_re = re.compile(
            r"(?:git\.kernel\.org/.+/commit/?\?.*id=|"
            r"github\.com/torvalds/linux/commit/)"
            r"([0-9a-f]{7,40})"
        )
        for ref in refs:
            url = ref.get("url", "")
            m = commit_re.search(url)
            if m:
                return m.group(1)
        return None

    def _try_github_search(self) -> Optional[str]:
        """Search GitHub for commits mentioning the CVE."""
        url = self._GITHUB_SEARCH_URL.format(cve_id=self.cve_id)
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github.cloak-preview+json",
            "User-Agent": "SyzDirect-CVEResolver/1.0",
        })
        body = self._http_get_req(req)
        if not body:
            return None
        data = json.loads(body)
        items = data.get("items", [])
        if items:
            return items[0].get("sha")
        return None

    # ── Stage B: fetch and parse patch ────────────────────────────────────

    def _fetch_patch(self, commit_hash: str) -> str:
        """Fetch unified diff from kernel.org."""
        url = self._KERNEL_PATCH_URL.format(commit=commit_hash)
        body = self._http_get(url)
        if not body:
            raise CVEResolveError(
                f"Failed to fetch patch for {commit_hash}.\n"
                f"The commit may not be in mainline torvalds/linux."
            )
        return body

    def _parse_patch(self, patch: str) -> Tuple[str, str]:
        """Extract (function, file) from unified diff.

        Strategy:
          1. Collect all changed .c files with hunk counts
          2. Pick the file with most hunks
          3. Extract function names from @@ hunk headers for that file
          4. Pick the most-frequent function
        """
        # Parse changed files and their hunks
        file_hunks: Dict[str, List[str]] = {}  # filepath -> [func_names]
        current_file = None

        for line in patch.splitlines():
            # +++ b/net/core/sock.c
            m = re.match(r"^\+\+\+ b/(.+)$", line)
            if m:
                current_file = m.group(1)
                continue
            # @@ -1234,7 +1234,8 @@ int sock_setsockopt(struct sock *sk, ...)
            if current_file and line.startswith("@@"):
                m = re.match(r"^@@.*@@\s+(.+)$", line)
                if m:
                    context = m.group(1).strip()
                    func = self._extract_func_name(context)
                    if func:
                        file_hunks.setdefault(current_file, []).append(func)
                else:
                    file_hunks.setdefault(current_file, [])

        # Filter to .c files only (prefer over .h)
        c_files = {f: funcs for f, funcs in file_hunks.items() if f.endswith(".c")}
        if not c_files:
            c_files = file_hunks  # fall back to whatever we have

        if not c_files:
            raise CVEResolveError("Could not parse any changed files from patch.")

        # Pick file with most hunks
        best_file = max(c_files, key=lambda f: len(c_files[f]))
        funcs = c_files[best_file]

        if not funcs:
            raise CVEResolveError(
                f"Could not extract function name from patch hunks in {best_file}.\n"
                f"Please provide --function manually."
            )

        # Pick most frequent function
        freq: Dict[str, int] = {}
        for f in funcs:
            freq[f] = freq.get(f, 0) + 1
        best_func = max(freq, key=freq.get)

        return best_func, best_file

    @staticmethod
    def _extract_func_name(context: str) -> Optional[str]:
        """Extract function name from a @@ hunk context line.

        Examples:
          'int sock_setsockopt(struct sock *sk, ...)' → 'sock_setsockopt'
          'static void __teql_destroy(struct net_device *dev)' → '__teql_destroy'
        """
        # Match the last identifier before '('
        m = re.search(r"\b(\w+)\s*\(", context)
        if m:
            name = m.group(1)
            # Skip common C keywords that aren't function names
            if name in ("if", "for", "while", "switch", "return", "sizeof",
                        "typeof", "defined", "else"):
                return None
            return name
        return None

    # ── Stage C: vulnerable commit ────────────────────────────────────────

    def _find_vuln_commit(self, fix_hash: str, patch: str) -> str:
        """Find the vulnerable commit to check out.

        Always uses fix_commit~1 (parent of the fix) because:
        - The Fixes: tag points to the *introducing* commit which can be
          very old and unreachable in a shallow clone.
        - fix~1 is guaranteed fetchable alongside the fix commit and is
          the most recent vulnerable state of the code.
        """
        # Log Fixes: tag for reference only
        fixes_re = re.compile(r"Fixes:\s+([0-9a-f]{7,40})\b")
        m = fixes_re.search(patch)
        if m:
            self._log(f"  (Fixes: tag references introducing commit {m.group(1)})")

        self._log(f"  Using {fix_hash}~1 as vulnerable commit")
        return f"{fix_hash}~1"

    # ── HTTP helpers ──────────────────────────────────────────────────────

    def _http_get(self, url: str) -> Optional[str]:
        """GET a URL, return body as string or None on error."""
        req = urllib.request.Request(url, headers={
            "User-Agent": "SyzDirect-CVEResolver/1.0",
        })
        return self._http_get_req(req)

    def _http_get_req(self, req: urllib.request.Request) -> Optional[str]:
        """Execute a prepared Request, return body or None."""
        try:
            with urllib.request.urlopen(req, timeout=self._TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            self._log(f"  HTTP error for {req.full_url}: {e}")
            return None

    def _log(self, msg: str):
        if self.verbose:
            print(msg, file=sys.stderr)


# ── CLI entrypoint ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Resolve CVE → kernel commit/function/file")
    parser.add_argument("cve_id", help="CVE ID (e.g. CVE-2025-12345)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    try:
        result = CVEResolver(args.cve_id, verbose=not args.quiet).resolve()
        print(json.dumps(result, indent=2))
    except CVEResolveError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
