#!/usr/bin/env python3
"""Post-process Doxygen-generated HTML to replace <span class="tt">...</span> with <code>...</code>

Usage: fix_doxygen_html.py <path-to-html-dir>
"""

import re
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print("Usage: fix_doxygen_html.py <html-dir>")
    sys.exit(2)

html_dir = Path(sys.argv[1])
if not html_dir.exists() or not html_dir.is_dir():
    print(f"Error: {html_dir} is not a directory")
    sys.exit(2)

pattern = re.compile(r'<span\s+class="tt">(.*?)</span>', re.S)

changed = 0
for p in html_dir.rglob("*.html"):
    s = p.read_text(encoding="utf-8")
    matches = pattern.findall(s)
    if matches:
        new = pattern.sub(r"<code>\1</code>", s)
        p.write_text(new, encoding="utf-8")
        print(f"fixed {p}: {len(matches)} replacements")
        changed += 1

print(f"fix_doxygen_html: processed {changed} files in {html_dir}")
