#!/usr/bin/env python3
"""Diagnose why an AuthLeak dashboard may not show the Session Harvester UI."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INDEX_FILE = ROOT / "index.html"
MAIN_FILE = ROOT / "main.py"


def run_git(*arguments: str) -> tuple[bool, str]:
    """Run a git command from the script directory without raising on failure."""
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return False, "git executable not found"
    output = (completed.stdout or completed.stderr).strip()
    return completed.returncode == 0, output


def answer(label: str, value: bool, detail: str) -> None:
    print(f"{label}: {'Yes' if value else 'No'}")
    print(f"  {detail}")


def check_html() -> bool:
    if not INDEX_FILE.is_file():
        answer("HTML file present", False, f"Missing file: {INDEX_FILE}")
        answer("Session Harvester UI in local HTML", False, "Cannot inspect a missing index.html file.")
        return False

    source = INDEX_FILE.read_text(encoding="utf-8", errors="replace")
    has_heading = "Session Harvester" in source
    has_victim_button = "Harvest Victim Session" in source
    has_attacker_button = "Harvest Attacker Session" in source
    answer("HTML file present", True, str(INDEX_FILE))
    answer(
        "Session Harvester UI in local HTML",
        has_heading or has_victim_button or has_attacker_button,
        f"Heading: {'Yes' if has_heading else 'No'}; "
        f"Victim button: {'Yes' if has_victim_button else 'No'}; "
        f"Attacker button: {'Yes' if has_attacker_button else 'No'}.",
    )
    return has_heading or has_victim_button or has_attacker_button


def check_main() -> bool:
    if not MAIN_FILE.is_file():
        answer("main.py present", False, f"Missing file: {MAIN_FILE}")
        answer("/api/harvest route declared", False, "Cannot inspect a missing main.py file.")
        answer("FastAPI index path points at local index.html", False, "Cannot inspect a missing main.py file.")
        return False

    source = MAIN_FILE.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(MAIN_FILE))
        routes = {
            argument.value
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for decorator in node.decorator_list
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in {"get", "post", "put", "delete", "patch"}
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
            and isinstance(decorator.args[0].value, str)
            for argument in [decorator.args[0]]
        }
        parsed = True
    except SyntaxError as error:
        routes = set()
        parsed = False
        print(f"main.py syntax parse error: {error}")

    has_harvest_route = "/api/harvest" in routes
    points_to_local_html = "Path(__file__).with_name(\"index.html\")" in source
    serves_index = "FileResponse(INDEX_FILE)" in source
    answer("main.py present", True, str(MAIN_FILE))
    answer("main.py syntax parsed", parsed, "AST route inspection completed." if parsed else "Fix the syntax error above first.")
    answer("/api/harvest route declared", has_harvest_route, f"Declared routes include: {', '.join(sorted(routes)) or 'none'}")
    answer(
        "FastAPI index path points at local index.html",
        points_to_local_html and serves_index,
        f"INDEX_FILE assignment found: {'Yes' if points_to_local_html else 'No'}; "
        f"FileResponse(INDEX_FILE) found: {'Yes' if serves_index else 'No'}.",
    )
    return has_harvest_route and points_to_local_html and serves_index


def check_git() -> bool:
    log_ok, log = run_git("log", "-n", "1", "--format=%H%n%D%n%s")
    branches_ok, branches = run_git("branch", "-a")
    head_ok, head = run_git("rev-parse", "HEAD")
    upstream_ok, upstream = run_git("rev-parse", "@{upstream}")
    status_ok, status = run_git("status", "--porcelain")

    print("Git log -n 1:")
    print(f"  {log or 'Unavailable'}")
    print("Git branch -a:")
    print(f"  {branches or 'Unavailable'}")
    answer("Git commands available", log_ok and branches_ok and head_ok, "git log -n 1, git branch -a, and git rev-parse HEAD were executed.")
    answer("HEAD matches configured upstream", upstream_ok and head == upstream, f"HEAD: {head or 'Unavailable'}; upstream: {upstream or 'No upstream configured'}.")
    answer("Working tree clean", status_ok and not status, "No tracked changes reported." if status_ok and not status else (status or "Unable to read git status."))
    return upstream_ok and head == upstream


def main() -> int:
    print(f"AuthLeak diagnostic root: {ROOT}")
    print("=" * 72)
    html_ok = check_html()
    print("=" * 72)
    route_ok = check_main()
    print("=" * 72)
    git_ok = check_git()
    print("=" * 72)
    answer(
        "Expected Session Harvester pipeline present",
        html_ok and route_ok and git_ok,
        "Yes means local HTML, local FastAPI wiring, and configured upstream HEAD all agree. "
        "No identifies the failing check above.",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
