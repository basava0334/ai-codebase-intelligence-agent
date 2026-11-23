from pathlib import Path
import re


SECURITY_RULES = [
    {
        "name": "Possible hardcoded secret",
        "severity": "High",
        "explanation": "A password, token, or API key may be stored directly in source code.",
        "pattern": re.compile(
            r"""(?i)\b(api[_-]?key|password|passwd|secret|token)\b"""
            r"""\s*[:=]\s*["'][^"']{8,}["']"""
        ),
    },
    {
        "name": "Use of eval()",
        "severity": "High",
        "explanation": "eval() can run text as code. Review whether the input could be controlled by a user.",
        "pattern": re.compile(r"\beval\s*\("),
    },
    {
        "name": "Use of exec()",
        "severity": "High",
        "explanation": "exec() can run text as code. Review whether the input could be controlled by a user.",
        "pattern": re.compile(r"\bexec\s*\("),
    },
    {
        "name": "Subprocess with shell=True",
        "severity": "Medium",
        "explanation": "Combining a shell command with untrusted input can allow command injection.",
        "pattern": re.compile(r"\bshell\s*=\s*True\b"),
    },
    {
        "name": "Pickle loading",
        "severity": "Medium",
        "explanation": "Loading an untrusted pickle file can run harmful code.",
        "pattern": re.compile(r"\bpickle\.(load|loads)\s*\("),
    },
]


def scan_python_files(project_folder):
    """Scan Python files and return possible security findings."""
    root = Path(project_folder).expanduser()
    findings = []

    if not root.is_dir():
        raise NotADirectoryError(f"Folder not found: {root}")

    for file_path in root.rglob("*.py"):
        # Do not scan this scanner's own rule definitions.
        if file_path.resolve() == Path(__file__).resolve():
            continue

        try:
            lines = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        except OSError:
            continue

        for line_number, line in enumerate(lines, start=1):
            for rule in SECURITY_RULES:
                if rule["pattern"].search(line):
                    findings.append(
                        {
                            "file": str(file_path.relative_to(root)),
                            "line": line_number,
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "explanation": rule["explanation"],
                            "code": line.strip(),
                        }
                    )

    return findings