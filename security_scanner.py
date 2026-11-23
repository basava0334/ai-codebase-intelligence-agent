from pathlib import Path
import re


# These patterns identify code that may need a security review.
# A match is a warning for a human to check, not proof of a vulnerability.
SECURITY_RULES = [
    (
        "Possible hardcoded secret",
        re.compile(
            r"""(?i)\b(api[_-]?key|password|passwd|secret|token)\b"""
            r"""\s*[:=]\s*["'][^"']{8,}["']"""
        ),
    ),
    (
        "Use of eval()",
        re.compile(r"\beval\s*\("),
    ),
    (
        "Use of exec()",
        re.compile(r"\bexec\s*\("),
    ),
    (
        "Subprocess with shell=True",
        re.compile(r"\bshell\s*=\s*True\b"),
    ),
    (
        "Pickle loading",
        re.compile(r"\bpickle\.(load|loads)\s*\("),
    ),
]


def scan_python_files(project_folder):
    """Scan Python files and return possible security findings."""
    root = Path(project_folder).expanduser()
    findings = []

    if not root.is_dir():
        raise NotADirectoryError(f"Folder not found: {root}")

    for file_path in root.rglob("*.py"):
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
            for rule_name, pattern in SECURITY_RULES:
                if pattern.search(line):
                    findings.append(
                        {
                            "file": str(file_path.relative_to(root)),
                            "line": line_number,
                            "rule": rule_name,
                            "code": line.strip(),
                        }
                    )

    return findings