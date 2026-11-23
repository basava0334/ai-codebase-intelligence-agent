from pathlib import Path
import re


LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".c": "C",
    ".h": "C/C++",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".hxx": "C++",
    ".java": "Java",
}


ALL_SOURCE_EXTENSIONS = set(LANGUAGE_BY_EXTENSION)

SECURITY_RULES = [
    {
        "name": "Possible hardcoded secret",
        "severity": "High",
        "explanation": (
            "A password, token, or API key may be stored in source code. "
            "Check whether it is a real secret and move real secrets "
            "to a protected configuration."
        ),
        "extensions": ALL_SOURCE_EXTENSIONS,
        "pattern": re.compile(
            r"""(?i)\b(api[_-]?key|password|passwd|secret|token)\b"""
            r"""\s*[:=]\s*["'][^"']{8,}["']"""
        ),
    },
    {
        "name": "Use of eval()",
        "severity": "High",
        "explanation": (
            "eval() can run text as code. Review whether the input "
            "could be controlled by a user."
        ),
        "extensions": {".py"},
        "pattern": re.compile(r"\beval\s*\("),
    },
    {
        "name": "Use of exec()",
        "severity": "High",
        "explanation": (
            "exec() can run text as code. Review whether the input "
            "could be controlled by a user."
        ),
        "extensions": {".py"},
        "pattern": re.compile(r"\bexec\s*\("),
    },
    {
        "name": "Pickle loading",
        "severity": "High",
        "explanation": (
            "Loading an untrusted pickle file can run harmful code."
        ),
        "extensions": {".py"},
        "pattern": re.compile(r"\bpickle\.(load|loads)\s*\("),
    },
    {
        "name": "Subprocess with shell=True",
        "severity": "Medium",
        "explanation": (
            "A shell command combined with untrusted input may allow "
            "command injection."
        ),
        "extensions": {".py"},
        "pattern": re.compile(r"\bshell\s*=\s*True\b"),
    },
    {
        "name": "Use of gets()",
        "severity": "High",
        "explanation": (
            "gets() does not limit input length and can cause a "
            "buffer overflow. Use a bounded input function."
        ),
        "extensions": {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
        "pattern": re.compile(r"\bgets\s*\("),
    },
    {
        "name": "Use of strcpy()",
        "severity": "Medium",
        "explanation": (
            "strcpy() does not check the destination buffer size. "
            "Review the buffer size and input length."
        ),
        "extensions": {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
        "pattern": re.compile(r"\bstrcpy\s*\("),
    },
    {
        "name": "Use of sprintf()",
        "severity": "Medium",
        "explanation": (
            "sprintf() does not limit output length and may overflow "
            "the destination buffer."
        ),
        "extensions": {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
        "pattern": re.compile(r"\bsprintf\s*\("),
    },
    {
        "name": "Use of system()",
        "severity": "High",
        "explanation": (
            "system() runs a command through the operating system shell. "
            "Review whether any part of the command comes from user input."
        ),
        "extensions": {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
        "pattern": re.compile(r"\bsystem\s*\("),
    },
    {
        "name": "Java Runtime.exec()",
        "severity": "High",
        "explanation": (
            "Runtime.exec() starts a system process. Review whether "
            "the command includes untrusted input."
        ),
        "extensions": {".java"},
        "pattern": re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("),
    },
    {
        "name": "Java object deserialization",
        "severity": "Medium",
        "explanation": (
            "Deserializing untrusted Java objects can be unsafe. "
            "Check where the serialized data comes from."
        ),
        "extensions": {".java"},
        "pattern": re.compile(r"\bObjectInputStream\b"),
    },
    {
        "name": "Possible weak Java hash",
        "severity": "Medium",
        "explanation": (
            "MD5 and SHA-1 are not suitable for new security-sensitive "
            "hashing. Review the purpose of this hash."
        ),
        "extensions": {".java"},
        "pattern": re.compile(
            r"""MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-1)["']"""
        ),
    },
]


IGNORED_DIRECTORIES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
}


def scan_code_files(project_folder):
    """Scan supported source files and return possible security findings."""
    root = Path(project_folder).expanduser()

    if not root.is_dir():
        raise NotADirectoryError(f"Folder not found: {root}")

    findings = []

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        if any(part.lower() in IGNORED_DIRECTORIES for part in file_path.parts):
            continue

        extension = file_path.suffix.lower()
        if extension not in LANGUAGE_BY_EXTENSION:
            continue

        # Skip this scanner's rule definitions so it does not match itself.
        if file_path.name == Path(__file__).name:
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
                if (
                    extension in rule["extensions"]
                    and rule["pattern"].search(line)
                ):
                    findings.append(
                        {
                            "file": str(file_path.relative_to(root)),
                            "line": line_number,
                            "language": LANGUAGE_BY_EXTENSION[extension],
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "explanation": rule["explanation"],
                            "code": line.strip(),
                        }
                    )

    return findings