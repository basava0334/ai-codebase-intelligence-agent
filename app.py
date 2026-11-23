from pathlib import Path

import streamlit as st

from security_scanner import scan_python_files


st.set_page_config(page_title="AI Codebase Intelligence Agent")

st.title("AI Codebase Intelligence Agent")
st.write(
    "Explore Python code, view basic codebase statistics, "
    "and review possible security risks."
)

folder = st.text_input("Project folder path")

if folder:
    project_path = Path(folder).expanduser()

    if not project_path.is_dir():
        st.error("That folder was not found. Check the path and try again.")
    else:
        python_files = list(project_path.rglob("*.py"))
        file_lines = {}

        for file_path in python_files:
            try:
                lines = file_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                ).splitlines()
                file_lines[file_path] = lines
            except OSError:
                continue

        total_lines = sum(len(lines) for lines in file_lines.values())

        st.subheader("Codebase overview")
        st.write(f"Python files analyzed: {len(file_lines)}")
        st.write(f"Total lines of Python code: {total_lines}")

        st.subheader("Largest files")
        largest_files = sorted(
            file_lines.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )

        for file_path, lines in largest_files[:10]:
            st.write(
                f"{file_path.relative_to(project_path)} — {len(lines)} lines"
            )

        st.subheader("Possible maintenance hotspots")
        large_files = [
            (file_path, lines)
            for file_path, lines in file_lines.items()
            if len(lines) >= 50
        ]

        if large_files:
            for file_path, lines in large_files:
                st.warning(
                    f"{file_path.relative_to(project_path)} has "
                    f"{len(lines)} lines. Consider reviewing this file."
                )
        else:
            st.success("No Python files with 50 or more lines were found.")

        st.subheader("Security review")
        try:
            findings = scan_python_files(project_path)
        except NotADirectoryError as error:
            st.error(str(error))
            findings = []

        if findings:
            st.write(f"Possible findings: {len(findings)}")

            for finding in findings:
                st.warning(
                    f"{finding['file']}:{finding['line']} — "
                    f"{finding['rule']}"
                )
                st.code(finding["code"], language="python")
        else:
            st.success("No matches for the current security rules.")

        st.caption(
            "These are pattern-based warnings for human review. "
            "They do not prove a vulnerability or guarantee the code is secure."
        )

        st.subheader("Search code")
        query = st.text_input("Search for code")

        if query:
            matches = 0

            for file_path, lines in file_lines.items():
                for line_number, line in enumerate(lines, start=1):
                    if query.lower() in line.lower():
                        matches += 1
                        st.code(
                            f"{file_path.relative_to(project_path)}:"
                            f"{line_number}  {line}"
                        )

            if matches == 0:
                st.info("No matching lines found.")