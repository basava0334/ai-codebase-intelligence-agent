from pathlib import Path

import streamlit as st

st.set_page_config(page_title="AI Codebase Intelligence Agent")

st.title("AI Codebase Intelligence Agent")
st.write("Search Python code and inspect basic codebase statistics.")

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
                lines = file_path.read_text(encoding="utf-8").splitlines()
                file_lines[file_path] = lines
            except (UnicodeDecodeError, OSError):
                continue

        total_lines = sum(len(lines) for lines in file_lines.values())

        st.subheader("Codebase overview")
        st.write(f"Python files analyzed: {len(file_lines)}")
        st.write(f"Total lines of Python code: {total_lines}")

        largest_files = sorted(
            file_lines.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )

        st.subheader("Largest files")
        for file_path, lines in largest_files[:10]:
            st.write(f"{file_path.relative_to(project_path)} — {len(lines)} lines")

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
