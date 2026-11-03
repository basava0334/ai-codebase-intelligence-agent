from pathlib import Path

import streamlit as st

st.set_page_config(page_title="AI Codebase Intelligence Agent")

st.title("AI Codebase Intelligence Agent")
st.write("Choose a Python project folder to search its code.")

folder = st.text_input("Project folder path")

if folder:
    project_path = Path(folder).expanduser()

    if not project_path.is_dir():
        st.error("That folder was not found. Check the path and try again.")
    else:
        python_files = list(project_path.rglob("*.py"))
        st.write(f"Found {len(python_files)} Python files.")

        query = st.text_input("Search for code")
        if query:
            matches = 0

            for file_path in python_files:
                try:
                    lines = file_path.read_text(encoding="utf-8").splitlines()
                except UnicodeDecodeError:
                    continue

                for line_number, line in enumerate(lines, start=1):
                    if query.lower() in line.lower():
                        matches += 1
                        st.code(
                            f"{file_path.relative_to(project_path)}:{line_number}  {line}"
                        )

            if matches == 0:
                st.info("No matching lines found.")
