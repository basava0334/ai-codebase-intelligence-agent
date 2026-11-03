from pathlib import Path

import streamlit as st

st.set_page_config(page_title="AI Codebase Intelligence Agent")

st.title("AI Codebase Intelligence Agent")
st.write("Choose a Python project folder to see its Python files.")

folder = st.text_input("Project folder path")

if folder:
    project_path = Path(folder).expanduser()

    if not project_path.is_dir():
        st.error("That folder was not found. Check the path and try again.")
    else:
        python_files = list(project_path.rglob("*.py"))
        st.write(f"Found {len(python_files)} Python files:")

        for file_path in python_files:
            st.write(file_path.relative_to(project_path))
