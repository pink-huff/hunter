# Import libraries
import ast
import os

def parse_function_docstring(source_code):
    functions = []
    tree = ast.parse(source_code)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            docstring = ast.get_docstring(node)
            if docstring:
                functions.append((node.name, docstring))
    return functions

def generate_markdown_documentation(source_file_path):
    with open(source_file_path, 'r') as file:
        source_code = file.read()

    functions = parse_function_docstring(source_code)
    markdown_docs = [f"## Documentation for `{os.path.basename(source_file_path)}`\n\n"]

    for func_name, docstring in functions:
        markdown_docs.append(f"### {func_name}\n```python\n{docstring}\n```\n")

    return '\n'.join(markdown_docs)

def process_directory(directory):
    all_docs = ["# Project Documentation\n\n"]

    for subdir, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                file_path = os.path.join(subdir, file)
                markdown_documentation = generate_markdown_documentation(file_path)
                if markdown_documentation.strip():
                    all_docs.append(markdown_documentation)
                else:
                    print(f"No documentation generated for {file_path}")
    return "\n".join(all_docs)

# Assuming the script is placed inside the Docs folder
docs_directory = os.path.dirname(os.path.abspath(__file__))
core_directory = os.path.join(docs_directory, '..', 'core')
documentation_content = process_directory(core_directory)

documentation_file_path = os.path.join(docs_directory, 'documentation.md')
with open(documentation_file_path, 'w') as md_file:
    md_file.write(documentation_content)

print(f"Combined Markdown documentation generated at {documentation_file_path}")