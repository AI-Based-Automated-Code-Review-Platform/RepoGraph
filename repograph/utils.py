import os
from tree_sitter import Language, Parser

# Load the tree-sitter Python, JavaScript, and Java parsers
PY_LANGUAGE = Language("build/my-languages.so", "python")
JS_LANGUAGE = Language("build/my-languages.so", "javascript")
JAVA_LANGUAGE = Language("build/my-languages.so", "java")

parser = Parser()

LANGUAGE_MAP = {
    ".py": PY_LANGUAGE,
    ".js": JS_LANGUAGE,
    ".java": JAVA_LANGUAGE
}

def set_language_for_file(file_extension):
    """Set the parser language based on file extension."""
    if file_extension in LANGUAGE_MAP:
        parser.set_language(LANGUAGE_MAP[file_extension])
    else:
        raise ValueError(f"Unsupported file extension: {file_extension}")

def create_structure(directory_path):
    """Create the structure of the repository directory by parsing Python, JavaScript, and Java files.
    :param directory_path: Path to the repository directory.
    :return: A dictionary representing the structure.
    """
    structure = {}

    for root, dirs, files in os.walk(directory_path):
        relative_root = os.path.relpath(root, directory_path)
        curr_struct = structure

        # Handle the root directory case
        if relative_root == ".":
            for file_name in files:
                file_extension = os.path.splitext(file_name)[1]
                if file_extension in LANGUAGE_MAP:
                    file_path = os.path.join(root, file_name)
                    file_info = parse_file(file_path, file_extension)
                    structure[file_name] = file_info
            continue

        for part in relative_root.split(os.sep):
            if part not in curr_struct:
                curr_struct[part] = {}
            curr_struct = curr_struct[part]

        for file_name in files:
            file_extension = os.path.splitext(file_name)[1]
            if file_extension in LANGUAGE_MAP:
                file_path = os.path.join(root, file_name)
                file_info = parse_file(file_path, file_extension)
                curr_struct[file_name] = file_info
            else:
                curr_struct[file_name] = {}

        # Handle empty directories
        for dir_name in dirs:
            if dir_name not in curr_struct:
                curr_struct[dir_name] = {}

    return structure

def parse_file(file_path, file_extension):
    """Parse a file to extract class and function definitions with their line numbers."""
    try:
        with open(file_path, "r") as file:
            file_content = file.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return {}

    set_language_for_file(file_extension)
    tree = parser.parse(bytes(file_content, "utf-8"))
    root_node = tree.root_node

    if file_extension == ".py":
        return parse_python_like_file(root_node)
    elif file_extension == ".js":
        return parse_javascript_like_file(root_node)
    elif file_extension == ".java":
        return parse_java_like_file(root_node)

    return {}

def parse_python_like_file(root_node):
    """Parse Python-like files for classes and functions."""
    return extract_definitions(root_node, ["class_definition", "function_definition"])

def parse_javascript_like_file(root_node):
    """Parse JavaScript-like files for classes and functions."""
    return extract_definitions(root_node, ["class", "function"])

def parse_java_like_file(root_node):
    """Parse Java-like files for classes and methods."""
    return extract_definitions(root_node, ["class_declaration", "method_declaration"])

def extract_definitions(node, definition_types):
    """Extract class and function/method definitions from the syntax tree."""
    classes = []
    functions = []

    for child in node.children:
        if child.type in definition_types:
            name_node = next((c for c in child.children if c.type == "identifier"), None)
            name = name_node.text.decode("utf-8") if name_node else "unknown"
            start_line, end_line = child.start_point[0] + 1, child.end_point[0] + 1

            if child.type in ["class", "class_definition", "class_declaration"]:
                classes.append({
                    "name": name,
                    "start_line": start_line,
                    "end_line": end_line,
                    "methods": extract_definitions(child, ["method_definition", "method_declaration"]),
                })
            elif child.type in ["function", "function_definition", "method_declaration"]:
                functions.append({
                    "name": name,
                    "start_line": start_line,
                    "end_line": end_line,
                })

        extracted = extract_definitions(child, definition_types)
        classes.extend(extracted["classes"])
        functions.extend(extracted["functions"])

    return {
        "classes": classes,
        "functions": functions
    }
