import os
import colorsys
import random
import sys
import re
import warnings
from collections import defaultdict, namedtuple
from pathlib import Path
import networkx as nx
from tree_sitter import Language, Parser
from utils import create_structure
import pickle
import json

# Load the tree-sitter Python, JavaScript, and Java parsers
PY_LANGUAGE = Language('build/my-languages.so', 'python')
JS_LANGUAGE = Language('build/my-languages.so', 'javascript')
JAVA_LANGUAGE = Language('build/my-languages.so', 'java')

parser = Parser()

LANGUAGE_MAP = {
    ".py": PY_LANGUAGE,
    ".js": JS_LANGUAGE,
    ".java": JAVA_LANGUAGE,
}

def set_language_for_file(file_extension):
    """Set the parser language based on file extension."""
    if file_extension in LANGUAGE_MAP:
        parser.set_language(LANGUAGE_MAP[file_extension])
    else:
        raise ValueError(f"Unsupported file extension: {file_extension}")

Tag = namedtuple("Tag", "rel_fname fname line name kind category info".split())

class CodeGraph:

    def __init__(
        self,
        map_tokens=1024,
        root=None,
        main_model=None,
        io=None,
        repo_content_prefix=None,
        verbose=False,
        max_context_window=None,
    ):
        self.io = io
        self.verbose = verbose

        if not root:
            root = os.getcwd()
        self.root = root

        self.max_map_tokens = map_tokens
        self.max_context_window = max_context_window

        self.repo_content_prefix = repo_content_prefix
        self.structure = create_structure(self.root)

        # Precompute all source files in the repo for local-import checks
        self.all_source_files = self.find_src_files(self.root)

    def parse_tree(self, code, file_extension):
        """Parse the code using tree-sitter."""
        set_language_for_file(file_extension)
        tree = parser.parse(bytes(code, "utf-8"))
        return tree

    def extract_function_calls(self, node, rel_fname, current_function):
        """
        Recursively extract function call tags within a function/method node.
        We search for typical call-expression node types. The 'info' field will
        store the caller's function name.
        """
        calls = []
        if node.type in ("call", "call_expression", "method_invocation"):
            func_name_node = next((c for c in node.children if c.type == "identifier"), None)
            if func_name_node:
                callee_name = func_name_node.text.decode("utf-8")
                calls.append(Tag(
                    rel_fname=rel_fname,
                    fname=None,
                    line=[node.start_point[0] + 1, node.end_point[0] + 1],
                    name=callee_name,
                    kind="call",
                    category="function_call",
                    info={"caller": current_function}
                ))

        for child in node.children:
            calls.extend(self.extract_function_calls(child, rel_fname, current_function))
        return calls

    def extract_tags(self, node, rel_fname):
        """
        Recursively extract tags (classes/functions) from a tree-sitter node.
        This also extracts function-call tags from each function's body.
        """
        tags = []
        for child in node.children:
            # Detect classes and functions
            if child.type in [
                "class",
                "class_definition",
                "function",
                "function_definition",
                "class_declaration",
                "method_declaration",
            ]:
                name_node = next((c for c in child.children if c.type == "identifier"), None)
                name = name_node.text.decode("utf-8") if name_node else "unknown"
                start_line, end_line = child.start_point[0] + 1, child.end_point[0] + 1

                kind = (
                    "class"
                    if child.type in ["class", "class_definition", "class_declaration"]
                    else "function"
                )

                # Save the class/function definition tag
                tags.append(Tag(
                    rel_fname=rel_fname,
                    fname=None,
                    line=[start_line, end_line],
                    name=name,
                    kind="def",
                    category=kind,
                    info=""
                ))

                if kind == "class":
                    # If it's a class, we recursively gather method definitions as well
                    methods = self.extract_tags(child, rel_fname)
                    for method in methods:
                        if method.category == "function":
                            method_info = {
                                "name": method.name,
                                "start_line": method.line[0],
                                "end_line": method.line[1],
                            }
                            # Tag the method specifically as 'kind="method"' for clarity
                            tags.append(Tag(
                                rel_fname=rel_fname,
                                fname=None,
                                line=method.line,
                                name=method.name,
                                kind="method",
                                category="function",
                                info=method_info
                            ))
                    tags.extend(methods)
                else:
                    # If it's a function, extract calls inside
                    calls = self.extract_function_calls(child, rel_fname, current_function=name)
                    tags.extend(calls)

            # Recurse further down the AST
            tags.extend(self.extract_tags(child, rel_fname))
        return tags

    def extract_imports(self, node, file_extension, rel_fname):
        """
        Recursively walk the AST to extract import statements for Python, JS, or Java.
        """
        imports = []
        for child in node.children:
            if file_extension == ".py":
                if child.type in ["import_statement", "import_from_statement"]:
                    imported_mod = child.text.decode("utf-8").strip()
                    imports.append(
                        Tag(
                            rel_fname=rel_fname,
                            fname=None,
                            line=[child.start_point[0] + 1, child.end_point[0] + 1],
                            name=imported_mod,
                            kind="import",
                            category="import",
                            info={}
                        )
                    )
            elif file_extension == ".js":
                if child.type == "import_statement":
                    imported_mod = child.text.decode("utf-8").strip()
                    imports.append(
                        Tag(
                            rel_fname=rel_fname,
                            fname=None,
                            line=[child.start_point[0] + 1, child.end_point[0] + 1],
                            name=imported_mod,
                            kind="import",
                            category="import",
                            info={}
                        )
                    )
            elif file_extension == ".java":
                if child.type == "import_declaration":
                    imported_mod = child.text.decode("utf-8").strip()
                    imports.append(
                        Tag(
                            rel_fname=rel_fname,
                            fname=None,
                            line=[child.start_point[0] + 1, child.end_point[0] + 1],
                            name=imported_mod,
                            kind="import",
                            category="import",
                            info={}
                        )
                    )

            # Recurse to find nested imports
            imports.extend(self.extract_imports(child, file_extension, rel_fname))

        return imports

    def get_tags(self, fname, rel_fname):
        """Get tags for a given file using tree-sitter."""
        try:
            with open(fname, "r", encoding="utf-8") as f:
                code = f.read()
        except Exception as e:
            print(f"Error reading file {fname}: {e}")
            return []

        file_extension = os.path.splitext(fname)[1]
        tree = self.parse_tree(code, file_extension)

        def_tags = self.extract_tags(tree.root_node, rel_fname)
        import_tags = self.extract_imports(tree.root_node, file_extension, rel_fname)

        return def_tags + import_tags

    def get_code_graph(self, other_files, mentioned_fnames=None):
        """Build a code graph from extracted tags."""
        if self.max_map_tokens <= 0 or not other_files:
            return
        if not mentioned_fnames:
            mentioned_fnames = set()

        tags = []
        for file in other_files:
            rel_fname = self.get_rel_fname(file)
            tags.extend(self.get_tags(file, rel_fname))

        code_graph = self.tag_to_graph(tags)
        return tags, code_graph

    def is_local_import(self, imported_module: str) -> bool:
        """
        Check if the 'imported_module' refers to a file/module that exists
        in the repo (i.e., not built-in or external).
        """
        # Very rough pattern to parse the first word after 'import' or 'from'
        match = re.match(r'(?:from\s+([\w\.]+)\s+import)|(?:import\s+([\w\.]+))', imported_module)
        if not match:
            return False

        mod_name = match.group(1) or match.group(2)
        # For multi-dot imports, just check the first part (e.g. `mypackage.sub`)
        mod_name = mod_name.split('.')[0]

        # See if 'mod_name' matches any local file's basename
        for fpath in self.all_source_files:
            base = os.path.splitext(os.path.basename(fpath))[0]
            if base == mod_name:
                return True
        return False

    def tag_to_graph(self, tags):
        """Convert tags into a graph representation."""
        G = nx.MultiDiGraph()

        # 1) Ensure each file is a node in the graph
        #    We'll do this by collecting all unique rel_fname from the tags.
        all_files = set(t.rel_fname for t in tags)
        for f in all_files:
            # Each file node: category='file', kind='file'
            if not G.has_node(f):
                G.add_node(
                    f,
                    category='file',
                    info={},
                    fname=None,
                    line=None,
                    kind='file',
                    rel_fname=f
                )

        # 2) Add nodes for classes/functions/import targets, skipping non-local imports
        for tag in tags:
            # If this is an import tag and NOT local, skip creating that node
            if tag.category == 'import' and not self.is_local_import(tag.name):
                continue

            node_key = tag.name
            if not G.has_node(node_key):
                G.add_node(
                    node_key,
                    category=tag.category,
                    info=tag.info,
                    fname=tag.fname,
                    line=tag.line,
                    kind=tag.kind,
                    rel_fname=tag.rel_fname
                )

        # 3) Create edges for file -> [class/function] to represent containment
        for tag in tags:
            # We only care about definitions of classes/functions
            if tag.kind == 'def' and tag.category in ['class', 'function']:
                file_node = tag.rel_fname  # The file name
                # Edge: file_node -> tag.name with label 'contains'
                if G.has_node(file_node) and G.has_node(tag.name):
                    G.add_edge(file_node, tag.name, label='contains')

        # 4) Create edges for class -> method to represent containment
        for tag in tags:
            if tag.category == 'class':
                # Find methods that belong to this class
                class_methods = [
                    t.name
                    for t in tags
                    if t.kind == 'method'
                    and t.rel_fname == tag.rel_fname
                    # method lines fall within the class lines
                    and t.line[0] >= tag.line[0]
                    and t.line[1] <= tag.line[1]
                ]
                for method_name in class_methods:
                    if G.has_node(tag.name) and G.has_node(method_name):
                        # Changed label from 'has_method' to 'contains'
                        G.add_edge(tag.name, method_name, label='contains')

        # 5) import edges (file -> file) only if local
        for tag in tags:
            if tag.category == 'import':
                importing_file_node = tag.rel_fname
                imported_module_string = tag.name  # e.g. "import os"

                # Skip non-local imports
                if not self.is_local_import(imported_module_string):
                    continue

                # We already have a node for the importing file (from step 1).
                # But we need to find the local file node that matches the imported module name.
                # We do a small loop or check to see if there's a file node that corresponds.
                # For simplicity, use the same 'is_local_import' logic with the module’s base name:
                base_match = re.match(
                    r'(?:from\s+([\w\.]+)\s+import)|(?:import\s+([\w\.]+))',
                    imported_module_string
                )
                if base_match:
                    mod_name = base_match.group(1) or base_match.group(2)
                    mod_name = mod_name.split('.')[0]
                    # Attempt to find a file node with that base name
                    for f in G.nodes:
                        # Check only nodes that are category='file'
                        if G.nodes[f].get('category') == 'file':
                            # Compare the file's base name to mod_name
                            base = os.path.splitext(os.path.basename(f))[0]
                            if base == mod_name:
                                # Then create the edge: importing_file -> that file node
                                G.add_edge(importing_file_node, f, label='imports')

        # 6) function calls: caller -> callee (both are functions)  
        for tag in tags:
            if tag.kind == 'call' and tag.category == 'function_call':
                caller = tag.info.get("caller")
                callee = tag.name

                # Ensure we have nodes for caller/callee
                if caller and not G.has_node(caller):
                    G.add_node(caller, category='function', info={}, fname=None, line=None, kind='def')
                if callee and not G.has_node(callee):
                    G.add_node(callee, category='function', info={}, fname=None, line=None, kind='def')

                if caller and callee:
                    G.add_edge(caller, callee, label='calls')

        return G

    def get_rel_fname(self, fname):
        return os.path.relpath(fname, self.root)

    def find_src_files(self, directory):
        """Return all source files under the given directory."""
        if not os.path.isdir(directory):
            return [directory]

        src_files = []
        for root_dir, dirs, files in os.walk(directory):
            for file in files:
                if os.path.splitext(file)[1] in LANGUAGE_MAP.keys():
                    src_files.append(os.path.join(root_dir, file))
        return src_files

    def find_files(self, dirs):
        chat_fnames = []
        for dir in dirs:
            p = Path(dir)
            if p.is_dir():
                chat_fnames += self.find_src_files(dir)
            elif os.path.splitext(dir)[1] in LANGUAGE_MAP.keys():
                chat_fnames.append(dir)
        return chat_fnames

if __name__ == "__main__":
    dir_name = sys.argv[1]
    code_graph = CodeGraph(root=dir_name)
    chat_fnames_new = code_graph.find_files([dir_name])
    tags, G = code_graph.get_code_graph(chat_fnames_new)

    print("---------------------------------")
    print(f"Successfully constructed the code graph for repo directory {dir_name}")
    print(f"   Number of nodes: {len(G.nodes)}")
    print(f"   Number of edges: {len(G.edges)}")
    print("---------------------------------")

    with open(f'{os.getcwd()}/graph.pkl', 'wb') as f:
        pickle.dump(G, f)

    with open(f'{os.getcwd()}/tags.json', 'w') as f:
        for tag in tags:
            f.write(json.dumps(tag._asdict()) + '\n')

    print(f"Successfully cached code graph and node tags in directory '{os.getcwd()}'")
