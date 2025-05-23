import os
import random
import sys
import re
import warnings
from collections import defaultdict, namedtuple
from pathlib import Path
import networkx as nx
from tree_sitter import Language, Parser
from repograph.utils import create_structure
import pickle
import json

# Load the tree-sitter Python, JavaScript, Java, and C parsers
PY_LANGUAGE = Language('build/my-languages.so', 'python')
JS_LANGUAGE = Language('build/my-languages.so', 'javascript')
JAVA_LANGUAGE = Language('build/my-languages.so', 'java')
C_LANGUAGE = Language("build/my-languages.so", "c")

parser = Parser()

LANGUAGE_MAP = {
    ".py": PY_LANGUAGE,
    ".js": JS_LANGUAGE,
    ".java": JAVA_LANGUAGE,
    ".c": C_LANGUAGE,
}

def set_language_for_file(file_extension):
    """Set the parser language based on file extension."""
    if file_extension in LANGUAGE_MAP:
        parser.set_language(LANGUAGE_MAP[file_extension])
    else:
        raise ValueError(f"Unsupported file extension: {file_extension}")

# Named tuple for intermediate tag storage
Tag = namedtuple("Tag", "rel_fname fname line name kind category info".split())

class CodeGraph:
    """
    This class constructs a graph from source code, extracting classes, functions,
    imports, variables, etc. Then we store them as nodes/edges in an NX graph.
    """

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
        # Create a hierarchical structure of the codebase (optional usage)
        self.structure = create_structure(self.root)

        # Precompute all source files in the repo for local-import checks
        self.all_source_files = self.find_src_files(self.root)

    def parse_tree(self, code, file_extension):
        """Parse the code (string) using tree-sitter."""
        set_language_for_file(file_extension)
        tree = parser.parse(bytes(code, "utf-8"))
        return tree

    def parse_code_string(self, code_string, rel_fname):
        """
        Parse the given code string in-memory using tree-sitter
        and return the extracted tags (like classes, functions, imports, etc.).
        """
        file_extension = os.path.splitext(rel_fname)[1]
        tree = self.parse_tree(code_string, file_extension)
        def_tags = self.extract_tags(tree.root_node, rel_fname)
        import_tags = self.extract_imports(tree.root_node, file_extension, rel_fname)
        return def_tags + import_tags

    def extract_function_calls(self, node, rel_fname, current_function):
        """
        Recursively extract function call tags within a function/method node.
        We store 'fname=current_function' so 'fname' reflects the caller function name.
        """
        calls = []
        if node.type in ("call", "call_expression", "method_invocation"):
            func_name_node = next((c for c in node.children if c.type == "identifier"), None)
            if func_name_node:
                callee_name = func_name_node.text.decode("utf-8")
                calls.append(Tag(
                    rel_fname=rel_fname,
                    fname=current_function,  # The caller’s function name
                    line=[node.start_point[0] + 1, node.end_point[0] + 1],
                    name=callee_name,        # The callee name
                    kind="call",
                    category="function_call",
                    info={}
                ))

        for child in node.children:
            calls.extend(self.extract_function_calls(child, rel_fname, current_function))
        return calls


    def extract_variable_attributes(self, node, rel_fname, current_function, inside_assignment=False):
        """
        Recursively walk the AST to find variable/attribute references inside a function.
        We'll store 'fname=current_function' so 'fname' reflects the enclosing function name.
        """
        dependencies = []

        if node.type in ("assignment", "augmented_assignment_expression"):
            # Typically child[0] => left side (writes), child[-1] => right side (reads)
            if len(node.children) >= 2:
                lhs = node.children[0]
                rhs = node.children[-1]
                dependencies.extend(
                    self.extract_variable_attributes(lhs, rel_fname, current_function, inside_assignment=True)
                )
                dependencies.extend(
                    self.extract_variable_attributes(rhs, rel_fname, current_function, inside_assignment=False)
                )

        elif node.type == "identifier":
            var_name = node.text.decode("utf-8")
            kind = "write" if inside_assignment else "read"
            dependencies.append(
                Tag(
                    rel_fname=rel_fname,
                    fname=current_function,  # The enclosing function’s name
                    line=[node.start_point[0] + 1, node.end_point[0] + 1],
                    name=var_name,
                    kind=kind,               # "read" or "write"
                    category="var_dependency",
                    info={}
                )
            )

        elif node.type == "attribute":
            # e.g. "self.x" or "obj.prop" in Python
            var_name = node.text.decode("utf-8")
            kind = "write" if inside_assignment else "read"
            dependencies.append(
                Tag(
                    rel_fname=rel_fname,
                    fname=current_function,  # The enclosing function’s name
                    line=[node.start_point[0] + 1, node.end_point[0] + 1],
                    name=var_name,
                    kind=kind,
                    category="var_dependency",
                    info={"is_attribute": True}
                )
            )

        # Recurse further if we're not specifically dividing assignment left/right
        if node.type not in ("assignment", "augmented_assignment_expression"):
            for child in node.children:
                dependencies.extend(
                    self.extract_variable_attributes(child, rel_fname, current_function, inside_assignment)
                )

        return dependencies

    def extract_inheritance_tags(self, class_node, file_extension, rel_fname, class_name):
        """
        Detect class inheritance. Returns a list of Tag objects representing 'inherits_from'.
        """
        inheritance_tags = []

        if file_extension == ".py":
            arg_list_node = next((c for c in class_node.children if c.type == "argument_list"), None)
            if arg_list_node:
                parent_ids = [c.text.decode("utf-8") for c in arg_list_node.children if c.type == "identifier"]
                for parent_cls in parent_ids:
                    inheritance_tags.append(
                        Tag(
                            rel_fname=rel_fname,
                            fname=None,
                            line=[class_node.start_point[0] + 1, class_node.end_point[0] + 1],
                            name=f"{class_name}->{parent_cls}",
                            kind="inherits",
                            category="class_inheritance",
                            info={"child_class": class_name, "parent_class": parent_cls}
                        )
                    )


        elif file_extension == ".java":
            superclass_node = next((c for c in class_node.children if c.type == "superclass"), None)
            if superclass_node:
                type_identifier = next((c for c in superclass_node.children if c.type == "type_identifier"), None)
                if type_identifier:
                    parent_cls = type_identifier.text.decode("utf-8")
                    inheritance_tags.append(
                        Tag(
                            rel_fname=rel_fname,
                            fname=None,
                            line=[class_node.start_point[0] + 1, class_node.end_point[0] + 1],
                            name=f"{class_name}->{parent_cls}",
                            kind="inherits",
                            category="class_inheritance",
                            info={"child_class": class_name, "parent_class": parent_cls}
                        )
                    )

        elif file_extension == ".js":
            extends_clause_node = next((c for c in class_node.children if c.type == "extends_clause"), None)
            if extends_clause_node:
                parent_identifier = next((c for c in extends_clause_node.children if c.type == "identifier"), None)
                if parent_identifier:
                    parent_cls = parent_identifier.text.decode("utf-8")
                    inheritance_tags.append(
                        Tag(
                            rel_fname=rel_fname,
                            fname=None,
                            line=[class_node.start_point[0] + 1, class_node.end_point[0] + 1],
                            name=f"{class_name}->{parent_cls}",
                            kind="inherits",
                            category="class_inheritance",
                            info={"child_class": class_name, "parent_class": parent_cls}
                        )
                    )
        # C has no built-in class inheritance
        return inheritance_tags

    def extract_tags(self, node, rel_fname):
        """
        Recursively extract tags (classes, functions, calls, var_deps, etc.) from a tree-sitter node.
        """
        tags = []
        for child in node.children:
            # Identify classes or functions
            if child.type in [
                "class",
                "class_definition",
                "function",
                "function_definition",
                "function_declaration",
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

                # Tag for the class or function definition
                tags.append(Tag(
                    rel_fname=rel_fname,
                    fname=None,
                    line=[start_line, end_line],
                    name=name,
                    kind="def",
                    category=kind,
                    info=""
                ))

                # If it's a class, handle inheritance + gather methods
                if kind == "class":
                    file_extension = os.path.splitext(rel_fname)[1]
                    inheritance_tags = self.extract_inheritance_tags(child, file_extension, rel_fname, name)
                    tags.extend(inheritance_tags)


                    # Recursively gather method definitions inside the class
                    methods = self.extract_tags(child, rel_fname)
                    # Mark them as "method" (but also keep them as "function" category)
                    for method in methods:
                        if method.category == "function":
                            method_info = {"name": method.name}
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
                    # If it's a function, extract function calls & var/attr dependencies
                    calls = self.extract_function_calls(child, rel_fname, current_function=name)
                    tags.extend(calls)

                    var_deps = self.extract_variable_attributes(child, rel_fname, current_function=name)
                    tags.extend(var_deps)

            # Recurse deeper
            tags.extend(self.extract_tags(child, rel_fname))

        return tags

    def extract_imports(self, node, file_extension, rel_fname):
        """
        Recursively extract import statements (#include in C or import in others).
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
            elif file_extension == ".c":
                if child.type == "preproc_include":
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

            # Recurse deeper
            imports.extend(self.extract_imports(child, file_extension, rel_fname))

        return imports

    def get_tags(self, fname, rel_fname):
        """Get tags for a given file by reading it from disk and parsing."""
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
        """Build a code graph from extracted tags for the given list of file paths."""
        if self.max_map_tokens <= 0 or not other_files:
            return None, None
        if not mentioned_fnames:
            mentioned_fnames = set()

        tags = []
        for file_path in other_files:
            rel_fname = self.get_rel_fname(file_path)
            tags.extend(self.get_tags(file_path, rel_fname))

        code_graph = self.tag_to_graph(tags)
        return tags, code_graph

    def is_local_import(self, imported_module: str) -> bool:
        """
        Check if this 'imported_module' is local vs. built-in/external.
        """
        # Case: C #include "something.h"
        if imported_module.startswith("#include") and '"' in imported_module:
            match = re.search(r'#include\s+"([^"]+)"', imported_module)
            if match:
                possible_local_header = match.group(1).split(".")[0]
                for fpath in self.all_source_files:
                    base = os.path.splitext(os.path.basename(fpath))[0]
                    if base == possible_local_header:
                        return True
            return False

        # Case: Python import or from import
        match = re.match(r'(?:from\s+([\w\.]+)\s+import)|(?:import\s+([\w\.]+))', imported_module)
        if not match:
            return False

        mod_name = match.group(1) or match.group(2)
        mod_name = mod_name.split('.')[0]

        for fpath in self.all_source_files:
            base = os.path.splitext(os.path.basename(fpath))[0]
            if base == mod_name:
                return True
        return False

    def tag_to_graph(self, tags):
        """
        Convert extracted tags into a NetworkX graph.

        We do NOT directly write the final JSON here.
        Instead, we store enough info in the graph so we can later
        produce the final metadata structure.
        """
        G = nx.MultiDiGraph()

        # 1) Create a node for each file we see in tags
        all_files = set(t.rel_fname for t in tags)
        for f in all_files:
            abs_path = os.path.join(self.root, f)
            file_name = os.path.basename(abs_path)
            try:
                size = os.path.getsize(abs_path)
                created_at = os.path.getctime(abs_path)
                updated_at = os.path.getmtime(abs_path)
                with open(abs_path, "r", encoding="utf-8") as temp_f:
                    total_lines = sum(1 for _ in temp_f)
            except:
                size = 0
                created_at = 0
                updated_at = 0
                total_lines = 0


            # Add as a "file" node
            node_data = {
                "relative_path": f,
                "file_name": file_name,
                "name": file_name,
                "type": "file",
                "line_range": [1, total_lines if total_lines else 1],
                "metadata": {
                    "language": os.path.splitext(file_name)[1].lstrip('.'),
                    "size": size,
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "dependencies": [],
                    "total_lines": total_lines
                },
            }
            G.add_node(f, **node_data)

        # 2) Create nodes for classes, functions, variables, etc.
        for tag in tags:
            # Skip external imports from being nodes
            if tag.category == 'import' and not self.is_local_import(tag.name):
                continue

            node_key = self._get_node_key(tag)
            # Some ephemeral tags (inherits, call, etc.) might only be edges
            if tag.kind in ["inherits", "call"]:
                continue

            if not G.has_node(node_key):
                # Determine node "type"
                if tag.kind in ["def", "method"] and tag.category == "class":
                    node_type = "class"
                elif tag.kind in ["def", "method"] and tag.category == "function":
                    node_type = "function"
                elif tag.kind == "import":
                    # We'll only add file->file edges for imports
                    continue
                elif tag.kind in ["write", "read"]:
                    node_type = "variable"
                else:
                    node_type = "unknown"

                relative_path = tag.rel_fname
                file_name = os.path.basename(tag.rel_fname)
                start_line, end_line = tag.line if tag.line else [1, 1]

                node_data = {
                    "relative_path": relative_path,
                    "file_name": file_name,
                    "name": tag.name,
                    "type": node_type,
                    "line_range": [start_line, end_line],
                    "metadata": {}
                }

                if node_type == "class":
                    node_data["metadata"] = {
                        "parent_classes": [],
                        "methods": [],
                        "variables": [],
                    }
                elif node_type == "function":
                    node_data["metadata"] = {
                        "parameters": [],
                        "parent_class": None,
                        "calls": [],
                        "reads": [],
                        "writes": [],
                    }
                elif node_type == "variable":
                    is_attr = (isinstance(tag.info, dict) and tag.info.get("is_attribute")) or False
                    node_data["metadata"] = {
                        "is_attribute": is_attr,
                        "accessed_by": [],
                        "modified_by": [],
                    }

                G.add_node(node_key, **node_data)

        # 3) file -> class/function edges (containment)
        for tag in tags:
            if tag.kind == 'def' and tag.category in ['class', 'function']:
                file_node = tag.rel_fname
                node_key = self._get_node_key(tag)
                if G.has_node(file_node) and G.has_node(node_key):
                    G.add_edge(file_node, node_key, label='contains')


        # 4) class -> method edges. Also link method’s parent_class
        for tag in tags:
            if tag.category == 'class':
                class_key = self._get_node_key(tag)
                # Check method tags that lie within the class range
                for possible_method in tags:
                    if possible_method.kind == 'method' and possible_method.rel_fname == tag.rel_fname:
                        # If method lines are inside the class lines
                        if (possible_method.line[0] >= tag.line[0]) and (possible_method.line[1] <= tag.line[1]):
                            method_key = self._get_node_key(possible_method)
                            if G.has_node(class_key) and G.has_node(method_key):
                                G.add_edge(class_key, method_key, label='contains')
                                # Also record parent_class in method's metadata
                                G.nodes[method_key]["metadata"]["parent_class"] = tag.name

        # 5) file->file edges from imports
        for tag in tags:
            if tag.category == 'import':
                importing_file_node = tag.rel_fname
                imported_module_string = tag.name

                # Skip external
                if not self.is_local_import(imported_module_string):
                    continue

                # For C #include "...":
                if imported_module_string.startswith("#include"):
                    match = re.search(r'#include\s+"([^"]+)"', imported_module_string)
                    if match:
                        local_header_basename = os.path.splitext(match.group(1))[0]
                        for f in G.nodes:
                            if G.nodes[f].get('type') == 'file':
                                base = os.path.splitext(os.path.basename(f))[0]
                                if base == local_header_basename:
                                    G.add_edge(importing_file_node, f, label='imports')
                                    G.nodes[importing_file_node]["metadata"]["dependencies"].append(f)
                else:
                    # Python/JS/Java
                    base_match = re.match(
                        r'(?:from\s+([\w\.]+)\s+import)|(?:import\s+([\w\.]+))',
                        imported_module_string
                    )
                    if base_match:
                        mod_name = base_match.group(1) or base_match.group(2)
                        mod_name = mod_name.split('.')[0]
                        for f in G.nodes:
                            if G.nodes[f].get('type') == 'file':
                                base = os.path.splitext(os.path.basename(f))[0]
                                if base == mod_name:
                                    G.add_edge(importing_file_node, f, label='imports')
                                    G.nodes[importing_file_node]["metadata"]["dependencies"].append(f)

        # 6) function->function edges from calls
        for tag in tags:
            if tag.kind == 'call' and tag.category == 'function_call':
                caller = tag.fname
                callee = tag.name
                if not caller or not callee:
                    continue

                caller_node_key = self._get_func_node_key(tag.rel_fname, caller)
                callee_node_key = self._get_func_node_key(tag.rel_fname, callee)


                # Ensure we have a node for caller
                if not G.has_node(caller_node_key):
                    G.add_node(
                        caller_node_key,
                        relative_path=tag.rel_fname,
                        file_name=os.path.basename(tag.rel_fname),
                        name=caller,
                        type="function",
                        line_range=[tag.line[0], tag.line[1]],
                        metadata={
                            "parameters": [],
                            "parent_class": None,
                            "calls": [],
                            "reads": [],
                            "writes": [],
                        }
                    )
                # Ensure we have a node for callee
                if not G.has_node(callee_node_key):
                    G.add_node(
                        callee_node_key,
                        relative_path=tag.rel_fname,
                        file_name=os.path.basename(tag.rel_fname),
                        name=callee,
                        type="function",
                        line_range=[tag.line[0], tag.line[1]],
                        metadata={
                            "parameters": [],
                            "parent_class": None,
                            "calls": [],
                            "reads": [],
                            "writes": [],
                        }
                    )

                # Add edge
                G.add_edge(caller_node_key, callee_node_key, label='calls')
                # Record in caller’s metadata
                G.nodes[caller_node_key]["metadata"]["calls"].append(callee_node_key)

        # 7) class inheritance edges
        for tag in tags:
            if tag.kind == 'inherits' and tag.category == 'class_inheritance':
                child_cls = tag.info.get("child_class")
                parent_cls = tag.info.get("parent_class")
                if not child_cls or not parent_cls:
                    continue

                child_key = self._get_class_node_key(tag.rel_fname, child_cls)
                parent_key = self._get_class_node_key(tag.rel_fname, parent_cls)

                if not G.has_node(child_key):
                    G.add_node(
                        child_key,
                        relative_path=tag.rel_fname,
                        file_name=os.path.basename(tag.rel_fname),
                        name=child_cls,
                        type="class",
                        line_range=[tag.line[0], tag.line[1]],
                        metadata={
                            "parent_classes": [],
                            "methods": [],
                            "variables": [],
                        }
                    )
                if not G.has_node(parent_key):
                    G.add_node(
                        parent_key,
                        relative_path=tag.rel_fname,
                        file_name=os.path.basename(tag.rel_fname),
                        name=parent_cls,
                        type="class",
                        line_range=[tag.line[0], tag.line[1]],
                        metadata={
                            "parent_classes": [],
                            "methods": [],
                            "variables": [],
                        }
                    )

                G.add_edge(child_key, parent_key, label='inherits_from')
                G.nodes[child_key]["metadata"]["parent_classes"].append(parent_key)

        # 8) var dependencies: function->variable
        for tag in tags:
            if tag.category == 'var_dependency':
                func_name = tag.fname
                var_name = tag.name
                access_type = tag.kind  # read/write
                if not func_name or not var_name:
                    continue

                func_key = self._get_func_node_key(tag.rel_fname, func_name)
                var_key = self._get_var_node_key(tag.rel_fname, var_name)


                if not G.has_node(func_key):
                    G.add_node(
                        func_key,
                        relative_path=tag.rel_fname,
                        file_name=os.path.basename(tag.rel_fname),
                        name=func_name,
                        type="function",
                        line_range=[tag.line[0], tag.line[1]],
                        metadata={
                            "parameters": [],
                            "parent_class": None,
                            "calls": [],
                            "reads": [],
                            "writes": [],
                        }
                    )
                if not G.has_node(var_key):
                    is_attr = (isinstance(tag.info, dict) and tag.info.get("is_attribute")) or False
                    G.add_node(
                        var_key,
                        relative_path=tag.rel_fname,
                        file_name=os.path.basename(tag.rel_fname),
                        name=var_name,
                        type="variable",
                        line_range=[tag.line[0], tag.line[1]],
                        metadata={
                            "is_attribute": is_attr,
                            "accessed_by": [],
                            "modified_by": [],
                        }
                    )

                label = 'reads' if access_type == 'read' else 'writes'
                G.add_edge(func_key, var_key, label=label)

                # Update function's reads/writes
                if label == 'reads':
                    if var_key not in G.nodes[func_key]["metadata"]["reads"]:
                        G.nodes[func_key]["metadata"]["reads"].append(var_key)
                else:
                    if var_key not in G.nodes[func_key]["metadata"]["writes"]:
                        G.nodes[func_key]["metadata"]["writes"].append(var_key)

                # Update variable's usage
                if label == 'reads':
                    G.nodes[var_key]["metadata"]["accessed_by"].append(func_key)
                else:
                    G.nodes[var_key]["metadata"]["modified_by"].append(func_key)

        return G

    def _get_node_key(self, tag):
        """Return a unique key for the node based on category/kind/name."""
        if tag.kind == "def" and tag.category == "class":
            return f"{tag.rel_fname}::class::{tag.name}"
        if tag.kind in ["def", "method"] and tag.category == "function":
            return self._get_func_node_key(tag.rel_fname, tag.name)
        if tag.kind in ["read", "write"]:
            return self._get_var_node_key(tag.rel_fname, tag.name)
        return f"{tag.rel_fname}::{tag.category}::{tag.name}"

    def _get_func_node_key(self, rel_fname, func_name):
        return f"{rel_fname}::function::{func_name}"

    def _get_var_node_key(self, rel_fname, var_name):
        return f"{rel_fname}::var::{var_name}"

    def _get_class_node_key(self, rel_fname, cls_name):
        return f"{rel_fname}::class::{cls_name}"

    def _parse_import_path(self, import_string):
        if import_string.startswith("#include"):
            match = re.search(r'#include\s+"([^"]+)"', import_string)
            if match:
                return match.group(1)
            return import_string
        match = re.match(r'(?:from\s+([\w\.]+)\s+import)|(?:import\s+([\w\.]+))', import_string)
        if match:
            return match.group(1) or match.group(2)
        return import_string

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
        """Given a list of paths or directories, return all valid source file paths."""
        chat_fnames = []
        for dir in dirs:
            p = Path(dir)
            if p.is_dir():
                chat_fnames += self.find_src_files(dir)
            elif os.path.splitext(dir)[1] in LANGUAGE_MAP.keys():
                chat_fnames.append(dir)
        return chat_fnames

if __name__ == "__main__":
    # If run directly, we parse a local directory path from sys.argv
    if len(sys.argv) < 2:
        print("Usage: python construct_graph.py <directory_path>")
        sys.exit(1)

    dir_name = sys.argv[1]
    code_graph = CodeGraph(root=dir_name)
    all_src_files = code_graph.find_files([dir_name])
    tags, G = code_graph.get_code_graph(all_src_files)

    if G is None:
        print("No graph constructed (possibly no valid source files).")
        sys.exit(0)

    print("---------------------------------")
    print(f"Successfully constructed the code graph for repo directory {dir_name}")
    print(f"   Number of nodes: {len(G.nodes)}")
    print(f"   Number of edges: {len(G.edges)}")
    print("---------------------------------")

    # **Step 1: Cache File Contents**
    # To improve efficiency, cache the lines of each file.
    file_contents_cache = {}
    for file_path in all_src_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                file_contents_cache[file_path] = lines
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            file_contents_cache[file_path] = []

    # Now produce the final metadata JSON
    final_nodes = []
    for node_id in G.nodes:
        data = G.nodes[node_id]
        node_type = data["type"]

        # Common fields
        out = {
            "Node_id": node_id,
            "Node_type": node_type,
            "name": data["name"],
            "filepath": data["relative_path"],
            "start_line": data["line_range"][0],
            "end_line": data["line_range"][1],
            "Info": {
                "Number_of_line": data["metadata"].get("total_lines", 0),
                "Language": data["metadata"].get("language", ""),
                "relatedfiles": []
            }
        }

        # **Step 2: Extract Related Files**
        if node_type == "file":
            dep_ids = data["metadata"].get("dependencies", [])  # node IDs
            related_files = []
            for dep_id in dep_ids:
                if dep_id in G.nodes:
                    related_files.append(G.nodes[dep_id]["name"])
            out["Info"]["relatedfiles"] = related_files

        elif node_type == "class":
            meta = data["metadata"]
            parent_names = []
            for parent_id in meta.get("parent_classes", []):
                if parent_id in G.nodes:
                    parent_names.append(G.nodes[parent_id]["name"])

            # Gather methods by checking edges or metadata
            method_names = []
            for succ in G.successors(node_id):
                if G.nodes[succ]["type"] == "function":
                    # It's a method if the parent_class is this class name
                    if G.nodes[succ]["metadata"].get("parent_class") == data["name"]:
                        method_names.append(G.nodes[succ]["name"])

            var_names = list(set(meta.get("variables", [])))  # Adapt if you store class-level vars

            out["Info"].update({
                "Inheritance": parent_names,
                "methods": method_names,
                "variables": var_names
            })

        elif node_type == "function":
            meta = data["metadata"]
            call_names = []
            for callee_id in meta.get("calls", []):
                if callee_id in G.nodes:
                    call_names.append(G.nodes[callee_id]["name"])


    def find_files(self, dirs):
        """Given a list of paths or directories, return all valid source file paths."""
        chat_fnames = []
        for dir in dirs:
            p = Path(dir)
            if p.is_dir():
                chat_fnames += self.find_src_files(dir)
            elif os.path.splitext(dir)[1] in LANGUAGE_MAP.keys():
                chat_fnames.append(dir)
        return chat_fnames

if __name__ == "__main__":
    # If run directly, we parse a local directory path from sys.argv
    if len(sys.argv) < 2:
        print("Usage: python construct_graph.py <directory_path>")
        sys.exit(1)

    dir_name = sys.argv[1]
    code_graph = CodeGraph(root=dir_name)
    all_src_files = code_graph.find_files([dir_name])
    tags, G = code_graph.get_code_graph(all_src_files)

    if G is None:
        print("No graph constructed (possibly no valid source files).")
        sys.exit(0)

    print("---------------------------------")
    print(f"Successfully constructed the code graph for repo directory {dir_name}")
    print(f"   Number of nodes: {len(G.nodes)}")
    print(f"   Number of edges: {len(G.edges)}")
    print("---------------------------------")

    # **Step 1: Cache File Contents**
    # To improve efficiency, cache the lines of each file.
    file_contents_cache = {}
    for file_path in all_src_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                file_contents_cache[file_path] = lines
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            file_contents_cache[file_path] = []

    # Now produce the final metadata JSON
    final_nodes = []
    for node_id in G.nodes:
        data = G.nodes[node_id]
        node_type = data["type"]

        # Common fields
        out = {
            "Node_id": node_id,
            "Node_type": node_type,
            "name": data["name"],
            "filepath": data["relative_path"],
            "start_line": data["line_range"][0],
            "end_line": data["line_range"][1],
            "Info": {
                "Number_of_line": data["metadata"].get("total_lines", 0),
                "Language": data["metadata"].get("language", ""),
                "relatedfiles": []
            }
        }

        # **Step 2: Extract Related Files**
        if node_type == "file":
            dep_ids = data["metadata"].get("dependencies", [])  # node IDs
            related_files = []
            for dep_id in dep_ids:
                if dep_id in G.nodes:
                    related_files.append(G.nodes[dep_id]["name"])
            out["Info"]["relatedfiles"] = related_files

        elif node_type == "class":
            meta = data["metadata"]
            parent_names = []
            for parent_id in meta.get("parent_classes", []):
                if parent_id in G.nodes:
                    parent_names.append(G.nodes[parent_id]["name"])

            # Gather methods by checking edges or metadata
            method_names = []
            for succ in G.successors(node_id):
                if G.nodes[succ]["type"] == "function":
                    # It's a method if the parent_class is this class name
                    if G.nodes[succ]["metadata"].get("parent_class") == data["name"]:
                        method_names.append(G.nodes[succ]["name"])

            var_names = list(set(meta.get("variables", [])))  # Adapt if you store class-level vars

            out["Info"].update({
                "Inheritance": parent_names,
                "methods": method_names,
                "variables": var_names
            })

        elif node_type == "function":
            meta = data["metadata"]
            call_names = []
            for callee_id in meta.get("calls", []):
                if callee_id in G.nodes:
                    call_names.append(G.nodes[callee_id]["name"])


            out["Info"].update({
                "Parameter": meta.get("parameters", []),
                "IsMethodof": meta.get("parent_class"),
                "calls": call_names
            })

        elif node_type == "variable":
            meta = data["metadata"]
            used_by = set(meta.get("accessed_by", []) + meta.get("modified_by", []))
            calls = []
            for used_id in used_by:
                if used_id in G.nodes:
                    used_node = G.nodes[used_id]
                    if used_node["type"] == "function":
                        func_name = used_node["name"]
                        parent_cls = used_node["metadata"].get("parent_class", None)
                        if parent_cls:
                            calls.append(parent_cls)
                        calls.append(func_name)
                    elif used_node["type"] == "class":
                        calls.append(used_node["name"])
                    else:
                        calls.append(used_node["name"])
            out["Info"].update({"calls": list(set(calls))})

        # **Step 3: Extract Code Snippet**
        # Only add code snippets for node types other than "file" and "class"
        if node_type not in ["file", "class"]:
            file_path = os.path.join(code_graph.root, data["relative_path"])
            lines = file_contents_cache.get(file_path, [])
            start = max(data["line_range"][0] - 1, 0)  # Convert to 0-based index
            end = data["line_range"][1]  # Exclusive in slicing
            # Ensure end does not exceed the number of lines
            end = min(end, len(lines))
            code_snippet = ''.join(lines[start:end]).strip()
            out["Info"]["code"] = code_snippet

        final_nodes.append(out)

    # Write out as one JSON array
    tags_json_path = os.path.join(os.getcwd(), "tags.json")
    with open(tags_json_path, "w", encoding="utf-8") as f:
        json.dump(final_nodes, f, indent=2)

    # Also cache the graph if needed
    graph_pkl_path = os.path.join(os.getcwd(), "graph.pkl")
    with open(graph_pkl_path, 'wb') as f:
        pickle.dump(G, f)

    print(f"Successfully wrote updated metadata to {tags_json_path}")
