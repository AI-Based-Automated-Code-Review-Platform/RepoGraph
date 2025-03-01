import os
import re


def build_dependency_map(G, file_data):
    """
    Build a mapping from dependency name (base name) → (is_local, node_id)
    using the file's dependencies (from metadata).
    """
    dependency_map = {}
    imported_files = file_data["metadata"].get("dependencies", [])
    for imported_fid in imported_files:
        dep_data = G.nodes[imported_fid]
        rel = dep_data.get("relative_path")
        if rel:
            # Local file: use file's basename without extension.
            base_name = os.path.splitext(os.path.basename(rel))[0]
            dependency_map[base_name] = (True, imported_fid)
        else:
            # External library: use the last chunk of the name.
            ext_name = dep_data["name"].split("::")[-1]
            dependency_map[ext_name] = (False, imported_fid)
    return dependency_map

def parse_import_bases(import_statements, dependency_map):
    """
    Parse each raw import statement (Python syntax) to build a dictionary of import_bases.
    The returned dictionary maps a base (e.g. "foo") to a list of imported symbols or aliases.
    """
    import_bases = {}
    for stmt in import_statements:
        imp = stmt["import_text"].strip()
        # Handle "from foo.bar import x, y as z"
        match_from = re.match(r'^from\s+([\w\.]+)\s+import\s+(.*)', imp)
        if match_from:
            full_mod = match_from.group(1)            # e.g. "foo.bar"
            imported_part = match_from.group(2)         # e.g. "x, y as z"
            base_name = full_mod.split('.')[0]
            # Ignore external if marked in dependency_map.
            # if base_name in dependency_map and dependency_map[base_name][0] is False:
            #     continue
            import_bases.setdefault(base_name, [])
            items = [p.strip() for p in imported_part.split(',')]
            for it in items:
                as_alias = re.match(r'^(\w+)\s+as\s+(\w+)$', it)
                if as_alias:
                    original = as_alias.group(1)
                    alias = as_alias.group(2)
                    import_bases[base_name].append(original)
                    import_bases[base_name].append(alias)
                else:
                    import_bases[base_name].append(it)
        # Handle "import foo.bar as baz" or "import foo.bar"
        else:
            match_imp = re.match(r'^import\s+([\w\.]+)(?:\s+as\s+(\w+))?', imp)
            if match_imp:
                mod_name = match_imp.group(1)
                alias = match_imp.group(2)
                base_name = mod_name.split('.')[0]
                # if base_name in dependency_map and dependency_map[base_name][0] is False:
                #     continue
                import_bases.setdefault(base_name, [])
                # For import statements we add the base_name and its alias if exists.
                if alias:
                    import_bases[base_name].append(alias)
                else:
                    # In simple import, we keep the base_name.
                    import_bases[base_name].append(base_name)
            else:
                # Fallback: keep the whole statement as a "base"
                import_bases.setdefault(imp, [])
    return import_bases

def find_candidate_nodes(G, imported_files, import_bases, target_name, file_rel_path):
    """
    Given import_bases and target_name, try to map target_name to an import base.
    If found, restrict the search to the corresponding dependency file; otherwise, use a fallback search.
    """
    matching_import = None
    for base in import_bases.keys():
        if target_name.startswith(base + ".") or target_name == base:
            matching_import = base
        for alias in import_bases[base]:
            if target_name.startswith(alias + "."):
                matching_import = base
                break
            if target_name == alias:
                matching_import = alias
                break

    candidate_nodes = []
    external_flag = False
    if matching_import:
        # Locate exactly which file node corresponds to that import, ignoring others
        for imported_fid in imported_files:
            imported_data = G.nodes[imported_fid]
            path = imported_data.get("relative_path")
            # If it's local:
            if path and matching_import in imported_data["name"]:
                # Search only this file for matching function/class/variable
                for node_id in G.nodes:
                    data = G.nodes[node_id]
                    # Check only that file’s nodes
                    if (
                        data["type"] in ("function","class","variable")
                        and data["relative_path"] == path
                        and (data["name"] == target_name or data["name"]==target_name.split(".")[-1])
                    ):
                        candidate_nodes.append(node_id)
                        external_flag = False
                break 
            else:
                # external => you might do an “internet search” placeholder
                external_flag = True
    else:
        # 3) No matched import base => split on '.' ignoring first part to handle something like "self.x.y"
        name_parts = target_name.split(".")
        if len(name_parts) > 1:
            # drop name_parts[0] from the search
            name_to_search = ".".join(name_parts[1:])
        else:
            name_to_search = target_name

        # We search the current file plus its imported files
        scope_paths = [G.nodes[file_rel_path].get("relative_path")]
        for imported_fid in imported_files:
            imported_data = G.nodes[imported_fid]
            if imported_data.get("relative_path"):
                scope_paths.append(imported_data["relative_path"])

        for node_id in G.nodes:
            data = G.nodes[node_id]
            if data["type"] in ("function","class","variable") and data.get("relative_path") in scope_paths:
                if data["name"] == name_to_search or (len(name_parts)>2 and data["name"].endswith(name_to_search.split(".")[-1])):
                    candidate_nodes.append(node_id)
    return candidate_nodes,external_flag
def build_candidate_info(G, candidate_nodes, root_path, file_rel_path, import_statements):
    """
    Build the result information for each candidate node.
    """
    results = []
    for cnode in candidate_nodes:
        ndata = G.nodes[cnode]
        info = {
            "filepath": ndata.get("relative_path"),
            "lines": ndata.get("line_range"),
            "node_id": cnode,
            "node_type": ndata.get("type"),
            "name": ndata.get("name")
        }
        # Only add file import statements if candidate is in the current file.
        if ndata.get("relative_path") == file_rel_path:
            info["imports_in_file"] = [stmt["import_text"] for stmt in import_statements]
        # Load code snippet from disk if available.
        file_path = ndata.get("relative_path")
        code_snippet = []
        if file_path:
            start, end = ndata.get("line_range", [None, None])
            if start is not None and end is not None:
                full_path = os.path.join(root_path, file_path)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                        snippet = lines[start-1:end]
                        code_snippet = snippet
                except Exception as e:
                    pass
        info["code"] = code_snippet

        if ndata["type"] == "function":
            info["parameters"] = ndata["metadata"].get("parameters", [])
            info["reads"] = list(ndata["metadata"].get("reads", []))
            info["writes"] = list(ndata["metadata"].get("writes", []))
            parent_class = ndata["metadata"].get("parent_class")
            if parent_class:
                info["class_parents"] = [parent_class]
                # Find class info.
                for node_id2, d2 in G.nodes(data=True):
                    if d2["type"] == "class" and d2["name"] == parent_class:
                        info["class_variables"] = d2["metadata"].get("variables", [])
                        info["class_methods"] = d2["metadata"].get("methods", [])
                        break
        elif ndata["type"] == "class":
            info["class_variables"] = ndata["metadata"].get("variables", [])
            info["class_methods"] = ndata["metadata"].get("methods", [])
        results.append(info)
    return results

def retrieve_node_context(G, root_path, node_identifier):
    """
    Given a descriptor like 'myfile.py::function::myfunc' or 'myfile.py::class::MyClass',
    locate the graph node(s), gather context, and return a summary.
    Summary includes:
      - file path, line range, extracted code
      - for functions: parameters, reads, writes, and parent class info if exists
      - for classes: variables and methods
      - external_flag if lookup is external
    """
    parts = node_identifier.split("::")
    if len(parts) < 3:
        return {"error": "Please provide something like 'file.py::function::my_func' or 'file.py::class::MyClass'."}

    file_name, node_type, target_name = parts[0], parts[1], "::".join(parts[2:])

    # 1) Find the file node.
    file_node_id = None
    for node_id in G.nodes:
        data = G.nodes[node_id]
        if data["type"] == "file" and data["relative_path"] == file_name:
            file_node_id = node_id
            break
    if not file_node_id:
        return {"error": f"File {file_name} not found in graph."}
    file_data = G.nodes[file_node_id]
    file_rel_path = file_data.get("relative_path")

    # (A) Get raw import statements.
    import_statements = file_data["metadata"].get("import_statements", [])

    # (B) Build dependency map from file's dependencies.
    dependency_map = build_dependency_map(G, file_data)

    # (C) Parse raw import statements into import_bases.
    import_bases = parse_import_bases(import_statements, dependency_map)

    # (D) Find candidate nodes based on target_name and imports.
    candidate_nodes, external_flag = find_candidate_nodes(
        G,
        file_data["metadata"].get("dependencies", []),
        import_bases,
        target_name,
        file_rel_path
    )

    # (E) Build the final candidate infos.
    results = build_candidate_info(G, candidate_nodes, root_path, file_rel_path, import_statements)

    return {
        "results": results,
        "external_flag": external_flag
    }

# def retrieve_node_context(G,root_path, node_identifier):
#     """
#     Given a descriptor like 'myfile.py::function::myfunc' or 'myfile.py::class::MyClass',
#     locate the graph node(s), gather context, and return a summary of:
#       - file path
#       - line range
#       - extracted code
#       - function parameters/reads/writes (if function)
#       - class variables/methods (if class)
#       - any external imports from the file
#     """

#     parts = node_identifier.split("::")
#     if len(parts) < 3:
#         return {"error": "Please provide something like 'file.py::function::my_func' or 'file.py::class::MyClass'."}

#     file_name, node_type, target_name = parts[0], parts[1], "::".join(parts[2:])

#     # 1) Find the file node
#     file_node_id = None
#     for node_id in G.nodes:
#         data = G.nodes[node_id]
#         if data["type"] == "file" and data["relative_path"] == file_name:
#             file_node_id = node_id
#             break

#     if not file_node_id:
#         return {"error": f"File {file_name} not found in graph."}

#     file_data = G.nodes[file_node_id]
#     file_rel_path = file_data.get("relative_path")

#     # ----------------------------------------------------------------
#     # (A) Collect the raw import statements & line numbers
#     # ----------------------------------------------------------------
#     import_statements = file_data["metadata"].get("import_statements", [])

#     # For local vs external checks, build a map from dependency name → (is_local, node_id).
#     # Here, “dependency name” would ideally match the library's base name:
#     # For example, if your parse found "moves/Move.py", we might store "Move" → (True, node_id).
#     # If external, store "requests" → (False, some_external_node).
#     dependency_map = {}
#     imported_files = file_data["metadata"].get("dependencies", [])
#     for imported_fid in imported_files:
#         dep_data = G.nodes[imported_fid]
#         rel = dep_data.get("relative_path")
#         if rel:
#             # Local file: let's take the file's basename without extension as a "library name"
#             base_name = os.path.splitext(os.path.basename(rel))[0]  # e.g. "Move.py" -> "Move"
#             dependency_map[base_name] = (True, imported_fid)
#         else:
#             # External library: e.g. "external::requests"
#             # Strip out everything but the last chunk
#             # you might refine this logic for your naming style
#             ext_name = dep_data["name"].split("::")[-1]
#             dependency_map[ext_name] = (False, imported_fid)

#     # ----------------------------------------------------------------
#     # (B) Parse each raw import statement to build import_bases
#     # ----------------------------------------------------------------
#     import_bases = {}
#     for stmt in import_statements:
#         imp = stmt["import_text"].strip()
#         # 1) "from foo.bar import x, y as z"
#         match_from = re.match(r'^from\s+([\w\.]+)\s+import\s+(.*)', imp)
#         if match_from:
#             full_mod = match_from.group(1)            # e.g. "foo.bar"
#             imported_part = match_from.group(2)       # e.g. "x, y as z"

#             # Add the base name for full_mod
#             # "foo.bar".split(".")[0] => "foo"
#             # but if your local file is "bar.py", your parse rules might differ
#             base_name = full_mod.split('.')[0]
#             if base_name in dependency_map and dependency_map[base_name][0]==False:
#                 continue
#             import_bases[base_name] = []
#             # Then parse the items
#             items = [p.strip() for p in imported_part.split(',')]
#             for it in items:
#                 # e.g. "x as xx", "y"
#                 as_alias = re.match(r'^(\w+)\s+as\s+(\w+)$', it)
#                 if as_alias:
#                     original = as_alias.group(1)
#                     alias = as_alias.group(2)
#                     import_bases[base_name].append(original)
#                     import_bases[base_name].append(alias)
#                 else:
#                     import_bases[base_name].append(it)

#         # 2) "import foo.bar as baz"
#         else:
#             match_imp = re.match(r'^import\s+([\w\.]+)(?:\s+as\s+(\w+))?', imp)
#             if match_imp:
#                 mod_name = match_imp.group(1)   # e.g. "foo.bar"
#                 alias = match_imp.group(2)
#                 # base of "foo.bar" -> "foo"
#                 base_name = mod_name.split('.')[0]
#                 if base_name in dependency_map and dependency_map[base_name][0]==False:
#                     continue
#                 import_bases[base_name] = []
#                 import_bases.append(base_name)
#                 if alias:
#                     import_bases[base_name].append(alias)
#             else:
#                 # If it doesn't match either pattern, it might be external or a different style.
#                 # We skip "split('::')" now, and rely on metadata if needed.
#                 # For instance, just assume the entire statement is the base:
#                 # or parse it differently if your code has specific external markers
#                 import_bases[imp] = []

#     # Now we have import_bases purely from Python syntax
#     # We can cross-check them with dependency_map to see if it's local or external if we want:
#     # Example:
#     # for b in import_bases:
#     #     is_local, node_id = dependency_map.get(b, (False, None))
#     #     if is_local:
#     #         ... do local logic ...
#     #     else:
#     #         ... external / unknown logic ...

#     # 3) Figure out if target_name starts with anything from import_bases
#     #    If so, we might map it to local or external
#     matching_import = None
#     for b in import_bases.keys():
#         if target_name.startswith(b+".") or target_name == b:
#             matching_import = b
#             break
#         for alias in import_bases[b]:
#             if target_name.startswith(alias+".") or target_name == alias:
#                 matching_import = b
#                 break

#     external_flag = False
#     candidate_nodes = []

#     if matching_import:
#         # Locate exactly which file node corresponds to that import, ignoring others
#         for imported_fid in imported_files:
#             imported_data = G.nodes[imported_fid]
#             path = imported_data.get("relative_path")
#             # If it's local:
#             if path and matching_import in imported_data["name"]:
#                 # Search only this file for matching function/class/variable
#                 for node_id in G.nodes:
#                     data = G.nodes[node_id]
#                     # Check only that file’s nodes
#                     if (
#                         data["type"] in ("function","class","variable")
#                         and data["relative_path"] == path
#                         and (data["name"] == target_name or data["name"]==target_name.split(".")[-1])
#                     ):
#                         candidate_nodes.append(node_id)
#                 break 
#             else:
#                 # external => you might do an “internet search” placeholder
#                 external_flag = True
#     else:
#         # 3) No matched import base => split on '.' ignoring first part to handle something like "self.x.y"
#         name_parts = target_name.split(".")
#         if len(name_parts) > 1:
#             # drop name_parts[0] from the search
#             name_to_search = ".".join(name_parts[1:])
#         else:
#             name_to_search = target_name

#         # We search the current file plus its imported files
#         scope_paths = [G.nodes[file_node_id].get("relative_path")]
#         for imported_fid in imported_files:
#             imported_data = G.nodes[imported_fid]
#             if imported_data.get("relative_path"):
#                 scope_paths.append(imported_data["relative_path"])

#         for node_id in G.nodes:
#             data = G.nodes[node_id]
#             if data["type"] in ("function","class","variable") and data.get("relative_path") in scope_paths:
#                 if data["name"] == name_to_search or (len(name_parts)>2 and data["name"].endswith(name_to_search.split(".")[-1])):
#                     candidate_nodes.append(node_id)

#     # Build the return data for each candidate node
#     results = []
#     for cnode in candidate_nodes:
#         ndata = G.nodes[cnode]
#         info = {
#             "filepath": ndata.get("relative_path"),
#             "lines": ndata.get("line_range"),
#             "node_id": cnode,
#             "node_type": ndata.get("type"),
#             "name": ndata.get("name"),
#             "external_flag": external_flag,
#         }
#         if ndata.get("relative_path") == file_rel_path:
#             info["imports_in_file"] = [imp["import_text"] for imp in import_statements]
#         # Attempt to load the code from disk if filepath is known
#         file_path = ndata.get("relative_path")
#         code_snippet = []
#         if file_path:
#             # We read the relevant lines from disk
#             start, end = ndata.get("line_range", [None, None])
#             if start is not None and end is not None:
#                 full_path = os.path.join(root_path, file_path)
#                 try:
#                     with open(full_path, "r", encoding="utf-8") as f:
#                         lines = f.readlines()
#                         snippet = lines[start-1:end]
#                         code_snippet = snippet
#                 except:
#                     pass
#         info["code"] = code_snippet

#         # If it's a function, gather parameters + read/write sets
#         if ndata["type"] == "function":
#             info["parameters"] = ndata["metadata"].get("parameters", [])
#             info["reads"] = list(ndata["metadata"].get("reads", []))
#             info["writes"] = list(ndata["metadata"].get("writes", []))
#             # If parent_class is not None, get that class’s variables/methods
#             parent_class = ndata["metadata"].get("parent_class")
#             if parent_class:
#                 info["class_parents"] = [parent_class]
#                 # find the class node
#                 for node_id2, d2 in G.nodes(data=True):
#                     if d2["type"] == "class" and d2["name"] == parent_class:
#                         # gather class variables/methods
#                         info["class_variables"] = d2["metadata"].get("variables", [])
#                         info["class_methods"] = d2["metadata"].get("methods", [])
#                         break
#         elif ndata["type"] == "class":
#             # gather methods & variables
#             info["class_variables"] = ndata["metadata"].get("variables", [])
#             info["class_methods"] = ndata["metadata"].get("methods", [])
#         results.append(info)

#     return results