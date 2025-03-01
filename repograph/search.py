import networkx as nx

def find_file_by_name(G, filename):
    """
    Return the node-id of a file node whose 'name' equals `filename`.
    """
    for node_id in G.nodes:
        data = G.nodes[node_id]
        if data["type"] == "file" and data["name"] == filename:
            return node_id
    return None

def find_class_by_name(G, classname, file_node_id=None):
    """
    Return a list of node-ids for class nodes named `classname`.
    Optionally, if file_node_id is given, only search classes in that file.
    """
    results = []
    for node_id in G.nodes:
        data = G.nodes[node_id]
        if data["type"] == "class" and data["name"] == classname:
            if file_node_id:
                if data["relative_path"] == G.nodes[file_node_id]["relative_path"]:
                    results.append(node_id)
            else:
                results.append(node_id)
    return results

def find_function_by_name(G, funcname, file_node_id=None):
    """
    Return a list of node-ids for function nodes named `funcname`.
    Optionally, restrict to a specific file node.
    """
    results = []
    for node_id in G.nodes:
        data = G.nodes[node_id]
        if data["type"] == "function" and data["name"] == funcname:
            if file_node_id:
                if data["relative_path"] == G.nodes[file_node_id]["relative_path"]:
                    results.append(node_id)
            else:
                results.append(node_id)
    return results

def find_variable_by_name(G, varname, file_node_id=None):
    """
    Return a list of node-ids for variable nodes named `varname`.
    Optionally, restrict to a specific file.
    """
    results = []
    for node_id in G.nodes:
        data = G.nodes[node_id]
        if data["type"] == "variable" and data["name"] == varname:
            if file_node_id:
                if data["relative_path"] == G.nodes[file_node_id]["relative_path"]:
                    results.append(node_id)
            else:
                results.append(node_id)
    return results

# ----------------------------------------------------------------------
# FILE-LEVEL QUERIES
# ----------------------------------------------------------------------

def files_that_import(G, target_file_node_id):
    """
    Which files import or include a certain file/module (given by node_id)?
    """
    results = []
    for (src, dst, edge_data) in G.edges(data=True):
        if edge_data.get("label") == "imports" and dst == target_file_node_id:
            results.append(src)
    return results


def direct_dependencies_of_file(G, file_node_id):
    """
    Return the list of files that `file_node_id` directly imports.
    """
    results = []
    for (_, dst, edge_data) in G.out_edges(file_node_id, data=True):
        if edge_data.get("label") == "imports" or edge_data.get("label") == "imports_external":
            results.append(dst)
    return results

def transitive_dependencies_of_file(G, file_node_id):
    """
    Return *all* files that `file_node_id` imports (directly or transitively).
    """
    visited = set()
    stack = [file_node_id]
    while stack:
        current = stack.pop()
        for (_, nxt, edge_data) in G.out_edges(current, data=True):
            if (edge_data.get("label") == "imports" or edge_data.get("label") == "imports_external") and nxt not in visited:
                if G.nodes[nxt]["relative_path"]:
                    visited.add(G.nodes[nxt].get("relative_path"))
                    stack.append(nxt)
                else:
                    visited.add(nxt)
    visited.discard(file_node_id)
    return list(visited)

# ----------------------------------------------------------------------
# CLASS-LEVEL QUERIES
# ----------------------------------------------------------------------

def classes_that_inherit_from(G, parent_class_node_id):
    """
    Which classes inherit from the given class?
    """
    results = []
    for (child, parent, edge_data) in G.edges(data=True):
        if edge_data.get("label") == "inherits_from" and parent == parent_class_node_id:
            results.append(child)
    return results


def methods_of_class(G, class_node_id):
    """
    What methods does a particular class define?
    """
    methods = []
    for (_, succ, edge_data) in G.out_edges(class_node_id, data=True):
        if edge_data.get("label") == "contains":
            if G.nodes[succ]["type"] == "function":
                # Check if this function’s metadata indicates that it belongs to this class.
                if G.nodes[succ]["metadata"].get("parent_class") == G.nodes[class_node_id]["name"]:
                    methods.append(succ)
    return methods

def parent_classes_of_class(G, class_node_id):
    """
    Which parent classes does a given class extend?
    """
    return G.nodes[class_node_id]["metadata"]["parent_classes"]

# ----------------------------------------------------------------------
# FUNCTION-LEVEL QUERIES
# ----------------------------------------------------------------------

def functions_called_by(G, func_node_id):
    """
    What functions does this function call?
    """
    called = []
    for (_, dst, edge_data) in G.out_edges(func_node_id, data=True):
        if edge_data.get("label") == "calls":
            called.append(dst)
    return called

def functions_which_call(G, func_node_id):
    """
    Which functions call this one?
    """
    callers = []
    # for (src, _, edge_data) in G.in_edges(func_node_id, data=True):
    #     if edge_data.get("label") == "calls":
    #         callers.append(src)
    # return callers
    node = G.nodes[func_node_id]["name"]
    for node_id in G.nodes:
        data = G.nodes[node_id]
        if data["type"] == "function":
            if any(call.endswith(node) for call in data["metadata"]["calls"]):
                callers.append(node_id)
    return callers

def variables_accessed_by_function(G, func_node_id):
    """
    Which variables does a function read or write?
    """
    reads = []
    writes = []
    for (_, dst, edge_data) in G.out_edges(func_node_id, data=True):
        if edge_data.get("label") == "reads":
            reads.append(dst)
        elif edge_data.get("label") == "writes":
            writes.append(dst)
    return (reads, writes)

# ----------------------------------------------------------------------
# VARIABLE-LEVEL QUERIES
# ----------------------------------------------------------------------

def functions_that_access_variable(G, var_node_id):
    """
    Which functions read or modify a certain variable?
    """
    readers = []
    writers = []
    for (src, _, edge_data) in G.in_edges(var_node_id, data=True):
        if edge_data.get("label") == "reads":
            readers.append(src)
        elif edge_data.get("label") == "writes":
            writers.append(src)
    return (readers, writers)

def variable_is_attribute(G, var_node_id):
    """
    Check if the variable is a class/instance attribute.
    """
    return G.nodes[var_node_id]["metadata"].get("is_attribute", False)

# ----------------------------------------------------------------------
# CROSS-CUTTING QUERIES
# ----------------------------------------------------------------------

def find_references_to_name(G, name, node_type=None):
    """
    Find all nodes that match a given 'name'.
    """
    results = []
    for node_id, data in G.nodes(data=True):
        if data["name"] == name:
            if node_type and data["type"] != node_type:
                continue
            results.append(node_id)
    return results

def show_call_chain(G, start_func_node_id, end_func_node_id):
    """
    Show a path (if any) in the function-call graph from start_func to end_func.
    """
    def is_function_call_edge(u, v):
        for key, edge_data in G[u][v].items():
            if edge_data.get("label") == "calls":
                return True
        return False
    try:
        if start_func_node_id in G and end_func_node_id in G:
            return nx.shortest_path(G, source=start_func_node_id, target=end_func_node_id,method="dijkstra")
        else:
            raise nx.NetworkXNoPath()
    except nx.NetworkXNoPath:
        return None

def class_dependency_graph(G):
    """
    Generate a subgraph of classes only, focusing on 'inherits_from' and 'contains' edges.
    """
    class_graph = nx.MultiDiGraph()
    for node_id in G.nodes:
        ntype = G.nodes[node_id]["type"]
        if ntype in ("class", "function"):
            class_graph.add_node(node_id, **G.nodes[node_id])
    for (u, v, data) in G.edges(data=True):
        if u in class_graph.nodes and v in class_graph.nodes:
            if data.get("label") in ("inherits_from", "contains"):
                class_graph.add_edge(u, v, **data)
    return class_graph

# ----------------------------------------------------------------------
# NEW: Helper to return node metadata (like in tags.json)
# ----------------------------------------------------------------------

def get_node_metadata(G, node_id):
    """
    Given a node_id, return a dictionary with its metadata similar to what was saved in tags.json.
    """
    if node_id not in G.nodes:
        return None
    data = G.nodes[node_id]
    return {
        "Node_id": node_id,
        "Node_type": data.get("type"),
        "name": data.get("name"),
        "filepath": data.get("relative_path"),
        "start_line": data.get("line_range", [None, None])[0],
        "end_line": data.get("line_range", [None, None])[1],
        "Info": data.get("metadata", {})
    }


def build_file_to_nodes(G):
    """
    Build a mapping from a file's relative path to the set of node IDs that represent functions, classes, or variables.
    """
    file_to_nodes = {}
    for node_id, data in G.nodes(data=True):
        path = data.get("relative_path")
        if path and data["type"] in ("function", "class", "variable"):
            file_to_nodes.setdefault(path, set()).add(node_id)
    return file_to_nodes

def get_class_related_names(G, file_path, file_to_nodes):
    """
    From the given file (by relative path), gather names of methods that belong to a class.
    """
    names = set()
    for node_id in file_to_nodes.get(file_path, []):
        node_data = G.nodes[node_id]
        if node_data["type"] == "class":
            class_name = node_data.get("name")
            # For each method inside the class, if its parent_class matches, add its name.
            for succ in G.successors(node_id):
                succ_data = G.nodes[succ]
                if succ_data["type"] == "function" and succ_data["metadata"].get("parent_class") == class_name:
                    names.add(succ_data.get("name"))
    return names
# It can't catch imports that are used just for variable type specification
def is_import_used_in_file(G, current_file_path, imported_file_id, names, deps, file_to_nodes):
    """
    Determine heuristically if an import (identified by imported_file_id) is used in the current file.
    """
    imported_data = G.nodes[imported_file_id]
    # Case 1: The imported file has a relative path (i.e. it's an internal module).
    if imported_data.get("relative_path"):
        # Look for edges where the destination's relative_path matches the imported file.
        for src, dst, _ in G.edges(data=True):
            src_data = G.nodes[src]
            dst_data = G.nodes[dst]
            if (dst_data["type"] in ("function", "class", "variable") and 
                src_data["type"] in ("function", "class", "variable") and 
                dst_data.get("relative_path") == imported_data["relative_path"]):
                # Check if a node from the current file has the same name as the source.
                for node in file_to_nodes.get(current_file_path, []):
                    node_name = G.nodes[node].get("name")
                    src_name = src_data.get("name")
                    # Direct match or comparing using dependency prefixes from deps.
                    if node_name not in names and (node_name == src_name or 
                       any(node.split("::")[-1].startswith(dep) and node.split("::")[-1].split(".")[0] == src_name for dep in deps)):
                        return True
    # Case 2: External or standard imports (no relative_path).
    else:
        for node in file_to_nodes.get(current_file_path, []):
            node_name = G.nodes[node].get("name")
            for src, _, _ in G.edges(data=True):
                src_name = G.nodes[src].get("name")
                if node_name not in names and src_name.startswith(node_name):
                    return True
    return False

def unused_imports(G):
    """
    Determine which files or modules are imported but never used.
    
    Returns a dictionary mapping each file node ID to a list of tuples (imported_fid, is_used)
    where is_used is a boolean indicating if that import is referenced.
    """
    results = {}
    file_to_nodes = build_file_to_nodes(G)
    
    # Process each file node
    for file_id, data in G.nodes(data=True):
        if data["type"] != "file":
            continue
        imported_files = data["metadata"].get("dependencies", [])
        if not imported_files:
            continue
        
        # For internal modules, we use the base name of the dependency.
        deps = [dep.split(".")[0] for dep in direct_dependencies_of_file(G, file_id) if "." in dep]
        usage_list = []
        current_file = data.get("relative_path")
        # Gather class-related method names that might indicate usage.
        class_method_names = get_class_related_names(G, current_file, file_to_nodes)
        
        for imported_fid in imported_files:
            used = is_import_used_in_file(G, current_file, imported_fid, class_method_names, deps, file_to_nodes)
            usage_list.append((imported_fid, used))
        results[file_id] = usage_list
    return results