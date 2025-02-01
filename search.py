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
        if edge_data.get("label") == "imports":
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
            if edge_data.get("label") == "imports" and nxt not in visited:
                visited.add(nxt)
                stack.append(nxt)
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
    for (src, _, edge_data) in G.in_edges(func_node_id, data=True):
        if edge_data.get("label") == "calls":
            callers.append(src)
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
        return nx.shortest_path(
            G, 
            source=start_func_node_id, 
            target=end_func_node_id, 
            weight=None, 
            method='dijkstra' if nx.is_weighted(G) else 'unweighted'
        )
    except nx.NetworkXNoPath:
        return None


def unused_imports(G):
    """
    Which files or modules are imported but never used?
    """
    results = {}
    for file_id in G.nodes:
        if G.nodes[file_id]["type"] != "file":
            continue
        imported_files = G.nodes[file_id]["metadata"].get("dependencies", [])
        if not imported_files:
            continue
        usage_list = []
        for imported_fid in imported_files:
            is_used = False
            # Heuristic: check if any function/class/variable from the imported file is referenced.
            for node2 in G.nodes:
                if G.nodes[node2]["type"] in ("function", "class", "variable") and \
                   G.nodes[node2]["relative_path"] == G.nodes[imported_fid]["relative_path"]:
                    for (src, dst, e_data) in G.edges(data=True):
                        if dst == node2:
                            if G.nodes[src]["type"] in ("function", "class", "variable") and \
                               G.nodes[src]["relative_path"] == G.nodes[file_id]["relative_path"]:
                                is_used = True
                                break
                    if is_used:
                        break
            usage_list.append((imported_fid, is_used))
        results[file_id] = usage_list
    return results

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
