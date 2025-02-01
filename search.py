import networkx as nx

def find_file_by_name(G, filename):
    """
    Return the node-id of a file node whose 'name' equals `filename`.
    If multiple files match, returns the first. Otherwise returns None.
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
            # If file_node_id is given, also check the file containment
            if file_node_id:
                # We can see if there's an edge file_node_id -> node_id with label 'contains'
                # or if data["relative_path"] matches the file node's path
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
# FILE-LEVEL QUESTIONS
# ----------------------------------------------------------------------

def files_that_import(G, target_file_node_id):
    """
    Which files import or include a certain file/module (given by node_id)?
    We look for edges with label='imports' leading to target_file_node_id.
    Returns a list of file node-ids that import the target file.
    """
    results = []
    for (src, dst, edge_data) in G.edges(data=True):
        if edge_data.get("label") == "imports" and dst == target_file_node_id:
            # src is the importing file
            results.append(src)
    return results

def direct_dependencies_of_file(G, file_node_id):
    """
    Return the list of files that `file_node_id` directly imports.
    i.e. edges file_node_id -> x with label='imports'
    """
    results = []
    for (_, dst, edge_data) in G.out_edges(file_node_id, data=True):
        if edge_data.get("label") == "imports":
            results.append(dst)
    return results

def transitive_dependencies_of_file(G, file_node_id):
    """
    Return *all* files that `file_node_id` imports (directly or transitively).
    This can be done with a DFS or BFS over 'imports' edges.
    """
    visited = set()
    stack = [file_node_id]

    while stack:
        current = stack.pop()
        for (_, nxt, edge_data) in G.out_edges(current, data=True):
            if edge_data.get("label") == "imports" and nxt not in visited:
                visited.add(nxt)
                stack.append(nxt)

    # Remove the original file node from the result if present
    visited.discard(file_node_id)
    return list(visited)


# ----------------------------------------------------------------------
# CLASS-LEVEL QUESTIONS
# ----------------------------------------------------------------------

def classes_that_inherit_from(G, parent_class_node_id):
    """
    Which classes inherit from the given class?
    In the graph, there's an edge child->parent with label='inherits_from'.
    So we look for edges with label='inherits_from' pointing to parent_class_node_id.
    """
    results = []
    for (child, parent, edge_data) in G.edges(data=True):
        if edge_data.get("label") == "inherits_from" and parent == parent_class_node_id:
            results.append(child)
    return results

def methods_of_class(G, class_node_id):
    """
    What methods does a particular class define?
    In the graph, there is an edge class->function with label='contains'.
    And also, the function node has "parent_class" in metadata matching the class name.
    """
    methods = []
    for (_, succ, edge_data) in G.out_edges(class_node_id, data=True):
        if edge_data.get("label") == "contains":
            if G.nodes[succ]["type"] == "function":
                methods.append(succ)
    return methods

def parent_classes_of_class(G, class_node_id):
    """
    Which parent classes does a given class extend?
    We can read `G.nodes[class_node_id]["metadata"]["parent_classes"]`,
    or follow edges class->(parent) labeled 'inherits_from'.
    """
    return G.nodes[class_node_id]["metadata"]["parent_classes"]

# ----------------------------------------------------------------------
# FUNCTION-LEVEL QUESTIONS
# ----------------------------------------------------------------------

def functions_called_by(G, func_node_id):
    """
    What functions does this function call?
    Edges with label='calls' from func_node_id -> other_function.
    """
    called = []
    for (_, dst, edge_data) in G.out_edges(func_node_id, data=True):
        if edge_data.get("label") == "calls":
            called.append(dst)
    return called

def functions_which_call(G, func_node_id):
    """
    Which functions call this one?
    Reverse traversal of edges labeled 'calls' that point to func_node_id.
    """
    callers = []
    for (src, _, edge_data) in G.in_edges(func_node_id, data=True):
        if edge_data.get("label") == "calls":
            callers.append(src)
    return callers

def variables_accessed_by_function(G, func_node_id):
    """
    Which variables does a function read or write?
    Edges function->variable with label='reads' or 'writes'.
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
# VARIABLE-LEVEL QUESTIONS
# ----------------------------------------------------------------------

def functions_that_access_variable(G, var_node_id):
    """
    Which functions read or modify a certain variable?
    We look for edges function->var with label='reads' or 'writes'.
    Alternatively, see G.nodes[var_node_id]["metadata"]["accessed_by"] or ["modified_by"].
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
    This is determined by 'is_attribute' in node metadata.
    """
    return G.nodes[var_node_id]["metadata"].get("is_attribute", False)

# ----------------------------------------------------------------------
# CROSS-CUTTING QUERIES
# ----------------------------------------------------------------------


def find_references_to_name(G, name, node_type=None):
    """
    Find all nodes that match a given 'name'. 
    Optionally restrict by node_type in {"function", "variable", "class", ...}.
    Then to see references (like calls, reads, writes), you can 
    do in_edge/out_edge analysis on each found node.

    Returns a list of node-ids.
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
    You can do a simple BFS or use networkx shortest_path.
    Returns a list of node-ids representing one path, or None if no path.
    """
    # We only want edges labeled 'calls' in the function subgraph. 
    # Let's build a subgraph or just use a custom BFS:
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
    For each file that imports something, check if that imported file's 
    classes/functions/variables are actually referenced by the importer.

    We'll return a dict:
      { importing_file_node_id: [ (imported_file_node_id, is_used_boolean), ... ], ... }
    Then you can filter for the ones where is_used_boolean == False.
    """
    results = {}
    for file_id in G.nodes:
        if G.nodes[file_id]["type"] != "file":
            continue
        
        imported_files = G.nodes[file_id]["metadata"]["dependencies"]  # these are node-ids for imported files
        if not imported_files:
            continue
        
        usage_list = []
        for imported_fid in imported_files:
            # Check if any classes/functions from imported_fid are used in file_id
            is_used = False
            
            # A simple heuristic: for each function or class in imported_fid, see if 
            # there's a call or inherits_from or read/write edge from something in file_id.
            # We'll gather all nodes that belong to imported_fid:
            for node2 in G.nodes:
                if G.nodes[node2]["type"] in ("function","class","variable") and \
                   G.nodes[node2]["relative_path"] == G.nodes[imported_fid]["relative_path"]:
                    # This node is in the imported file.
                    
                    # Now see if there's an edge from any node in file_id to node2
                    # Example: file_id -> function is 'contains', but we want usage edges:
                    # function_in_file_id -> function_in_imported_file is 'calls'
                    
                    # We can do a quick loop:
                    for (src, dst, e_data) in G.edges(data=True):
                        if dst == node2:
                            # check if src belongs to file_id
                            src_file = None
                            # If src is a file itself, that might not be relevant. We want function->function or class->class
                            # We'll see if the src node is also from the same file as file_id:
                            # or if there's a path from file_id to src with label 'contains' (meaning it's *in* that file).
                            # For simplicity, let's check just relative_path match:
                            if G.nodes[src]["type"] in ("function","class","variable"):
                                if G.nodes[src]["relative_path"] == G.nodes[file_id]["relative_path"]:

                                    # that means src is a function/class in the importer
                                    # so the usage is real
                                    is_used = True
                                    break
            usage_list.append((imported_fid, is_used))
        results[file_id] = usage_list
    return results

def class_dependency_graph(G):
    """
    Generate a subgraph of classes only, focusing on 'inherits_from' edges or 'contains' edges to methods.
    You could then export this subgraph in DOT format to visualize UML-like diagrams.
    """
    # We'll filter nodes to only type='class' or type='function' if you want methods too.
    # And edges labeled 'inherits_from' or 'contains'.
    class_graph = nx.MultiDiGraph()
    for node_id in G.nodes:
        ntype = G.nodes[node_id]["type"]
        if ntype in ("class","function"):
            class_graph.add_node(node_id, **G.nodes[node_id])

    for (u, v, data) in G.edges(data=True):
        if u in class_graph.nodes and v in class_graph.nodes:
            if data.get("label") in ("inherits_from","contains"):
                class_graph.add_edge(u, v, **data)

    return class_graph
