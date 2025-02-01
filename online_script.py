#!/usr/bin/env python3
import requests
import os
import sys
import json

from repograph.construct_graph import CodeGraph

GITHUB_API = "https://api.github.com"

def list_repo_files(owner, repo, branch="main"):
    """
    Return a list of file paths in the given GitHub repo/branch,
    by calling the GitHub 'git/trees' API with ?recursive=1.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    tree = data.get("tree", [])
    file_paths = []
    for item in tree:
        if item["type"] == "blob":
            file_paths.append(item["path"])
    return file_paths

def fetch_file_content(owner, repo, branch, path):
    """
    Fetch the raw text content of a single file in GitHub.
    We'll use the raw.githubusercontent.com URL for simplicity.
    """
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    resp = requests.get(raw_url)
    resp.raise_for_status()
    return resp.text

def main():
    if len(sys.argv) < 3:
        print("Usage: python online_script.py <owner> <repo> [branch]")
        sys.exit(1)

    owner = sys.argv[1]
    repo  = sys.argv[2]
    branch = sys.argv[3] if len(sys.argv) >= 4 else "main"

    # 1) List all files in the repo
    all_paths = list_repo_files(owner, repo, branch)

    # 2) Filter to known code extensions
    valid_exts = {".py", ".js", ".java", ".c"}
    code_paths = [p for p in all_paths if os.path.splitext(p)[1] in valid_exts]

    # 3) Initialize CodeGraph (use some dummy root, e.g. ".")
    code_graph = CodeGraph(root=".")

    all_tags = []

    # 4) For each source file, fetch content & parse in-memory
    for path in code_paths:
        try:
            code_string = fetch_file_content(owner, repo, branch, path)
        except Exception as e:
            print(f"Error fetching content for {path}: {e}")
            continue

        rel_fname = path  # We'll treat the path in the repo as "rel_fname"
        file_tags = code_graph.parse_code_string(code_string, rel_fname)
        all_tags.extend(file_tags)

    # 5) Convert all tags to a graph
    G = code_graph.tag_to_graph(all_tags)

    # 6) Print info about the graph
    print("---------------------------------")
    print(f"Constructed code graph for: https://github.com/{owner}/{repo} (branch: {branch})")
    print(f"   Number of nodes: {len(G.nodes())}")
    print(f"   Number of edges: {len(G.edges())}")
    print("---------------------------------")

    # 7) Now produce the final metadata JSON (similar to your __main__ code)
    final_nodes = []
    for node_id in G.nodes:
        data = G.nodes[node_id]
        node_type = data["type"]

        out = {
            "Node_id": node_id,
            "Node_type": node_type,
            "name": data["name"],
            "filepath": data["relative_path"],
            "start_line": data["line_range"][0],
            "end_line": data["line_range"][1],
            "Info": {}
        }

        if node_type == "file":
            dep_ids = data["metadata"]["dependencies"]
            related_files = []
            for dep_id in dep_ids:
                if dep_id in G.nodes:
                    related_files.append(G.nodes[dep_id]["name"])
            out["Info"] = {
                "Number_of_line": data["metadata"].get("total_lines", 0),
                "Language": data["metadata"].get("language", ""),
                "relatedfiles": related_files
            }


        elif node_type == "class":
            meta = data["metadata"]
            parent_names = []
            for parent_id in meta["parent_classes"]:
                if parent_id in G.nodes:
                    parent_names.append(G.nodes[parent_id]["name"])
            method_names = []
            for succ in G.successors(node_id):
                if G.nodes[succ]["type"] == "function":
                    if G.nodes[succ]["metadata"]["parent_class"] == data["name"]:
                        method_names.append(G.nodes[succ]["name"])
            var_names = list(set(meta["variables"]))
            out["Info"] = {
                "Inheritance": parent_names,
                "methods": method_names,
                "variables": var_names
            }

        elif node_type == "function":
            meta = data["metadata"]
            call_names = []
            for callee_id in meta["calls"]:
                if callee_id in G.nodes:
                    call_names.append(G.nodes[callee_id]["name"])
            out["Info"] = {
                "Parameter": meta.get("parameters", []),
                "IsMethodof": meta["parent_class"],
                "calls": call_names
            }

        elif node_type == "variable":
            meta = data["metadata"]
            used_by = set(meta["accessed_by"] + meta["modified_by"])
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
                    else:
                        calls.append(used_node["name"])
            out["Info"] = {"calls": list(set(calls))}

        final_nodes.append(out)

    # 8) Write out one JSON array
    with open("tags.json", "w", encoding="utf-8") as f:
        json.dump(final_nodes, f, indent=2)

    print("Wrote tags.json")

if __name__ == "__main__":
    main()
