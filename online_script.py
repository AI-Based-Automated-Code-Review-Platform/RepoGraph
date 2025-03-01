#!/usr/bin/env python3
import requests
import os
import sys
import json
import re
import pickle as pic
from repograph.construct_graph import CodeGraph
import subprocess

GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = None  # Set your token here if needed

# Headers for optional authentication
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

def extract_repo_details(repo_url):
    """
    Extract owner and repo name from a GitHub URL.
    Example: https://github.com/user/repo -> ("user", "repo")
    """
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", repo_url)
    if not match:
        print("Invalid GitHub URL format. Expected format: https://github.com/owner/repo")
        sys.exit(1)
    return match.group(1), match.group(2)

def get_default_branch(owner, repo):
    """
    Fetch the default branch (e.g., 'main' or 'master') for a repository.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    try:
        resp = requests.get(url, headers=HEADERS)
        resp.raise_for_status()
        return resp.json().get("default_branch", "master")  # Default to master if missing
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching default branch: {e}")
        sys.exit(1)

def list_repo_files(owner, repo, branch):
    """
    Fetch all file paths from the GitHub repository tree.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 404:
        print(f"Error: Repository '{owner}/{repo}' or branch '{branch}' not found.")
        sys.exit(1)
    resp.raise_for_status()
    data = resp.json()
    return [item["path"] for item in data.get("tree", []) if item["type"] == "blob"]

def fetch_file_content(owner, repo, branch, path):
    """
    Fetch the raw content of a file from GitHub.
    """
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    resp = requests.get(raw_url, headers=HEADERS)
    resp.raise_for_status()
    return resp.text

def main():
    # if len(sys.argv) < 2:
    #     print("Usage: python online_script.py <github_repo_url> [branch]")
    #     sys.exit(1)

    # repo_url = sys.argv[1]
    repo_url = "https://github.com/abdissa-png/A-chess-game-using-Pygame"
    owner, repo = extract_repo_details(repo_url)

    # Get branch if provided, otherwise fetch default branch
    # branch = sys.argv[2] if len(sys.argv) >= 3 else get_default_branch(owner, repo)
    branch = "new"

    print(f"Processing GitHub Repository: {owner}/{repo} (Branch: {branch})")

    # Clone the repository
    repo_dir = f"./tmp/{repo}"
    if os.path.exists(repo_dir):
        subprocess.run(["rm", "-rf", repo_dir])
    subprocess.run(["git", "clone", "--branch", branch, repo_url, repo_dir])

    # 1) Get all files in the repo
    all_paths = []
    for root, dirs, files in os.walk(repo_dir):
        for file in files:
            all_paths.append(os.path.relpath(os.path.join(root, file), repo_dir))

    # 2) Filter code files by extensions
    valid_exts = {".py", ".js", ".java", ".c"}
    code_paths = [p for p in all_paths if os.path.splitext(p)[1] in valid_exts]

    # 3) Initialize CodeGraph
    code_graph = CodeGraph(root=repo_dir)
    all_src_files = [p for p in all_paths if os.path.splitext(p)[1]]
    code_graph.all_source_files = all_src_files
    all_tags = []

    # 4) Fetch file content and parse
    for path in code_paths:
        try:
            with open(os.path.join(repo_dir, path), "r", encoding="utf-8") as f:
                code_string = f.read()
        except Exception as e:
            print(f"Error reading content for {path}: {e}")
            continue

        rel_fname = path
        file_tags = code_graph.parse_code_string(code_string, rel_fname)
        all_tags.extend(file_tags)
    print("Length of All tags: ", len(all_tags))
    # 5) Convert to graph structure
    G = code_graph.tag_to_graph(all_tags)

    # 6) Print graph statistics
    print("---------------------------------")
    print(f"Constructed code graph for: {repo_url} (branch: {branch})")
    print(f"   Number of nodes: {len(G.nodes())}")
    print(f"   Number of edges: {len(G.edges())}")
    print("---------------------------------")

    # 7) Generate metadata JSON
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
            related_files = [G.nodes[dep_id]["relative_path"] if G.nodes[dep_id]["relative_path"] else G.nodes[dep_id]["name"] for dep_id in dep_ids if dep_id in G.nodes]
            out["Info"] = {
                "Number_of_lines": data["metadata"].get("total_lines", 0),
                "Language": data["metadata"].get("language", ""),
                "related_files": related_files
            }

        elif node_type == "class":
            meta = data["metadata"]
            parent_names = [G.nodes[parent_id]["name"] for parent_id in meta["parent_classes"] if parent_id in G.nodes]
            method_names = [
                G.nodes[succ]["name"]
                for succ in G.successors(node_id)
                if G.nodes[succ]["type"] == "function" and G.nodes[succ]["metadata"]["parent_class"] == data["name"]
            ]
            var_names = list(set(meta["variables"]))
            out["Info"] = {
                "Inheritance": parent_names,
                "methods": method_names,
                "variables": var_names
            }

        elif node_type == "function":
            meta = data["metadata"]
            call_names = [G.nodes[callee_id]["name"] for callee_id in meta["calls"] if callee_id in G.nodes]
            unique_params = []
            seen = set()
            for param in meta.get("parameters", []):
                # Convert list values to tuples for hashability
                param_key = tuple(
                    (k, tuple(v) if isinstance(v, list) else v)
                    for k, v in sorted(param.items())
                )
                if param_key not in seen:
                    seen.add(param_key)
                    unique_params.append(param)
            out["Info"] = {
                "Parameters": unique_params,
                "IsMethodof": meta["parent_class"],
                "calls": list(set(call_names)),
                "reads": {key:list(meta.get("reads")[key]) for key in meta.get("reads", {})},
                "writes": {key:list(meta.get("writes")[key]) for key in meta.get("writes", {})},
            }

        elif node_type == "variable":
            meta = data["metadata"]
            used_by = meta["accessed_by"].union(meta["modified_by"])
            calls = []
            for used_id in used_by:
                if used_id in G.nodes:
                    used_node = G.nodes[used_id]
                    calls.append(used_node["name"])
                    if used_node["type"] == "function" and "parent_class" in used_node["metadata"]:
                        calls.append(used_node["metadata"]["parent_class"])
            out["Info"] = {"calls": list(set(calls)), "var_type": meta.get("var_type", ""), "modified_by":list(meta.get("modified_by",[])),"accessed_by":list(meta.get("accessed_by",[]))}

        final_nodes.append(out)

    # 8) Save results to tags.json
    with open("tags.json", "w", encoding="utf-8") as f:
        json.dump(final_nodes, f, indent=2)

    print("Wrote tags.json")
    
    #9) Save Graph to graph.pkl
    with open("graph.pkl", "wb") as f:
        pic.dump(G, f)
    print("Wrote graph.pkl")

if __name__ == "__main__":
    main()
