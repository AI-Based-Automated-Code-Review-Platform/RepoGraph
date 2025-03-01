import networkx as nx
import matplotlib.pyplot as plt
import pickle
import plotly.graph_objs as go
import re

# Load the graph from the .pkl file
with open('graph.pkl', 'rb') as f:
    G = pickle.load(f)

# Function to extract name between underscores
def extract_name(label):
    match = re.search(r'_(.*?)_', label)
    if match:
        return match.group(1)
    return label

# Extract names from node labels
labels = {node: extract_name(node) for node in G.nodes}

# Draw the graph in 2D
# plt.figure(figsize=(15, 15))
# pos = nx.spring_layout(G, k=0.1)  # Adjust the k parameter for better spacing
# nx.draw(G, pos, labels=labels, with_labels=True, node_size=500, node_color='skyblue', font_size=8, font_color='black', font_weight='bold', edge_color='gray')
# plt.title("NetworkX Graph Visualization")
# plt.show()

# Create 3D spring layout
pos_3d = nx.spring_layout(G, dim=3, k=0.1)

# Extract node positions
x_nodes = [pos_3d[node][0] for node in G.nodes]
y_nodes = [pos_3d[node][1] for node in G.nodes]
z_nodes = [pos_3d[node][2] for node in G.nodes]

# Extract edge positions
x_edges = []
y_edges = []
z_edges = []
for (src, dst, edge) in G.edges(data=True):
    if edge.get("label") == "imports":
        x_edges.extend([pos_3d[src][0], pos_3d[dst][0], None])
        y_edges.extend([pos_3d[src][1], pos_3d[dst][1], None])
        z_edges.extend([pos_3d[src][2], pos_3d[dst][2], None])

# Create trace for edges
edge_trace = go.Scatter3d(
    x=x_edges, y=y_edges, z=z_edges,
    mode='lines',
    line=dict(color='gray', width=1),
    hoverinfo='none'
)

# Create trace for nodes
node_trace = go.Scatter3d(
    x=x_nodes, y=y_nodes, z=z_nodes,
    mode='markers+text',
    marker=dict(symbol='circle', size=6, color='skyblue'),
    text=[node for node in G.nodes],
    textposition='top center',
    hoverinfo='text'
)

# Create the figure
fig = go.Figure(data=[edge_trace, node_trace])

# Set the layout
fig.update_layout(
    title='3D NetworkX Graph Visualization',
    showlegend=False,
    scene=dict(
        xaxis=dict(showbackground=False),
        yaxis=dict(showbackground=False),
        zaxis=dict(showbackground=False)
    )
)
# Show the plot
fig.show()