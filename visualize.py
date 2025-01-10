import networkx as nx
import matplotlib.pyplot as plt
import pickle

# Load the graph from the .pkl file
with open('graph.pkl', 'rb') as f:
    G = pickle.load(f)

# Draw the graph
plt.figure(figsize=(12, 12))
pos = nx.spring_layout(G)  # You can use other layouts like nx.circular_layout, nx.random_layout, etc.
nx.draw(G, pos, with_labels=True, node_size=500, node_color='skyblue', font_size=10, font_color='black', font_weight='bold', edge_color='gray')

# Show the plot
plt.title("NetworkX Graph Visualization")
plt.show()