from repograph.retriever import retrieve_node_context
from repograph.search import find_file_by_name,find_class_by_name,find_function_by_name,\
    find_variable_by_name,files_that_import,direct_dependencies_of_file, functions_that_access_variable, \
        transitive_dependencies_of_file, classes_that_inherit_from,methods_of_class,\
        parent_classes_of_class,show_call_chain,get_node_metadata,unused_imports,\
        functions_called_by,functions_which_call, variable_is_attribute,variables_accessed_by_function
import pickle
import json
with open("graph.pkl", "rb") as f:
    G = pickle.load(f)

# 1) Find a file by name
print("1) ",find_file_by_name(G, "King.py"),end="\n\n")
# 2) Find a class by name
print("2) ",find_class_by_name(G, "Piece"),end="\n\n")
# 3) Find a function by name
print("3) ",find_function_by_name(G, "minimax"),end="\n\n")
# 4) Find a variable by name
print("4) ",find_variable_by_name(G, "board.legalMoves"),end="\n\n")
# 5) Find files that import a file
print("5) ",files_that_import(G, "Board.py"),end="\n\n")
# 6) Find direct dependencies of a file
print("6) ",direct_dependencies_of_file(G, "Screen.py"),end="\n\n")
# 7) Transitive dependencies of a file
print("7) ",transitive_dependencies_of_file(G, "Pieces/King.py"),end="\n\n")
# 8) Classes that inherit from a class
print("8) ",classes_that_inherit_from(G, "Move.py::class::Move"),end="\n\n")
# 9) ParentClasses of a class
print("9) ",parent_classes_of_class(G, "Move.py::class::LongSideCastleMove"),end="\n\n")
# 10) Methods of a class
print("10) ",methods_of_class(G, "Move.py::class::Move"),end="\n\n")
# 11) functions that call a function
print("11) ",functions_which_call(G, "AI.py::function::minimax"),end="\n\n")
# 12) functions called by a function
print("12) ",functions_called_by(G, "AI.py::function::minimax"),end="\n\n")
# 13) variables accessed by a function
print("13) ",variables_accessed_by_function(G, "AI.py::function::minimax"),end="\n\n")
# 14) functions that access variable
print("14) ",functions_that_access_variable(G, "BoardUtils.py::getPosition|var::row"),end="\n\n")
# 15) is variable an attribute
print("15) ",variable_is_attribute(G, "Board.py::evaluate|var::self.whiteplayer.pieces"),end="\n\n")
# 16) Show call chain
print("16) ",show_call_chain(G, "Move.py::class::LongSideCastleMove","Move.py::class::Move"),end="\n\n")
# 17) Get node metadata
print("17) ",get_node_metadata(G, "Move.py::class::Move"),end="\n\n")
# 18) Get unused imports
print("18) ",json.dumps(unused_imports(G),indent=2),end="\n\n")
# 19) Code Content Retriever
print("19) ",json.dumps(retrieve_node_context(G,"./tmp/A-chess-game-using-Pygame","Board.py::initialize|var::START_ROW"),indent=2),end="\n\n")
# 20) Code Content Retriever
print("20) ",json.dumps(retrieve_node_context(G,"./tmp/A-chess-game-using-Pygame","Board.py::function::pickle.loads"),indent=2),end="\n\n")
# 21) Code Content Retriever
print("21) ",json.dumps(retrieve_node_context(G,"./tmp/A-chess-game-using-Pygame","Board.py::function::Rook"),indent=2),end="\n\n")
# 22) Code Content Retriever
print("22) ",json.dumps(retrieve_node_context(G,"./tmp/A-chess-game-using-Pygame","Board.py::function::getStrPosition"),indent=2),end="\n\n")