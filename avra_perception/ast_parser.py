import tree_sitter
from pydantic import BaseModel, Field
from typing import List, Dict
import tree_sitter_java

# Graph Data Contracts 
class GraphNode(BaseModel):
    """Represents a single operation, identifier, or keyword in the code."""

    id:int
    node_type:str=Field(...,description="The AST grammar type (e.g., 'method_invocation', 'identifier')")
    content: str = Field(...,description="The actual raw code string for this node")
    start_byte: int
    end_byte:int

class GraphEdge(BaseModel):
    """ Represents the structural relationship beteween tow nodes"""
    source_id : int
    target_id: int
    relation:str = Field(...,description="Type of connection ( E.g - 'child', 'next_sibling ')")

class AstGraph(BaseModel):
    """The complete mathemetical representation of the parsed source code. """
    nodes: List[GraphNode] =[]
    edges:List[GraphEdge] =[]


# parser implemntation 

class JavaASTParser:
    """
    Encap the tree-sitter C-bidings to parse raw Java Code into a serialized graph structure opt for DL ingestion
    """

    def __init__(self) -> None:
        # Initialized raw java grammer 
        # complies the specific syntax rule required to understand Java constucts 

        self.language = tree_sitter.Language(tree_sitter_java.language(),"java")

        # instanticate the core tree-sitter parser
        self.parser = tree_sitter.Parser()

        # Bind the java grammer into parser instance 
        self.parser.set_language(self.language)

    def parse_to_graph (self,raw_code:str) -> AstGraph:
        """Transform source code into mathemetical graph of nodes and edges """

        # covert string to raw bytes 
        # tree sitter operates on byte arrays for high-perform c-level traversal 
        code_bytes = raw_code.encode("utf8")
        # generate the raw AST 
        tree = self.parser.parse(code_bytes)

        # initialized DTO hold serialized graph data 
        graph = AstGraph()

        # counter for generate unique sequantial ids for every ode in the graph 
        node_id_counter = {"current": 0}

        # recursive depth-first-search sratring at root 
        self._traverse_and_build(
            tree.root_node, code_bytes, graph, node_id_counter, parent_id = None
        )
        return graph


    def _traverse_and_build(
            self, ts_node : tree_sitter.Node, code_bytes:bytes,
            graph :AstGraph, counter:Dict[str, int], parent_id: int |None
    ) -> None:

        """
        Recursively walks the Tree-sitter AST, 
        extracting semantic data and mapping structural edges.
        """

        # Capture the current unique ID for this specific node and ++ gloable counter 
        current_id = counter["current"]
        counter["current"] += 1

        # extract the precise string of code this node represent using byte slicing
        # decode it back to UTF=8 for sementic anelysis by models like CodeBERT 
        node_content = code_bytes[ts_node.start_byte:ts_node.end_byte].decode("utf8")

        # normalized graphNode object and apped it to our graph node list 
        graph.nodes.append(
            GraphNode(
                id=current_id, 
                node_type=ts_node.type,
                content=node_content,
                start_byte=ts_node.start_byte,
                end_byte=ts_node.end_byte
            )
        )

        # If this node has a parent, create a directional edge representing the hierarchical 'child_of' relationship.
        if parent_id is not None:
            graph.edges.append(
                GraphEdge(
                    source_id=parent_id,
                    target_id=current_id,
                    relation="child_of"
                )
            )

        # iterate over all immediate children of the current Tree-sitter node 
        for i, child in enumerate(ts_node.children):
            # Recursively process each child, parsing the current node's ID as the new Parent_id
            self._traverse_and_build(child, code_bytes, graph, counter, current_id)

            # For capturing the execurtion oder flow link sibling nodes sequently so it will be the foundation for the 
            # control flow graph 
            if i > 0:
                previous_sibling_id = current_id + i