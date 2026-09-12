import networkx as nx
from avra_perception.ast_parser import AstGraph
from typing import List, Dict, Any



class TaintSolver:
    """
    Reverse engineers data flow using graph theory
    It traverses the AST to prove that a vulnerable sink is reachable from an untrusted source.
    """

    def __init__(self, ast_graph: AstGraph) -> None:
        # initialize directed graph using NetworkX to use Shortest Path or Lowest Common Ancestor
        self.nx_graph = nx.DiGraph()

        # HY DRATE THE nETWORKX with our nodes and edges 
        self._buid_networkx_graph(ast_graph)


    def _buid_networkx_graph(self, ast_graph:AstGraph) ->None:
        # Insert all nodes, sorting thire orginal metadata as node attributes 
        for node in ast_graph.nodes:
            # stript whitespace 
            clean_content = node.content.strip()
            self.nx_graph.add_node(
                node.id,
                node_type =node.node_type,
                content=clean_content
            )
        # AST edges naturally flow parent -> child 
        for edge in ast_graph.edges:
            self.nx_graph.add_edge(edge.source_id, edge.target_id, relation = edge.relation)


    def extract_execution_context(self, sink_node_id:int) -> List[Dict[str, Any]]:

        """"
        Walk backword up the ast from the sink to extract the entire execution block So this help to 
        send to llm exact scope without sending all the file 
        """

        path =[]
        current_node = sink_node_id

        # traverse up the using graph predecessors 
        while current_node is not None:
            # Extract the metadata
            node_data = self.nx_graph.nodes[current_node]
            path.append({
                "id":current_node,
                "type":node_data["node_type"],
                "content":node_data["content"]
            })

            # Identify the parent node. In a strict AST, a node has exactly one structural parent.
            parents = list(self.nx_graph.predecessors(current_node))

            # move up the tree, or brake if hit root
            if parents:
                current_node = parents[0]
            else:
                break
        # return the traversal path for read top-down 
        return path[::-1]



    def verify_taint_path(self, source_id:int, sink_arg_id: int) -> bool:
        """
        Determine id the unstructured shares the same structural boundary as the sink execution 
        """

        # calculate LCA
        lca = nx.lowest_common_ancestor(self.nx_graph, source_id, sink_arg_id)

        if  lca is not None:
            lca_node = self.nx_graph.nodes[lca]

            # verify the common boundary is a method declaration 
            return lca_node.get("node_type") == "method_declaration"


        return False

        
