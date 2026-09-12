import json
from avra_perception.ast_parser import JavaASTParser

def run_parser_test():

    # define vulnarable java method containing direct sql injection 

    vulnerable_java_code = """
public class UserRepository {
    public void deleteUser(String username) {
        // VULNERABILITY: Untrusted input flows directly into the execution sink
        String query = "DELETE FROM users WHERE username = '" + username + "'";
        statement.execute(query);
    }
}
"""

    print("[*] Initializing Tree-sitter Java Parser...")
    # Instantiate the parser. This loads the pre-compiled C-bindings for Java grammar.
    parser = JavaASTParser()

    print("[*] Parsing raw code into Mathemetical AST graph ")
    ast_graph = parser.parse_to_graph(vulnerable_java_code)

    # isolate the total counts to verify the structural extraction was susscfully 
    print(f"[+] Extraction complete: {len(ast_graph.nodes)} Nodes, {len(ast_graph.edges)} Edgers found ")

    # Selialized pydantic models to JSO to cisualized the intermediate representation 
    print ("\n--- Sample Nodes ----------------------------------")
    for node in ast_graph.nodes[:5]:
        print(node.model_dump_json(indent=2))

    print("\n--- Sample Edges -------------------------")
    for edge in ast_graph.edges[:5]:
        print(edge.model_dump_json(indent=2))


    # actively look the vulnarable sink 
    print("\n Searching for ececutin sinks in the graph.....")
    for node in ast_graph.nodes:

        clean_content = node.content.strip()

        if node.node_type == "identifier":
            print(f"  -> Found Identifier: '{clean_content}' at node {node.id}")

        if node.node_type == "identifier" and clean_content == "execute":
            print(f"[!] found execution sink at node is {node.id}")
            print (f"sink details {node.model_dump_json(indent=2)}")


if __name__ == "__main__":
    run_parser_test()
