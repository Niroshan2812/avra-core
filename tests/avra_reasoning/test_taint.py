from avra_perception.ast_parser import JavaASTParser
from avra_reasoning.taint_solver import TaintSolver

def run_taint_test():

    vulnarable_JAVA_Code = """
    public class UserRepository {
        public void deleteUser(String username) {
            // VULNERABILITY: Untrusted input flows directly into the execution sink
            String query = "DELETE FROM users WHERE username = '" + username + "'";
            statement.execute(query);
        }
    }
    """

    print("[*] parsing code into mathemetical AST graph ")

    parser = JavaASTParser()
    ast_graph = parser.parse_to_graph(vulnarable_JAVA_Code)

    # identify parameters and execution nodes 
    source_id = None
    sink_id = None

    for node in ast_graph.nodes:
        clean_content = node.content.strip()

        # capture first instance 
        if node.node_type == "identifier" and clean_content == "username" and source_id is None:
            source_id = node.id


        # capture the executon method 
        if node.node_type == "identifier" and clean_content == "execute":
            sink_id = node.id

    print(f"\n[*] identified source node id {source_id} ('username')")
    print(f"[*] identified sink node id {sink_id} ('execute ')")


    # initialized the taintSolver to build the networkx directed graph 
    print("[*] initilized taintSolver and building networkx DiGraph")

    solver = TaintSolver(ast_graph)

    # Execute the graph theory reachability anelysis 
    print("[*] LCA anelysis")
    is_reachable = solver.verify_taint_path(source_id, sink_id)

    if is_reachable:
        print("[*] vulnarability proven - Untrusted source reaches the execution sink within the same execution scope.")
    else:
        print("[*] False Positive: No structural path connects the cource to the sink ")


    # reverse engineer the execution context to build localixrd llm prompt 

    print ("\n [*] Reverse engineering ecevution context for next phase ")
    context = solver.extract_execution_context(sink_id)

    # print hirarchical path from the root class 
    for step in context:
        print(f"   ->[Node {step['id']}] {step['type'].upper()}: {step['content'][:40]}...")


if __name__ == "__main__":
    run_taint_test()
