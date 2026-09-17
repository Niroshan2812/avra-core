import os
from openai import OpenAI
from avra_action.statergies.base_strategy import TaintPath
from avra_action.statergies.sqli_strategy import SqlInjectionStatergy

def run_action_test():

    # Define isolated block of vulnarability code execute in reaction layer 

    isolated_vulnarable_block = """
    public void deleteUser(String username){
        String quary = "DELETE FROM users WHERE username = '"+ username +"'";
        statement.execute(query)
    }
"""

    taint_trace = TaintPath(
        entry_point="deleteUser(String username)",
        sink_expression="statement.execute(query);",
        # The variable transformation path: parameter -> query string -> execution
        variable_trace=["username", "query", "execute"] 
    )

    print("[*] Step 1: Initializing LLM Client and Strategy Engine...")

    llm_client = OpenAI(
        api_key = os.getenv("OPENAI_API_KEY","mock-key-for-testing")


    )

    # istantiate the specific remediation statergy using dependancy injection 

    statergy = SqlInjectionStatergy(llm_client)

    print("[*] Trigger context-aware code generation ")


    # Execute statergy
    try:
        result = statergy.generate_patch(
            source_code = isolated_vulnarable_block,
            taint_trace = taint_trace,
            historical_context =[],
            falure_logs =None
        )

        print("\n[+] MILESTONE 3 SUCCESS: Patch Generated!")
        print(f"Target CWE: {result.cwe_id}")
        print(f"Confidence: {result.confidence_score}\n")
        print("--- PROPOSED PATCH ---")
        print(result.patched_code)
        print("----------------------")

    except Exception as e:
        print(f"\n[-] Execution pushed: required valid LLM endpoint, error : {e}")



if __name__ == "__main__":
    run_action_test()