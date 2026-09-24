from avra_sandbox.docker_sandbox import DockerSandboxEviremet

def run_sandbox_test():
    print("[*] Step 1: Initializing Secure Docker Sandbox...")
    # Using an Alpine Python image for a faster test execution, 
    # though Maven/Java is your production target.
    sandbox = DockerSandboxEviremet(base_image="python:3.11-alpine")

    # Define a patched payload with an intentional syntax error to test the feedback loop.
    malformed_patch = """
    def execute_query(username):
        query = "SELECT * FROM users"
        # Intentional syntax error (missing parenthesis) to trigger stderr
        print "Executing query securely" 
    """

    print("[*] Step 2: Injecting payload into Ephemeral Container...")
    # Run the python syntax checker (equivalent to 'mvn compile')
    result = sandbox.verify_patch(
        patched_code=malformed_patch,
        test_command="python -m py_compile UserRepository.java" 
    )

    print("\n[*] Step 3: Extracting Container Telemetry...")
    if result.passed:
        print("[+] SUCCESS: Patch compiled and tests passed.")
    else:
        print("[-] FAILURE: Compilation rejected by sandbox.")
        print("\n--- CAPTURED STDERR (To feed back to LLM) ---")
        print(result.stderr_logs.strip())
        print("---------------------------------------------")

if __name__ == "__main__":
    run_sandbox_test()