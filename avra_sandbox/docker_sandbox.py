import docker
from docker.errors import ContainerError, ImageNotFound, APIError
from pydantic import BaseModel, Field
import tempfile
import os 


class SandboxResult(BaseModel):
    passed: bool = Field(..., description="True if compilation and test exit with code 0.")
    stdout_logs: str = Field(..., description="Standed output from the test runner ")
    stderr_logs: str = Field(...,description="Standed error / stack trace to feed back to the llm ")

class DockerSandboxEviremet:
    """
    Manages the lifecycle of secure, ephemeral contrainers fortesting for testing untrusted ai generated patches 

    """

    def __init__(self, base_image: str = "maven:3.9-eclipse-temurin-21-alpine") -> None:
        self.client = docker.from_env()
        self.base_image = base_image

        # Early pull the image for time 

        try:
            self.client.images.get(self.base_image)

        except ImageNotFound:
            print(f"[*] Pulling Sandbox image {self.base_image}")
            self.client.images.pull(self.base_image)

    def verify_patch(self, patched_code:str, test_command:str) -> SandboxResult:
        """
        Mounts the patched code into an isolated containner and execute the regression suite 

        """

        # create temp dic on the host to hold the parched 

        with tempfile.TemporaryDirectory() as temp_dir:

            # llm generated payload 
            test_file_path = os.path.join(temp_dir, "UserRepository.java")

            with open (test_file_path, "w") as f:
                f.write(patched_code)

            try:

                # Execute containner 
                output = self.client.containers.run(
                    image =self.base_image,
                    command=test_command,
                    volumes={temp_dir:{'bind': '/workspace', 'mode': 'ro'}}, # Read-only mount
                    working_dir = "/workspace",

                    # isolate for cybersecurity
                    network_mode="none",
                    mem_limit="512m",
                    cpu_quota = 100000,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],

                    # emperical cleanup
                    remove=True,
                    detach=False,
                    stderr=True,
                    stdout=True


                    
                )

                return SandboxResult(
                    passed=True,
                    stdout_logs=output.decode('utf-8'),
                    stderr_logs=""
                )
            except ContainerError as e:
                return SandboxResult(
                    passed=False,
                    stdout_logs="",
                    stderr_logs=e.stderr.decode('utf-8')
                )

            except APIError as e:
                return SandboxResult(
                                    passed=False,
                                    stdout_logs="",
                                    stderr_logs=str(e)
                                )
