import re
from .base_strategy import BaseRemediationStategy, TaintPath, RemediationResult
from openai import OpenAI
from typing import List, Optional

class SqlInjectionStatergy(BaseRemediationStategy):

    # bind this statergy spwcifically to sql injection vulnarabilities 
    @property
    def target_cew(self) -> str:
        return "CWE-89"

    def __init__(self, llm_client: OpenAI):
        self.llm = llm_client

    def generate_patch (
            self, 
            source_code:str,
            taint_trace:TaintPath,
            historical_context:List[str],
            faliure_logs:Optional[str]=None
            
    ) -> RemediationResult:

        # define rigid system persona
        # We explicitly forbid markdown formatting in the prompt, though we will still sanitize it later as a failsafe
        system_instruction = (
            "You are an autonomous DevSecOps agent. Your task is to remediate a CWE-89 SQL Injection. "
            "You must convert string concatenation into secure parameterized queries (e.g., PreparedStatement). "
            "Do NOT alter the core business logic. Return ONLY the raw, compilable Java code. "
            "Do not wrap the response in markdown blocks."
        )

        # Construct the dynamic context payload using the proven taint path.
        user_prompt = f"""
        Vulnerable Code Block:
        {source_code}

        Reverse-Engineered Data Flow:
        Entry Point: {taint_trace.entry_point}
        Taint Path: {' -> '.join(taint_trace.variable_trace)}
        Execution Sink: {taint_trace.sink_expression}
        """

        # implment RAG
        #Iject previous sucessull patches from the VDB to guid the model's syntax 
        if historical_context:
            user_prompt +="\n use this historical sucessful patches from this reporitory as syntax guide : \n"
            for past_patch in historical_context:
                user_prompt += f"{past_patch} \n"

        # implment self healing feedback loop 
        #if the sandbox verifier reject the previous iteration, inject the compile/test errors 
        if faliure_logs:
            user_prompt += (
                f"\n[URGENT] PREVIOUS ATTEMPT FAILED INCORRECTLY.\n"
                f"Compiler/Test Errors:\n{faliure_logs}\n"
                f"Analyze the error and provide a corrected implementation."
            )

        # execute the inference call with a low temp high deterministic, logical output 
        responce = self.llm.chat.completions.create(
            model="gpt-4o",
            temperature=0.1,
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt}
            ]
        )

        # extract the raw generated code from the LLM responce 
        raw_output = responce.choices[0].message.content.strip()

        # Sanitize the output. LLMs frequently ignore instructions and wrap code in ```java ... ```.
        # We use regex to strip these markdown artifacts so the code compiles cleanly in the Docker sandbox.
        clean_patch = self._strip_markdown(raw_output)

        # Package the sanitized code into the strict DTO contract and return it to the orchestrator.
        return RemediationResult(
            cwe_id=self.target_cwe,
            original_code=source_code,
            patched_code=clean_patch,
            confidence_score=0.95
        )

    def _strip_markdown(self, text:str) -> str:
        """
        Reverse-engineers LLM output habits by stripping markdown code block formatting.
        """

        # Match and remove ```java, ```sql, or generic ``` wrappers.
        pattern = r"^```[a-zA-Z]*\n(.*?)\n```$"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()

    
