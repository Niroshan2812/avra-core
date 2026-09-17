from abc import ABC, abstractmethod
from pydantic import BaseModel, Field
from typing import List, Optional 

# reverse engineerd vularability path -- prevent pasing arbitrary unstructured strings to LLM 
class TaintPath(BaseModel):
    entry_point :str = Field(..., description="The specific method or endpoint were untrusted data enters ")
    sink_expression: str =Field(..., description="The extract execution line were exploit triggers ")
    variable_trace: List[str]=Field(..., description="The orderd sequence of variable transformations")

# Define the strict output contract the LLM must return to the Sandbox verifier 
class RemediationResult(BaseModel):
    cwe_id:str
    orginal_code:str
    patched_code:str
    confidence_score:float=Field(...,description="Calculated probability that the patch is secure and compilable. ")

# Enforce the statergy pattern interface 
class BaseRemediationStategy(ABC):
    @property
    @abstractmethod
    def target_cew(self) -> str:
        """
        Force every child class to declare exactly which common weakness Enumeration it handles 
        """
        pass

    @abstractmethod
    def generate_patch(
        self, 
        source_code:str,
        taint_trace:TaintPath,
        historical_context:List[str],
        faliure_logs:Optional[str]=None

    ) ->RemediationResult:
        """
        The core generation contract. Every vulnarability type must implement this method, to translate the methametical graph trace into a secure code patch.  
        """
        pass