import json
import os
from kafka import KafkaConsumer
from openai import OpenAI

from avra_perception.ast_parser import JavaASTParser
from avra_reasoning.taint_solver import TaintSolver
from avra_action.statergies.base_strategy import TaintPath
from avra_action.statergies.sqli_strategy import SqlInjectionStatergy
from avra_sandbox.docker_sandbox import SandboxResult


class AutonomusOrchestrator:
    """
    Consumes vulnerability events from Kafka and drives the end-to-end remediation lifecycle.
    """

    def __init__(self):

        # Kafka for listen webhook-triggers 

        self.cosumer = KafkaConsumer(
            
        )