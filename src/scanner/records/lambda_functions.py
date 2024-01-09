from dataclasses import dataclass


@dataclass
class LambdaFunction:
    name: str
    arn: str
    runtime: str
    role: str
    description: str
    environment: str
    region: str
