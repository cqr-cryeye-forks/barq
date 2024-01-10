from dataclasses import dataclass, asdict


@dataclass
class LambdaFunction:
    name: str
    arn: str
    runtime: str
    role: str
    description: str
    environment: str
    region: str

    def dict(self):
        return asdict(self)
