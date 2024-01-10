from dataclasses import dataclass, asdict


@dataclass
class CommandInvocation:
    id: str
    instance_id: str = None
    region: str = None
    state: str = 'requested'
    platform: str = 'linux'
    error: str = 'No errors'
    output: str = 'No output'

    def dict(self):
        return asdict(self)
