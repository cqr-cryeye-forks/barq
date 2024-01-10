from dataclasses import dataclass, field, asdict


@dataclass
class Parameter:
    name: str
    value: str

    def dict(self):
        return asdict(self)


@dataclass
class Secret:
    name: str
    value: str
    description: str = ''

    def dict(self):
        return asdict(self)


@dataclass
class Findings:
    secrets: list[Secret] = field(default_factory=list)
    tokens: list = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)

    def dict(self):
        return asdict(self)
