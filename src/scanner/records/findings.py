from dataclasses import dataclass, field


@dataclass
class Parameter:
    name: str
    value: str


@dataclass
class Secret:
    name: str
    value: str
    description: str = ''


@dataclass
class Findings:
    secrets: list[Secret] = field(default_factory=list)
    tokens: list = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
