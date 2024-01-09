from typing import NamedTuple, Final

from src.constants.attack_types import AttackType


class HandlerConfig(NamedTuple):
    disable_av: bool = False


ATTACH_MAPPING: Final[dict[AttackType, HandlerConfig]] = {
    AttackType.METADATA: HandlerConfig(),
    AttackType.PRINT_FILE: HandlerConfig(),
    AttackType.URL: HandlerConfig(),
    AttackType.MSF: HandlerConfig(),
    AttackType.COMMAND: HandlerConfig(),
    AttackType.REVERSE_SHELL: HandlerConfig(),
}