import enum


@enum.unique
class AttackType(enum.Enum):
    METADATA = 'metadata'
    PRINT_FILE = 'printfile'
    URL = 'url'
    MSF = 'msf'
    COMMAND = 'command'
    REVERSE_SHELL = 'reverseshell'


ATTACK_OPTIONS = [
    {
        'selector': '1',
        'prompt': 'Download EC2 metadata and userdata (custom init script)',
        'return': AttackType.METADATA.value,
    },
    {
        'selector': '2',
        'prompt': 'Display a file',
        'return': AttackType.PRINT_FILE.value,
    },
    {
        'selector': '3',
        'prompt': 'Visit a URL from inside EC2 instance',
        'return': AttackType.URL.value,
    },
    {
        'selector': '4',
        'prompt': 'metasploit',
        'return': AttackType.MSF.value,
    },
    {
        'selector': '5',
        'prompt': 'Run a command',
        'return': AttackType.COMMAND.value,
    },
    {
        'selector': '6',
        'prompt': 'Reverse Shell to external server',
        'return': AttackType.REVERSE_SHELL.value,
    },
]
