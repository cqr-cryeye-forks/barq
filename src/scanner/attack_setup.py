from dataclasses import dataclass, asdict


@dataclass
class AttackSetup:
    url_address: str = "http://169.254.169.254/latest/"
    linux_file_path: str = "/etc/passwd"
    windows_file_path: str = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    bash_command: str = "whoami"
    powershell_command: str = "whoami"
    remote_ip_host: str = ""
    remote_port: str = "4444"
    remote_port_windows: str = "5555"
    command: str = "cat /etc/passwd"

    def dict(self):
        return asdict(self)
