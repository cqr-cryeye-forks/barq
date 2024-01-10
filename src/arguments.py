import argparse

from src.typing import T_REGION_NAME, T_SECRET_KEY, T_ACCESS_KEY_ID, T_TOKEN


def create_parser():
    parser = argparse.ArgumentParser(description='The AWS Cloud Post Exploitation framework')
    parser.add_argument('-k', '--key-id', type=T_ACCESS_KEY_ID, default=None,
                        help="The AWS access key id")
    parser.add_argument('-s', '--secret-key', type=T_SECRET_KEY, default=None,
                        help="The AWS secret access key. (--key-id must be set)")
    parser.add_argument('-r', '--region', nargs='*', type=T_REGION_NAME, default=None,
                        help="Region to use. If not set - all regions will be scanned. (--key-id must be set)")
    parser.add_argument('-t', '--token', type=T_TOKEN, default=None,
                        help="The AWS session token to use. (--key-id must be set)")
    parser.add_argument('-j', '--json', type=str, default=None,
                        help="Json file name or location where to save all results")
    parser.add_argument("-a", "--auto", action="store_true", default=False,
                        help="Proceed all scans in fully automated mode, without asking or requesting info. "
                             "Make sure to provide all required info in props, "
                             "otherwise some commands can be skipped")
    parser.add_argument('-u', '--url-address', type=str, default="http://169.254.169.254/latest/",
                        help="URL for url attack.")
    parser.add_argument('-wf', '--windows-file-path', type=str, default="/etc/passwd",
                        help="File path for Linux instances.")
    parser.add_argument('-lf', '--linux-file-path', type=str, default="C:\\Windows\\System32\\drivers\\etc\\hosts",
                        help="File path for Windows instances.")
    parser.add_argument('-bc', '--bash-command', type=str, default="whoami",
                        help="Bash attack command")
    parser.add_argument('-pc', '--powershell-command', type=str, default="whoami",
                        help="PowerShell attack command")
    parser.add_argument('-rh', '--remote-host', type=str, default="",
                        help="Remote IP or hostname to connect back to")
    parser.add_argument('-rp', '--remote-port', type=str, default="4444",
                        help="Remote port")
    parser.add_argument('-rpw', '--remote-port-windows', type=str, default="5555",
                        help="Remote port")
    parser.add_argument('-ac', '--attack-command', type=str, default="cat /etc/passwd",
                        help="Command to run")
    return parser.parse_args()


cli_arguments = create_parser()
