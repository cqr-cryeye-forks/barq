import json

from clint.textui import prompt
from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from src.constants.attack_types import ATTACK_OPTIONS
from src.constants.scan_modes import EC2ScanMode
from src.helpers.print_output import add_color, print_color
from src.menu.menu_commands import INSTANCES_COMMANDS
from src.menu.pages.page_base import PageBase
from src.menu.typing import T_MENU_PAGE_NAME


class InstancesPage(PageBase):

    @property
    def name(self) -> T_MENU_PAGE_NAME:
        """Name of the page"""
        return "EC2Instances"

    @property
    def help_text(self) -> str:
        """Help text for specific page"""
        return """showsecrets     - Show credentials and secrets acquired from the target AWS account
            ec2attacks      - Launch attacks against running EC2 instances
            list            - List all discovered EC2 instances
            dumpsecrets     - Gather and dump credentials of EC2 in Secrets Manager and Parameter Store
            attacksurface   - Discover attack surface of target AWS account
            securitygroups  - List all discovered Security Groups
            commandresults  - Check command results
            instance        - Get more details about an instance
            """

    @property
    def commands(self) -> list:
        """Ask before closing app if KeyboardInterrupt"""
        return INSTANCES_COMMANDS

    @property
    def handle_exit(self) -> bool:
        """Ask before closing app if KeyboardInterrupt"""
        return True

    def exit_handler(self) -> None:
        """function to handle KeyboardInterrupt"""
        choice = prompt.query(add_color(
            "Are you sure you want to go back to the main menu? Y/N", 'red'), default='Y')
        if choice == 'Y':
            self.menu.show_root()
        self.menu.open_page('ec2instances')

    def proceed_command(self, command: str):
        if command == 'dumpsecrets':
            if not self.is_session_set:
                return
            self.scanner.find_all_creds()
        elif command == 'attacksurface':
            self.scanner.find_attack_surface()
        elif command == 'showsecrets':
            self.scanner.show_findings()
        elif command == 'showawssecrets':
            self.scanner.show_aws_creds()
        elif command == 'securitygroups':
            self.scanner.show_security_groups()
        elif command == 'ec2attacks':
            target_options = [{'selector': '1', 'prompt': 'All EC2 instances', 'return': EC2ScanMode.ALL.value},
                              {'selector': '2', 'prompt': 'Single EC2 instance', 'return': EC2ScanMode.SINGLE.value}]
            scan_mode = prompt.options('Choose your scope type:', target_options)
            print_color('[*] EC2 Attack List:')
            attack = prompt.options('Choose your attack mode:', ATTACK_OPTIONS)
            self.scanner.run_ec2_attacks(scan_mode=scan_mode, attack_mode=attack)
        elif command == 'list':
            self.scanner.show_ec2_instances()
        elif command == 'commandresults':
            self.scanner.show_command_invocations()
        elif command == 'instance':
            if len(self.scanner.ec2_instances) < 1:
                print_color(
                    '[!] You have no stored EC2 instances. Run the command attacksurface to discover them')
                return
            self.scanner.show_ec2_instances()
            print_color('[*] Target Options:')
            region = ''
            instance = None
            while instance is None:
                target_id = prompt.query('Type/Paste your target EC2 ID:')
                instance = next(target for target in targets if target.id == target_id)
            ec2client = self.scanner.session.client('ec2', region_name=region)
            result = ec2client.describe_instances(InstanceIds=[instance.id, ])

            json_str = json.dumps(
                result['Reservations'][0]['Instances'][0], indent=2, sort_keys=True, default=str)
            print(highlight(json_str, JsonLexer(), TerminalFormatter()))
