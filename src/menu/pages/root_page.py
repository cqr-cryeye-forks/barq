from src.menu.menu_commands import MAIN_COMMANDS
from src.menu.pages.page_base import PageBase
from src.menu.typing import T_MENU_PAGE_NAME


class RootPage(PageBase):

    @property
    def name(self) -> T_MENU_PAGE_NAME:
        """Name of the page"""
        return "Main"

    @property
    def help_text(self) -> str:
        """Help text for specific page"""
        return """showsecrets     - Show credentials and secrets acquired from the target AWS account
            training        - Go to training mode            
            dumpsecrets     - Gather and dump credentials of EC2 in Secrets Manager and Parameter Store
            attacksurface   - Discover attack surface of target AWS account
            addtosecgroups  - Add IPs and ports to security groups
            persistence     - Add persistence and hide deeper
            ec2instances    - Go to EC2 instances menu
            securitygroups  - List all discovered Security Groups
            """

    @property
    def commands(self) -> list:
        """Ask before closing app if KeyboardInterrupt"""
        return MAIN_COMMANDS

    @property
    def handle_exit(self) -> bool:
        """Ask before closing app if KeyboardInterrupt"""
        return True

    def proceed_command(self, command: str):
        if command == 'dumpsecrets':
            if not self.is_session_set:
                return
            self.scanner.find_all_creds()
        elif command == 'attacksurface':
            self.scanner.find_attack_surface()
        elif command == 'showsecrets':
            self.scanner.show_findings()
        elif command == 'securitygroups':
            self.scanner.show_security_groups()
        elif command == 'training':
            self.menu.open_page('training')
        elif command == 'ec2instances':
            self.menu.open_page('ec2instances')
