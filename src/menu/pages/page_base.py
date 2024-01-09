import readline
from getpass import getpass

from clint.textui import prompt
from prettytable import PrettyTable

from src.helpers.get_regions import get_all_aws_regions
from src.helpers.print_output import print_color
from src.menu.pages.page_abstract import PageAbstract
from src.menu.root import MenuBase
from src.scanner.barq_scanner import BarqScanner


class PageBase(PageAbstract):
    def __init__(self, scanner: BarqScanner, menu: MenuBase = None):
        super().__init__(scanner, menu)
        self.scanner: BarqScanner = scanner
        self.menu: MenuBase = menu

    def _proceed_command(self, command: str):
        """Proceed selected action"""
        if command == 'setprofile':
            self.set_scanner_profile()
        elif command == 'showprofile':
            if not self.scanner.aws_creds:
                print_color(
                    '[!] You haven\'t set your AWS credentials yet. Run the command setprofile to set them')
            else:
                self.scanner.show_aws_creds()
        elif command == 'help':
            self._show_help_text()
        elif command == 'where':
            print_color(f'You are in the {self.name} page', 'green')
        elif command == 'back':
            self.menu.go_to_previous_page()
        elif command == 'exit':
            # cleanup tasks
            try:
                exit()
            except:
                pass
        else:
            self.proceed_command(command)

    def set_scanner_profile(self):
        readline.set_completer(None)
        aws_access_key_id = getpass('Enter your AWS Access Key ID:')
        print_color("[*] Key id is: %s************%s" %
                    (aws_access_key_id[0:2], aws_access_key_id[-3:-1]))
        aws_secret_access_key = getpass('Enter AWS Secret Access Key:')
        print_color("[*] secret key is: %s************%s" %
                    (aws_secret_access_key[0:2], aws_secret_access_key[-3:-1]))
        aws_session_token = getpass("Enter your session token, only if needed: ")

        possible_regions = get_all_aws_regions()
        region_table = PrettyTable(['Region'])
        for region in possible_regions:
            region_table.add_row([region])
        print(region_table)
        chosen_region = ''
        while chosen_region not in possible_regions:
            chosen_region = prompt.query(
                'What is your preferred AWS region?', default='us-east-1')
            if chosen_region in possible_regions:
                break
            else:
                print_color("[!] Invalid AWS region! Please try again")
        self.scanner.set_aws_creds(
            access_key_id=aws_access_key_id,
            secret_access_key=aws_secret_access_key,
            region_name=chosen_region,
            session_token=aws_session_token,
        )
