import readline

from src.helpers.print_output import print_color, add_color
from src.menu.root import MenuBase
from src.menu.typing import T_MENU_PAGE_NAME
from src.scanner.barq_scanner import BarqScanner


class PageAbstract:
    def __init__(self, scanner: BarqScanner, menu: MenuBase = None):
        self.scanner: BarqScanner = scanner
        self.menu: MenuBase = menu

    @property
    def name(self) -> T_MENU_PAGE_NAME:
        """Name of the page"""
        return "Base Page"

    @property
    def name_color(self) -> str:
        """Color of the page name"""
        return "green"

    @property
    def help_text(self) -> str:
        """Help text for specific page"""
        return "Write your help text here"

    @property
    def handle_exit(self) -> bool:
        """Ask before closing app if KeyboardInterrupt"""
        return False

    @property
    def commands(self) -> list[str]:
        """Ask before closing app if KeyboardInterrupt"""
        return []

    @property
    def is_session_set(self) -> bool:
        """Check that AWS connected"""
        if not self.scanner.session:
            print_color("[!] Error! No EC2 credentials set. Call setprofile first!")
            return False
        return True

    def _proceed_command(self, command: str):
        """Proceed selected action"""
        ...

    def proceed_command(self, command: str):
        """Proceed base or selected action"""
        ...

    def _show_help_text(self):
        help_text = self.name
        help_text += """ Help menu
            ================
            help            - print help menu
            where           - find where you are in the program
            back            - Go back to the previous menu
            exit            - Exit the program
            setprofile      - Set your AWS credentials
            showprofile     - Show your AWS credentials
            """
        help_text += self.help_text
        print_color(help_text)

    def _completer(self, text: str, state: int) -> str | None:
        """main function to handle action on the page"""
        for command in self.commands:
            if command.startswith(text):
                if not state:
                    return command
                else:
                    state -= 1

    @staticmethod
    def exit_handler() -> None:
        """function to handle KeyboardInterrupt"""
        print_color('Buy!', "green")

    def wait_for_command(self) -> None:
        """
        The command handler loop for the page.
        Commands will be sent to the processor and the prompt will be displayed.
        :return: None
        """
        while True:
            try:
                command = ''
                while command == '':
                    try:
                        readline.set_completer_delims(' \t\n;')
                        readline.parse_and_bind("tab: complete")
                        readline.set_completer(self._completer)
                        command = input(add_color(self.name, self.name_color) + ' > ')
                    except Exception as e:
                        print_color(e.__str__(), "red", bold=True)
                        exit()
                self._proceed_command(command=str(command))
            except KeyboardInterrupt as k:
                if self.handle_exit:
                    self.exit_handler()
                else:
                    print_color("CTRL+C pressed. Exiting...", 'red')
                    exit(9)
