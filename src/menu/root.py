from queue import Queue
from typing import TYPE_CHECKING

from src.helpers.print_output import print_color
from src.menu.typing import T_MENU_PAGE_NAME
if TYPE_CHECKING:
    from src.menu.pages.page_abstract import PageBase


class MenuBase:

    def __init__(self, pages: list, root_page: "PageBase") -> None:
        self.pages: list = pages
        for page in pages:
            page.menu = self
        self.root_page: "PageBase" = root_page
        self.current_page: "PageBase" = root_page
        self.page_history: Queue["PageBase"] = Queue()

    def show_root(self) -> None:
        self.root_page.wait_for_command()

    def reset_page_history(self) -> None:
        self.page_history = Queue()

    def force_to_page(self, page_name: T_MENU_PAGE_NAME) -> None:
        """
        Go to a page directly, bypassing the history.
        History will be reset and start from the beginning.
        :param page_name: menu to go to element directly.
        :return: None
        """
        new_page: "PageBase" | None = None
        self.current_page = self.root_page
        for page in self.pages:
            if page_name == page.name:
                new_page = page
                break
        self.reset_page_history()
        if not new_page:
            print_color("Page '{page_name}' not found. Force to root")
            new_page = self.root_page
            self.current_page = new_page
        self.current_page.wait_for_command()

    def open_page(self, page_name: T_MENU_PAGE_NAME, update_history: bool = True) -> None:
        """
        Go to a menu directly, bypassing the stack.
        This is used for functionality that involves interaction under a particular menu,
        and therefore does not add a menu to the stack.
        :param page_name: menu to go to element directly.
        :param update_history: boolean if needed to add source page to the history.
        :return: None
        """
        new_page: "PageBase" | None = None
        for page in self.pages:
            if page_name.lower() == page.name.lower():
                new_page = page
                break
        if not new_page:
            print_color("Page '{page_name}' not found. Please select correct page")
        else:
            if update_history:
                self.page_history.put(self.current_page)
            self.current_page = new_page
        self.current_page.wait_for_command()

    def go_to_previous_page(self) -> None:
        """
        Go back to previous menu (Pull from menu stack)
        :return: None
        """
        if self.page_history.empty():
            print_color("No previous pages")
            self.show_root()
            return
        previous_page = self.page_history.get()
        self.open_page(previous_page.name, update_history=False)
