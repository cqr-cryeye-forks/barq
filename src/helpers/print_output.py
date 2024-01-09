from clint.textui import puts, colored
from prettytable import PrettyTable


def add_color(string, color=None, bold: bool = False):
    """
    Change text color for the Linux terminal.
    """
    color_mappings = {
        "[!]": "red",
        "[+]": "green",
        "[..]": "yellow",
        "[*]": "blue"
    }

    if not color:
        for prefix, prefix_color in color_mappings.items():
            if string.strip().startswith(prefix):
                return getattr(colored, prefix_color)(string)
        else:
            return colored.black(string)

    return getattr(colored, color.lower())(string, bold=bold)


def print_color(text: str, color=None, bold: bool = False) -> None:
    puts(add_color(string=text, color=color, bold=bold))


def print_table(columns_names: list[str], table_data: list, title: str | None = None) -> None:
    if title:
        print_color(title)
    _table = PrettyTable()
    _table.field_names = columns_names
    _table.add_rows(table_data)
    print(_table)
