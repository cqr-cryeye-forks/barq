from clint.textui import puts, colored


def add_color(string, color=None):
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

    return getattr(colored, color.lower())(string)


def print_color(text: str, color=None) -> None:
    puts(add_color(string=text, color=color))
