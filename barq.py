#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import signal
from typing import NoReturn

from botocore.exceptions import ClientError

from src.arguments import cli_arguments
from src.constants.logo import ASCII_LOGO
from src.helpers.get_regions import get_all_aws_regions
from src.helpers.print_output import print_color
from src.menu.pages.instances_page import InstancesPage
from src.menu.pages.root_page import RootPage
from src.menu.pages.training_page import TrainingPage
from src.menu.root import MenuBase
from src.scanner.barq_scanner import BarqScanner


def start() -> NoReturn:
    """
        The start of the barq functionality.
    """
    logger = logging.getLogger('log')
    logger.setLevel(logging.ERROR)
    ch = logging.FileHandler('log.log')
    ch.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
    logger.addHandler(ch)
    logger.error('calling start')

    signal.signal(signal.SIGINT, signal.default_int_handler)
    print_color(ASCII_LOGO, 'yellow')
    regions = []
    if cli_arguments.key_id:
        if not cli_arguments.secret_key:
            print_color("[!] --secret-key is required with --key-id")
            exit(1)
        regions = cli_arguments.region
        if regions is None or []:
            print_color("[!] Region is not set. All available regions will be scanned. "
                        "First available region will be used")
            print_color("[!] Getting available regions...")
            regions = get_all_aws_regions()
        if len(regions) > 1:
            print_color(f"[!] Multi-regional scan! scan will be proceeded for each of available regions!")
    for region_name in regions:
        print_color(f"[*] Try to use region {region_name}...")
        try:
            scanner = BarqScanner(
                session_token=cli_arguments.token,
                access_key_id=cli_arguments.key_id,
                secret_access_key=cli_arguments.secret_key,
                region_name=region_name,
            )
            scanner.init_aws_session()
        except ClientError:
            print_color(f"[!] Region {region_name} is not available. Skipping...")
            continue
        root_page = RootPage(scanner=scanner)
        pages = [
            root_page,
            TrainingPage(scanner=scanner),
            InstancesPage(scanner=scanner),
        ]
        menu = MenuBase(pages=pages, root_page=root_page)
        menu.show_root()

if __name__ == "__main__":
    start()
