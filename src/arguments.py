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
    parser.add_argument('-t', '--token', type=T_TOKEN, default='',
                        help="The AWS session token to use. (--key-id must be set)")
    return parser.parse_args()


cli_arguments = create_parser()
