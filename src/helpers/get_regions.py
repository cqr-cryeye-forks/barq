from boto3.session import Session

from src.typing import T_REGION_NAME_LIST


def get_all_aws_regions() -> T_REGION_NAME_LIST:
    s = Session()
    return s.get_available_regions('dynamodb')
