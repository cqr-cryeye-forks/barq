from dataclasses import dataclass, field, asdict

from src.typing import T_SECRET_KEY, T_ACCESS_KEY_ID, T_TOKEN, T_REGION_NAME


@dataclass
class AWSCredentials:
    region_name: T_REGION_NAME
    access_key_id: T_ACCESS_KEY_ID = None
    secret_access_key: T_SECRET_KEY = None
    session_token: T_TOKEN = None
    possible_regions: list = field(default_factory=list)

    def dict(self):
        return asdict(self)
