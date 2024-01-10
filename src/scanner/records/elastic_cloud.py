from dataclasses import dataclass, asdict


@dataclass
class EC2Instance:
    id: str
    ami_id: str
    public_dns_name: str
    public_ip_address: str
    platform: str = ''
    state: str = ''
    region: str = ''
    iam_profile: str = ''

    def dict(self):
        return asdict(self)
