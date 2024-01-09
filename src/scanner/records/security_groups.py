from dataclasses import dataclass, field


@dataclass
class PermissionRule:
    protocol: str
    from_port: str
    to_port: str
    ranges: str  # 0.0.0.0/0


@dataclass
class SecurityGroup:
    id: str
    description: str = ''
    ip_permissions: list[PermissionRule] = field(default_factory=list)
    ip_permissions_egress: list[PermissionRule] = field(default_factory=list)
