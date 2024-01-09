import enum


@enum.unique
class EC2ScanMode(enum.Enum):
    ALL = 'all'
    SINGLE = 'single'
