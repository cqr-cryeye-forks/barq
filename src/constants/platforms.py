import enum


@enum.unique
class PlatformTypes(enum.Enum):
    WINDOWS = 'windows'
    LINUX = 'linux'
