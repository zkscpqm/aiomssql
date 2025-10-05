import dataclasses
import socket
from typing import Final


def is_localhost(host: str) -> bool:
    """Check if host refers to local machine"""
    host = host.lower().strip('[]')  # Handle IPv6 [::1]
    return host in {
        'localhost',
        '127.0.0.1',
        '::1',
        '0:0:0:0:0:0:0:1',
        socket.gethostname().lower(),
        socket.getfqdn().lower()
    }


@dataclasses.dataclass(frozen=True)
class Version:
    major: int
    minor: int
    build: int
    sub_build: int = 0

    def __str__(self):
        return f"{self.major}.{self.minor}.{self.build}.{self.sub_build}"

    def to_uint32(self) -> int:
        """Pack version into uint32 where each part gets 8 bits"""
        # Validate ranges (8 bits = 0-255)
        if not all(0 <= v <= 255 for v in [self.major, self.minor, self.build, self.sub_build]):
            raise ValueError("Version components must be 0-255")

        return (self.major << 24) | (self.minor << 16) | (self.build << 8) | self.sub_build

    @classmethod
    def from_uint32(cls, version_int: int) -> 'Version':
        """Unpack version from uint32"""
        major = (version_int >> 24) & 0xFF
        minor = (version_int >> 16) & 0xFF
        build = (version_int >> 8) & 0xFF
        sub_build = version_int & 0xFF
        return cls(major, minor, build, sub_build)

    def __eq__(self, other: 'Version') -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return ((self.major, self.minor, self.build, self.sub_build)
                == (other.major, other.minor, other.build, other.sub_build))


VERSION: Final[Version] = Version(0, 0, 1, 0)
AIOMSSQL: Final[str] = "AIOMSSQL Python TDS Driver"
