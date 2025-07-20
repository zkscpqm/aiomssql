from dataclasses import dataclass

from aiomssql.tds.types import TDSVersion


@dataclass(frozen=True)
class ConnectionConfig:
    host: str
    port: int = 1433
    timeout: float = 30.0
    tds_version: TDSVersion = TDSVersion.TDS_74
    packet_size: int = 4096

    @classmethod
    def local(cls) -> 'ConnectionConfig':
        """Create a default configuration for local connections"""
        return cls(host='localhost', port=1433, timeout=30.0, tds_version=TDSVersion.TDS_74, packet_size=4096)


@dataclass(frozen=True)
class LoginConfig:
    username: str
    password: str
    database: str = 'master'
