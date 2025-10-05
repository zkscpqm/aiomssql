from dataclasses import dataclass, field
from typing import Optional

from aiomssql.tds.types import TDSVersion


@dataclass(frozen=True)
class ConnectionConfig:
    host: str
    port: int = 1433
    timeout: float = 30.0
    tds_version: TDSVersion = field(default_factory=lambda: TDSVersion.TDS_80_TX)
    packet_size: int = 4096

    @classmethod
    def local(
        cls,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
        tds_version: Optional[TDSVersion] = None,
        packet_size: Optional[int] = None
    ) -> 'ConnectionConfig':
        """Create a default configuration for local connections"""
        kwargs = {}
        if port is not None:
            kwargs['port'] = port
        if timeout is not None:
            kwargs['timeout'] = timeout
        if tds_version is not None:
            kwargs['tds_version'] = tds_version
        if packet_size is not None:
            kwargs['packet_size'] = packet_size
        return cls(host='localhost', **kwargs)


@dataclass(frozen=True)
class LoginConfig:
    username: str
    password: str
    database: str = 'master'
