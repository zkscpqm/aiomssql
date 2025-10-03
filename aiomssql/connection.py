"""
Async MSSQL Connection Implementation
Handles connection establishment and login
"""
from typing import Optional
from contextlib import asynccontextmanager

from aiomssql.tds.config import ConnectionConfig, LoginConfig
from aiomssql.tds.connector import TDSConnector
from aiomssql.tds.io import TLSOptions


class AsyncMSSQLDriver:

    def __init__(self, conn_cfg: ConnectionConfig, login_cfg: Optional[LoginConfig] = None,
                 application_name: str = 'unnamed_app'):
        self.conn_cfg: ConnectionConfig = conn_cfg
        self.connector: TDSConnector = TDSConnector(application_name)
        self.login_cfg: Optional[LoginConfig] = login_cfg
        self.connected: bool = False

    async def connect(self, login_cfg: Optional[LoginConfig] = None, tls_options: Optional[TLSOptions] = None):
        if self.connected:
            raise RuntimeError("Already connected")
        login_cfg = login_cfg or self.login_cfg
        if not login_cfg:
            raise ValueError("Login configuration is required")
        if not tls_options:
            tls_options = TLSOptions.prefer_secure(server_hostname=self.conn_cfg.host, handshake_timeout=3.)
        await self.connector.connect(self.conn_cfg, tls_options)
        await self.connector.login7_sql_credentials(login_cfg, tls_options)
        self.connected = True

    async def close(self):
        """Close the connection"""
        await self.connector.disconnect()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


@asynccontextmanager
async def connect(
    conn_cfg: ConnectionConfig, login_cfg: LoginConfig, app_name: str = 'unnamed_app',
    tls_options: Optional[TLSOptions] = None
):
    """
    Create an async connection to MSSQL Server
    """
    conn = AsyncMSSQLDriver(conn_cfg, login_cfg, app_name)
    await conn.connect(login_cfg, tls_options=tls_options)
    try:
        yield conn
    finally:
        await conn.close()
