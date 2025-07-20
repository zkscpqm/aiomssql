"""
Async MSSQL Connection Implementation
Handles connection establishment and login
"""
from typing import Optional
from contextlib import asynccontextmanager

from aiomssql.tds.config import ConnectionConfig, LoginConfig
from aiomssql.tds.connector import TDSConnector


class AsyncMSSQLDriver:

    def __init__(self, conn_cfg: ConnectionConfig, login_cfg: Optional[LoginConfig] = None,
                 application_name: str = 'unnamed_app'):
        self.connector: TDSConnector = TDSConnector(conn_cfg, name=application_name)
        self.login_cfg: Optional[LoginConfig] = login_cfg
        self.connected: bool = False

    async def connect(self, login_cfg: Optional[LoginConfig] = None):
        if self.connected:
            raise RuntimeError("Already connected")
        login_cfg = login_cfg or self.login_cfg
        if not login_cfg:
            raise ValueError("Login configuration is required")
        await self.connector.connect()
        await self.connector.login7_sql_credentials(login_cfg)
        self.connected = True

    async def close(self):
        """Close the connection"""
        await self.connector.disconnect()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


@asynccontextmanager
async def connect(conn_cfg: ConnectionConfig, login_cfg: LoginConfig, app_name: str = 'unnamed_app'):
    """
    Create an async connection to MSSQL Server
    """
    conn = AsyncMSSQLDriver(conn_cfg, login_cfg, app_name)
    await conn.connect(login_cfg)
    try:
        yield conn
    finally:
        await conn.close()
