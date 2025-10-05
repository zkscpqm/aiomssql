"""
Test script for async MSSQL login
"""
import asyncio

from aiomssql import AsyncMSSQLDriver, ConnectionConfig, LoginConfig
from aiomssql.tds.types import TDSVersion


async def test_create_delete_table():

    login_cfg = LoginConfig(
        username='odbc_test',
        password='password123',
        database='test_db'
    )

    print("=" * 50)
    print("Async MSSQL Create Delete table Test")
    print("=" * 50)

    conn_cfg = ConnectionConfig.local(tds_version=TDSVersion.TDS_80_TX)
    print(f"Trying to connect to {conn_cfg.host}:{conn_cfg.port}/{login_cfg.username}/{login_cfg.database}")
    conn = AsyncMSSQLDriver(conn_cfg, application_name="test_manual")
    await conn.connect(login_cfg)
    assert conn.connected, "Connection failed"
    print("Connected successfully!")
    await conn.exec("\nselect 'foo' as 'bar'\n        ")

    await conn.close()

    print("\n" + "=" * 50)
    print("Tests completed")


if __name__ == "__main__":
    asyncio.run(test_create_delete_table())
