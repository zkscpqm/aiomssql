"""
Test script for async MSSQL login
"""
import asyncio

from aiomssql import AsyncMSSQLDriver, connect, ConnectionConfig, LoginConfig


async def test_login():
    conn_cfg = ConnectionConfig.local()
    login_cfg = LoginConfig(
        username='odbc_test',
        password='password123',
        database='test_db'
    )

    print("=" * 50)
    print("Async MSSQL Login Test")
    print("=" * 50)

    # Test 1: Using context manager
    try:
        print(f"\nTest 1: Connecting to {conn_cfg.host}:{conn_cfg.port}")
        async with connect(conn_cfg, login_cfg, "test") as conn:
            print("✓ Connected successfully using context manager!")
            print(f"  Connected: {conn.connected}")

    except Exception as e:
        print(f"✗ Connection failed: {e}")
        raise e

    # Test 2: Manual connection
    try:
        print(f"\nTest 2: Manual connection to {conn_cfg.host}:{conn_cfg.port}")
        conn = AsyncMSSQLDriver(conn_cfg, application_name="test_manual")
        await conn.connect(login_cfg)
        print("✓ Connected successfully!")
        print(f"  Connected: {conn.connected}")
        await conn.close()
        print("✓ Connection closed")

    except Exception as e:
        print(f"✗ Connection failed: {e}")
        raise e

    # Test 3: Invalid credentials
    try:
        print(f"\nTest 3: Testing invalid credentials")
        async with connect(
            conn_cfg, LoginConfig("invalid_login", "invalid_password")
        ):
            print("✗ This shouldn't happen - invalid credentials worked!")

    except Exception as e:
        print(f"✓ Expected failure with invalid credentials: {e}")

    print("\n" + "=" * 50)
    print("Tests completed")


if __name__ == "__main__":
    asyncio.run(test_login())
