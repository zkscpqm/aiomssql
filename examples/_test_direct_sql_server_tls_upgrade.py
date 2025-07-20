import asyncio
import ssl


async def test_direct_tls_to_sql_server():
    """Test direct TLS connection to SQL Server (bypassing TDS pre-login)"""

    print("Testing direct TLS to SQL Server (like C# code)...")

    for version_name, min_ver, max_ver in [
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            print(f"Trying {version_name}...")

            # Create SSL context
            ctx = ssl.create_default_context()
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Connect directly with TLS (like C# code)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host='localhost',
                    port=1433,  # Same port as SQL Server
                    ssl=ctx,
                    server_hostname=None
                ),
                timeout=10.0
            )

            # Get SSL info
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                print(f"SUCCESS! {ssl_obj.version()} using {ssl_obj.cipher()}")

            writer.close()
            await writer.wait_closed()
            return True

        except Exception as e:
            print(f"{version_name} failed: {e}")

    return False


# Add this to your test file and run it
if __name__ == "__main__":
    asyncio.run(test_direct_tls_to_sql_server())