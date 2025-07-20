import asyncio
import ssl
import socket


class TLSTestServer:
    def __init__(self, cert_file: str, key_file: str, port: int = 4477):
        self.cert_file = cert_file
        self.key_file = key_file
        self.port = port
        self.server = None

    async def start(self):
        # Create server SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.cert_file, self.key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        print(f"Server: Starting TLS server on port {self.port}")

        self.server = await asyncio.start_server(
            self.handle_client,
            host='localhost',
            port=self.port,
            ssl=context
        )

        print(f"Server: Listening on localhost:{self.port}")
        return self.server

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info('peername')
        print(f"Server: Client connected from {peer}")

        try:
            # Get SSL info
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                cipher = ssl_obj.cipher()
                version = ssl_obj.version()
                print(f"Server: TLS Version: {version}, Cipher: {cipher}")

            # Read client message
            data = await reader.read(1024)
            print(f"Server: Received: {data.decode()}")

            # Send response
            response = b"Hello from TLS server! Handshake successful."
            writer.write(response)
            await writer.drain()
            print(f"Server: Sent: {response.decode()}")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            print("Server: Client disconnected")


class TLSTestClient:
    def __init__(self, port: int = 4477):
        self.port = port

    async def connect(self):
        # Create client SSL context
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Trust self-signed cert

        print(f"Client: Connecting to localhost:{self.port}")

        try:
            reader, writer = await asyncio.open_connection(
                host='localhost',
                port=self.port,
                ssl=context,
                server_hostname='localhost'
            )

            print("Client: Connected successfully!")

            # Get SSL info
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                cipher = ssl_obj.cipher()
                version = ssl_obj.version()
                print(f"Client: TLS Version: {version}, Cipher: {cipher}")

            # Send message
            message = b"Hello from TLS client!"
            writer.write(message)
            await writer.drain()
            print(f"Client: Sent: {message.decode()}")

            # Read response
            response = await reader.read(1024)
            print(f"Client: Received: {response.decode()}")

            writer.close()
            await writer.wait_closed()
            print("Client: Connection closed")

            return True

        except Exception as e:
            print(f"Client error: {e}")
            return False


async def test_tls_handshake(cert_file: str, key_file: str):
    """Test TLS handshake between server and client using provided certificates"""

    print("=" * 60)
    print("TLS HANDSHAKE TEST")
    print("=" * 60)

    # Create server and client
    server = TLSTestServer(cert_file, key_file)
    client = TLSTestClient()

    try:
        # Start server
        server_instance = await server.start()

        # Give server time to start
        await asyncio.sleep(0.1)

        # Connect client
        success = await client.connect()

        # Stop server
        server_instance.close()
        await server_instance.wait_closed()

        print("=" * 60)
        if success:
            print("✓ TLS handshake test PASSED")
        else:
            print("✗ TLS handshake test FAILED")
        print("=" * 60)

        return success

    except Exception as e:
        print(f"Test error: {e}")
        return False


# Example usage
if __name__ == "__main__":
    # Use your SQL Server certificate files
    CERT_FILE = r"C:\Users\zkscp\Documents\certificates\sqlserver-cert.pem"
    KEY_FILE = r"C:\Users\zkscp\Documents\certificates\sqlserver-key.pem"


    async def main():
        success = await test_tls_handshake(CERT_FILE, KEY_FILE)
        if success:
            print("\nTLS handshake works fine - issue is likely with SQL Server TLS implementation")
        else:
            print("\nTLS handshake failed - issue might be with certificate or SSL configuration")


    asyncio.run(main())