import asyncio
import ssl
import warnings
from typing import AsyncGenerator, Optional

from aiomssql.tds.config import ConnectionConfig
from aiomssql.tds.error import TDSError, TDSProtocolError
from aiomssql.tds.types import EncryptionOption
from aiomssql.util import is_localhost


class TLSOptions:

    def __init__(
        self,
        encryption: EncryptionOption,
        server_hostname: Optional[str] = None,
        trust_server_certificate: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        handshake_timeout: float = 60.0,
        shutdown_timeout: float = 30.0
    ):
        """
        Initialize TLS options for the connection.

        :param encryption: SQL Server encryption option
        :param server_hostname: Hostname for server verification in TLS.
        :param trust_server_certificate: If True, server certificate is not verified.
        :param cert_file: Path to the certificate file.
        :param key_file: Path to the key file.
        :param ssl_context: Custom SSL context to use for TLS connections.
        :param handshake_timeout: Timeout for TLS handshake in seconds.
        :param shutdown_timeout: Timeout for SSL shutdown in seconds.
        """
        self.encryption: EncryptionOption = encryption
        self.server_hostname: Optional[str] = server_hostname
        self.trust_server_certificate: bool = trust_server_certificate
        self.cert_file: Optional[str] = cert_file
        self.key_file: Optional[str] = key_file
        self.ssl_context: Optional[ssl.SSLContext] = ssl_context
        self.handshake_timeout: float = handshake_timeout
        self.shutdown_timeout: float = shutdown_timeout

        if self.encryption in (EncryptionOption.REQUIRED, EncryptionOption.ON):
            if not self.server_hostname:
                raise ValueError("server_hostname must be provided when TLS is enabled")
            if bool(self.cert_file) ^ bool(self.key_file):
                raise ValueError("Both or neither one of cert_file and key_file must be provided for TLS")

            if self.ssl_context is None:
                self.ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_ciphers(
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256:"

            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES128-GCM-SHA256"
        )
        if is_localhost(self.server_hostname) or self.trust_server_certificate:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_default_certs()
            if self.cert_file and self.key_file:
                ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    @classmethod
    def insecure(cls) -> 'TLSOptions':
        """Create insecure TLS options (no encryption). If the server requires encryption, connection will fail"""
        return cls(encryption=EncryptionOption.NOT_SUPPORTED)

    @classmethod
    def prefer_insecure(
        cls,
        server_hostname: Optional[str] = None,
        trust_server_certificate: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        handshake_timeout: float = 60.0,
        shutdown_timeout: float = 30.0
    ) -> 'TLSOptions':
        """Create TLS options that prefer insecure connection but allow encryption if required by the server"""
        return cls(
            encryption=EncryptionOption.OFF,
            server_hostname=server_hostname,
            trust_server_certificate=trust_server_certificate,
            cert_file=cert_file,
            key_file=key_file,
            ssl_context=ssl_context,
            handshake_timeout=handshake_timeout,
            shutdown_timeout=shutdown_timeout
        )

    @classmethod
    def secure(
        cls,
        server_hostname: str,
        trust_server_certificate: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        handshake_timeout: float = 60.0,
        shutdown_timeout: float = 30.0
    ) -> 'TLSOptions':
        """Create TLS options that require encryption for the connection"""
        return cls(
            encryption=EncryptionOption.REQUIRED,
            server_hostname=server_hostname,
            trust_server_certificate=trust_server_certificate,
            cert_file=cert_file,
            key_file=key_file,
            ssl_context=ssl_context,
            handshake_timeout=handshake_timeout,
            shutdown_timeout=shutdown_timeout
        )


class AIO:
    """Async I/O wrapper with enhanced functionality"""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        connection_config: ConnectionConfig
    ):
        self._connection_config: ConnectionConfig = connection_config
        self._tls_options: Optional[TLSOptions] = None

        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self._rlock: asyncio.Lock = asyncio.Lock()
        self._wlock: asyncio.Lock = asyncio.Lock()
        self._closed: bool = False

    @classmethod
    async def _connect(
        cls, cfg: ConnectionConfig,
        tls_options: Optional[TLSOptions],
        force_4096_packet_size: bool = False
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establish a new asyncio connection to the server.
        This is a low-level method that creates the StreamReader and StreamWriter.

        :param cfg: Connection configuration containing host, port, and other settings.
        :param tls_options: Optional TLS options for secure connections.
        :param force_4096_packet_size: If True, forces a packet size of 4096 bytes, useful for first PreLogin packet.
        """
        is_ssl = tls_options is not None and tls_options.encryption in (EncryptionOption.REQUIRED, EncryptionOption.ON)
        checking_hostname = is_ssl and tls_options.ssl_context.check_hostname

        ssl_context = tls_options.ssl_context if tls_options else None
        server_hostname = tls_options.server_hostname if checking_hostname else None
        packet_size = 4096 if force_4096_packet_size else max(cfg.packet_size, 4096)
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    host=cfg.host,
                    port=cfg.port,
                    limit=packet_size,
                    ssl=ssl_context,
                    server_hostname=server_hostname
                ),
                timeout=cfg.timeout
            )
        except Exception as e:
            raise TDSError(f"Failed to connect to {cfg.host}:{cfg.port}: {e}")

    @classmethod
    async def new(cls, cfg: ConnectionConfig) -> 'AIO':
        r, w = await cls._connect(cfg, None, force_4096_packet_size=True)
        return cls(r, w, cfg)

    async def upgrade_connection(self, tls_options: TLSOptions) -> None:
        """
        Upgrade to TLS by creating a brand new TLS connection.
        This discards the existing plain TCP connection and establishes a fresh TLS one.
        """

        try:
            self.writer.close()
            await self.writer.wait_closed()
            # Yes, the way to "upgrade" to TLS is to literally close the connection and create a new one.
            # The StreamWriter.start_tls() doesnt work with SQL Server??? Lost a full day to this.
            reader, writer = await self._connect(self._connection_config, tls_options)
            self.reader = reader
            self.writer = writer
        except ssl.SSLError as e:
            raise TDSError(f"TLS connection failed: {e}")
        except Exception as e:
            raise TDSError(f"TLS upgrade failed: {e}")

    async def read(self, n: int) -> bytes:
        """Read exactly n bytes from the stream"""
        if self._closed:
            raise IOError("Connection is closed")

        async with self._rlock:
            try:
                data = await self.reader.readexactly(n)
                return data
            except asyncio.IncompleteReadError as e:
                raise TDSProtocolError(f"Connection closed unexpectedly: expected {n} bytes, got {len(e.partial)}")
            except Exception as e:
                raise TDSError(f"Read error: {str(e)}")

    async def read_until(self, separator: bytes, max_size: int = 65536) -> bytes:
        """Read until separator is found or max_size is reached"""
        if self._closed:
            raise IOError("Connection is closed")

        async with self._rlock:
            try:
                data = await self.reader.readuntil(separator)
                if len(data) > max_size:
                    raise TDSProtocolError(f"Response too large: {len(data)} bytes")
                return data
            except asyncio.LimitOverrunError:
                raise TDSProtocolError("Response size limit exceeded")
            except Exception as e:
                raise TDSError(f"Read error: {str(e)}")

    async def stream(self, batch_size: int = 4096) -> AsyncGenerator[bytes, None]:
        """Stream data in chunks"""
        if self._closed:
            raise IOError("Connection is closed")

        async with self._rlock:
            while True:
                try:
                    chunk = await self.reader.read(batch_size)
                    if not chunk:
                        break
                    yield chunk
                except Exception as e:
                    raise TDSError(f"Stream error: {str(e)}")

    async def write(self, data: bytes) -> None:
        """Write data to the stream"""
        if self._closed:
            raise IOError("Connection is closed")

        async with self._wlock:
            try:
                self.writer.write(data)
                await self.writer.drain()
            except Exception as e:
                raise TDSError(f"Write error: {str(e)}")

    async def close(self) -> None:
        """Close the stream gracefully"""
        if self._closed:
            return

        self._closed = True

        async with self._wlock:
            try:
                if self.writer:
                    self.writer.close()
                    await self.writer.wait_closed()
            except Exception as e:
                warnings.warn(f"AIOMSSQL: Error closing asyncio.StreamWriter connection: {e}")
            finally:
                self.writer = None
                self.reader = None

    @property
    def is_closed(self) -> bool:
        """Check if connection is closed"""
        return self._closed
