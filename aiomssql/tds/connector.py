import asyncio
import struct
import warnings
from typing import Optional, Tuple, Final
from dataclasses import dataclass

from aiomssql.tds.packet import TDSPacket
from aiomssql.tds.config import ConnectionConfig, LoginConfig
from aiomssql.tds.error import TDSError, TDSProtocolError, TDSResponseError, SSLNegotiationError, TDSConnectionError
from aiomssql.tds.io import AIO, TLSOptions
from aiomssql.tds.request import Login7SQLAuthRequest, PreLoginRequest, SQLBatchRequest
from aiomssql.tds.response import TDSPreLoginResponse, TDSLogin7Response
from aiomssql.tds.types import TDSPacketType, TDSStatus, TokenType, EncryptionOption, TDSVersion
from aiomssql.util import Version


@dataclass
class TDSPacketHeader:
    """Parsed TDS packet header"""
    packet_type: TDSPacketType
    status: TDSStatus
    length: int
    spid: int
    packet_id: int
    window: int

    @classmethod
    def deserialize(cls, data: bytes) -> 'TDSPacketHeader':
        """
        Deserialize TDS packet header from raw bytes.

        Args:
            data: Raw header bytes (8 bytes)

        Returns:
            TDSPacketHeader: Parsed header object
        """
        if len(data) < 8:
            raise ValueError(f"Data too short for TDS packet header ({len(data)}/8 bytes)")

        packet_type = TDSPacketType(data[0])
        status = TDSStatus(data[1])
        length = struct.unpack('>H', data[2:4])[0]
        spid = struct.unpack('>H', data[4:6])[0]
        packet_id = data[6]
        window = data[7]

        return cls(packet_type, status, length, spid, packet_id, window)


class ConnectionInfo:

    def __init__(self, connection_config: ConnectionConfig):
        self._connection_config: ConnectionConfig = connection_config
        self._server_version: Optional[Version] = None

    @property
    def tds_version(self) -> TDSVersion:
        return self._connection_config.tds_version

    @property
    def packet_size(self) -> int:
        return self._connection_config.packet_size

    @property
    def timeout(self) -> float:
        return self._connection_config.timeout

    def set_server_version(self, version: Version):
        self._server_version = version

    def verify(self, tds_version: TDSVersion, server_version: Version):
        if tds_version != self._connection_config.tds_version:
            raise TDSProtocolError(f"Server TDS version {tds_version} "
                                   f"does not match client {self._connection_config.tds_version}")
        if server_version != self._server_version:
            raise TDSProtocolError(f"Server version {server_version} does not match expected {self._server_version}")


class TDSConnector:
    """
    Async-native TDS connector for SQL Server communication.
    Provides both low-level packet operations and high-level authentication methods.
    """

    def __init__(self, name: str = "unnamed_app"):
        self._name: Final[str] = name
        self.io: Optional[AIO] = None
        self.spid: int = 0
        self.is_connected: bool = False
        self._connection_info: Optional[ConnectionInfo] = None
        self._packet_id: int = 0

    @staticmethod
    async def _connect(connection_cfg: ConnectionConfig, tls_options: Optional[TLSOptions] = None) -> AIO:
        if connection_cfg.tds_version & TDSVersion.TDS_8X_TX:
            if tls_options is None or not tls_options.is_tls:
                raise TDSConnectionError(f"TDS 8.0+ requires TLS, but no TLS options provided")
            return await AIO.new(connection_cfg, tls_options)
        if connection_cfg.tds_version & TDSVersion.TDS_7X_TX:
            if tls_options is not None and tls_options.is_tls:
                parts = ("\nYou are trying to connect using protocol TDS 7.x and have TLS Enabled.",
                         "While this is typically ok, this library does NOT perform the"
                         " handshake in the way that Microsoft expects it as per their documentation:",
                         "https://learn.microsoft.com/en-us/openspecs/windows_protocols/"
                         "ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868",
                         "Instead, we initialise the TLS connection as we would in TDS 8.x",
                         "This is due to Microsoft expecting the TLS handshake to happen over their protocol "
                         "(thus having to manually implement TLS).",
                         "Fuck off, Microsoft, ain't nobody got time for that",)
                warnings.warn('\n'.join(parts), RuntimeWarning)
                # Excerpt from the link:
                #
                # The SSL payloads MUST be transported as data in TDS packets
                # with the message type set to 0x12 in the packet header. For example:
                #
                #  0x 12 01 00 4e 00 00 00 00// Packet Header
                #  0x 16 03 01 00 &// SSL payload
                # This applies to SSL traffic. The client sends the SSL handshake payloads as data in a PRELOGIN message
            return await AIO.new(connection_cfg, tls_options)
        raise TDSConnectionError(f"TDS version 0x{connection_cfg.tds_version:08x} not supported")

    async def connect(
        self,
        connection_cfg: ConnectionConfig,
        tls_options: Optional[TLSOptions] = None,
        reconnect: bool = False
    ) -> None:
        """Establish TCP connection to SQL Server"""
        if self.is_connected:
            if reconnect:
                await self.disconnect()
            else:
                raise TDSError("Already connected")
        try:
            self.io = await self._connect(connection_cfg, tls_options)
            self.is_connected = True
            self._connection_info = ConnectionInfo(connection_cfg)
            TDSPacket.set_tds_version(connection_cfg.tds_version)
        except asyncio.TimeoutError:
            raise TDSError(f"Connection timeout to {connection_cfg.host}:{connection_cfg.port}")
        except Exception as e:
            raise TDSError(f"Connection to {connection_cfg.host}:{connection_cfg.port} failed: {e}")

    async def disconnect(self) -> None:
        """Close the connection"""
        if self.io:
            await self.io.close()
            self.io = None
        self.is_connected = False
        self.spid = 0

    async def execute_batch(self, sql: str, timeout: Optional[float] = None) -> None:
        if timeout is None:
            timeout = self._connection_info.timeout

        # TODO: Check for packet size limit later

        packet = SQLBatchRequest(sql)
        print(f"DEBUG: Sending SQL batch: {sql}")
        await self._send_packet(packet, dbg=True)
        # resp = await self._read_response()
        resp = await asyncio.wait_for(self._read_response(), timeout)
        print(f"DEBUG: Batch executed, response length: {len(resp)}")

    def _next_packet_id(self) -> int:
        """Get next packet ID (wraps at 255)"""
        return 1
        # self._packet_id = (self._packet_id % 255) + 1
        # return self._packet_id

    async def _send_packet(self, packet: TDSPacket, status: TDSStatus = TDSStatus.EOM, dbg: bool = False):
        """Send a TDS packet using a packet"""
        if not self.is_connected:
            raise TDSError("Not connected")

        if packet.packet_type is None:
            raise ValueError("Builder must have packet type set")

        # Send the complete packet
        packet_data = packet.serialize(status, self.spid, self._next_packet_id())
        if dbg:
            example_packet = [
                0x01, 0x01, 0x00, 0x5C, 0x00, 0x00, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00,
                0x73, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00, 0x20, 0x00, 0x27, 0x00,
                0x66, 0x00, 0x6F, 0x00, 0x6F, 0x00, 0x27, 0x00, 0x20, 0x00, 0x61, 0x00, 0x73, 0x00, 0x20, 0x00,
                0x27, 0x00, 0x62, 0x00, 0x61, 0x00, 0x72, 0x00, 0x27, 0x00, 0x0A, 0x00, 0x20, 0x00, 0x20, 0x00,
                0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00
            ]
            print(f"expected_len({len(example_packet)}) == actual_len({len(packet_data)}) = {len(example_packet) == len(packet_data)}")
            match = lambda l1, l2: sum(1 for i in range(min(len(l1), len(l2))) if l1[i] == l2[i]) / max(len(l1), len(l2))
            print(f"match = {match(example_packet, list(packet_data)):.2%}")
        await self.io.write(packet_data)

    async def _read_packet_header(self) -> TDSPacketHeader:
        """Read and parse TDS packet header"""
        if not self.io:
            raise TDSError("Not connected")

        header_data = await self.io.read(8)
        return TDSPacketHeader.deserialize(header_data)

    async def _read_packet(self) -> Tuple[TDSPacketHeader, bytes]:
        """Read complete TDS packet"""
        header = await self._read_packet_header()

        # Read packet data (excluding header)
        data_length = header.length - 8
        if data_length > 0:
            data = await self.io.read(data_length)
        else:
            data = b''
        return header, data

    async def _read_response(self) -> bytes:
        """Read complete response (may span multiple packets)"""
        response = bytearray()

        while True:
            header, data = await self._read_packet()
            response.extend(data)

            # Check if this is the last packet
            if header.status & TDSStatus.EOM:
                break
        if self._is_error_response(response):
            raise TDSResponseError(bytes(response))
        return bytes(response)

    @staticmethod
    def _is_error_response(response_bytes: bytes) -> bool:
        """
        Quickly determine if response contains errors without full parsing.
        Returns True if errors present and no LOGINACK token found.
        """
        pos = 0
        has_error = False
        has_loginack = False

        while pos < len(response_bytes) and not (has_error and has_loginack):
            if pos >= len(response_bytes):
                break

            token = response_bytes[pos]
            pos += 1

            # Quick checks for tokens we care about
            if token == TokenType.ERROR:
                has_error = True
            elif token == TokenType.LOGINACK:
                has_loginack = True

            # Skip token data based on type
            if token in (TokenType.ERROR, TokenType.INFO, TokenType.LOGINACK, TokenType.ENVCHANGE):
                if pos + 2 <= len(response_bytes):
                    length = struct.unpack('<H', response_bytes[pos:pos + 2])[0]
                    pos += 2 + length
                else:
                    break
            elif token in (TokenType.DONE, TokenType.DONEPROC, TokenType.DONEINPROC):
                pos += 12  # Fixed size
            elif token == TokenType.RETURNSTATUS:
                pos += 4
            else:
                # Unknown token, try to skip with 2-byte length
                if pos + 2 <= len(response_bytes):
                    length = struct.unpack('<H', response_bytes[pos:pos + 2])[0]
                    pos += 2 + length
                else:
                    break

        return has_error and not has_loginack

    @staticmethod
    def _should_encrypt(client_encryption: EncryptionOption, server_encryption: EncryptionOption) -> bool:
        # Convert to 2-bit values (0-3)

        # Pre-compute condition bits
        client_cant = client_encryption == EncryptionOption.NOT_SUPPORTED
        client_prefer = client_encryption == EncryptionOption.ON
        client_require = client_encryption == EncryptionOption.REQUIRED

        server_cant = server_encryption == EncryptionOption.NOT_SUPPORTED
        server_require = server_encryption == EncryptionOption.REQUIRED

        if (client_cant and server_require) or (server_cant and client_require):
            raise SSLNegotiationError(client_encryption=client_encryption, server_encryption=server_encryption)

        if client_require or server_require:
            return True
        return client_prefer

    async def _pre_login(self, encryption: EncryptionOption = EncryptionOption.REQUIRED) -> TDSPreLoginResponse:
        """
        Perform pre-login handshake with the SQL Server.

        This method sends a pre-login packet and reads the response.

        Args:
            encryption: Encryption option to use (default is REQUIRED)

        Returns:
            TDSPreLoginResponse: Parsed pre-login response containing server options.
        """
        if not self.is_connected:
            raise TDSError("Not connected")

        packet = PreLoginRequest(encryption=encryption)
        await self._send_packet(packet)

        header, data = await self._read_packet()
        if header.packet_type != TDSPacketType.TABULAR_RESULT:
            raise TDSProtocolError(f"Expected TABULAR_RESULT, got {header.packet_type}")
        return TDSPreLoginResponse.deserialize(data)

    async def login7_sql_credentials(self, login_cfg: LoginConfig, tls_options: TLSOptions):
        """
        Perform SQL Server authentication using username/password.

        Args:
            login_cfg: Login configuration containing username, password, database
            tls_options: TLS options for secure connection (if needed)
        """
        if not self.is_connected:
            raise TDSError("Not connected")

        pre_login_response = await self._pre_login(encryption=tls_options.encryption)
        self._connection_info.set_server_version(pre_login_response.version)

        login7_request = Login7SQLAuthRequest(
            username=login_cfg.username,
            password=login_cfg.password,
            appname=self._name,
            database=login_cfg.database,
        )
        await self._send_packet(login7_request)

        b = await self._read_response()
        login7_response = TDSLogin7Response.deserialize(b)
        if login7_response.tds_version != self._connection_info.tds_version:
            raise TDSProtocolError(f"Server TDS version {login7_response.tds_version:08x} "
                                   f"does not match client {self._connection_info.tds_version:08x}")

        print(f"Login successful for user '{login_cfg.username}'")

    async def login7_windows_auth(self, database: str = "master", sspi_token: Optional[bytes] = None):
        """
        Perform Windows authentication (SSPI/Kerberos).

        Args:
            database: Initial database
            sspi_token: Pre-generated SSPI token (optional)
        """
        # TODO: Implement SSPI/Kerberos authentication
        # This requires platform-specific SSPI libraries
        raise NotImplementedError("Windows authentication not yet implemented")
    #
    # async def execute_batch(self, sql: str) -> None:
    #     """
    #     Execute a SQL batch command.
    #
    #     Args:
    #         sql: SQL query to execute
    #     """
    #     if not self.is_connected:
    #         raise TDSError("Not connected")
    #
    #     # Build SQL batch packet using packet properly
    #     packet = TDSPacket(TDSPacketType.SQL_BATCH)
    #     packet.write_string(sql, 'utf-16le')
    #
    #     await self._send_packet(packet)
    #
    #     # Read response
    #     response = await self._read_response()
    #
    #     # TODO: Parse response for results/errors
    #     print(f"Batch executed, response length: {len(response)}")
    #
    # async def execute_rpc(self, proc_name: str, params: Optional[list] = None) -> None:
    #     """
    #     Execute a remote procedure call.
    #
    #     Args:
    #         proc_name: Stored procedure name or special RPC ID
    #         params: List of parameters (not yet implemented)
    #     """
    #     if not self.is_connected:
    #         raise TDSError("Not connected")
    #
    #     packet = TDSPacket(TDSPacketType.RPC)
    #
    #     # Special procedure IDs
    #     special_procs = {
    #         "sp_executesql": 0xFFFF,
    #         "sp_prepare": 0xFFFE,
    #         "sp_execute": 0xFFFD,
    #         "sp_unprepare": 0xFFFC,
    #     }
    #
    #     if proc_name in special_procs:
    #         # Special stored procedure
    #         packet.write_uint16(0xFFFF)  # Name length for special proc
    #         packet.write_uint16(special_procs[proc_name])
    #     else:
    #         # Regular stored procedure name
    #         # Mark position to update length later
    #         packet.mark_position("proc_name_len")
    #         packet.write_uint16(0)  # Placeholder for length
    #
    #         # Write procedure name
    #         start_pos = packet.get_current_position()
    #         packet.write_string(proc_name)
    #         end_pos = packet.get_current_position()
    #
    #         # Calculate and update length
    #         name_length = (end_pos - start_pos) // 2  # UTF-16 character count
    #         packet.write_at_position(
    #             packet.get_position("proc_name_len"),
    #             packet.write_uint16,
    #             name_length
    #         )
    #
    #     # Option flags (0 for now)
    #     packet.write_uint16(0)
    #
    #     # TODO: Add parameter support
    #
    #     await self._send_packet(packet)
    #
    #     # Read response
    #     response = await self._read_response()
    #     print(f"RPC executed, response length: {len(response)}")

    async def logout(self) -> None:
        """Send logout packet and disconnect"""
        if not self.is_connected:
            return

        try:
            # TDS doesn't have a specific logout packet type
            # Just close the connection gracefully
            await self.disconnect()
        except Exception as e:
            print(f"Error during logout: {e}")

    #
    # async def write_raw(self, packet_type: TDSPacketType, data: bytes) -> None:
    #     """
    #     Write raw packet data (low-level interface).
    #
    #     Args:
    #         packet_type: TDS packet type
    #         data: Raw packet data
    #     """
    #     packet = TDSPacket(packet_type)
    #     packet.write_bytes(data)
    #     await self._send_packet(packet)
    #
    # async def begin_transaction(self, name: str = "", isolation_level: int = 1) -> None:
    #     """
    #     Begin a transaction with optional name and isolation level.
    #
    #     Args:
    #         name: Transaction name (optional)
    #         isolation_level: SQL Server isolation level (1-5)
    #     """
    #     if not self.is_connected:
    #         raise TDSError("Not connected")
    #
    #     packet = TDSPacket(TDSPacketType.TRANSACTION_MANAGER)
    #
    #     # Transaction Manager Request Type (5 = Begin Transaction)
    #     packet.write_uint16(5)
    #
    #     # Isolation level
    #     packet.write_uint8(isolation_level)
    #
    #     # Transaction name
    #     if name:
    #         # Use varchar for transaction name
    #         packet.write_varchar(name, 'utf-8')
    #     else:
    #         packet.write_uint8(0)  # Empty name
    #
    #     await self._send_packet(packet)
    #
    #     # Read response
    #     response = await self._read_response()
    #     print(f"Transaction started: {name or 'unnamed'}")
