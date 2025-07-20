import asyncio
import struct
from typing import Optional, Tuple, Final
from dataclasses import dataclass

from aiomssql.tds.packet import TDSPacket
from aiomssql.tds.config import ConnectionConfig, LoginConfig
from aiomssql.tds.error import TDSError, TDSProtocolError, TDSResponseError
from aiomssql.tds.io import AIO
from aiomssql.tds.request import Login7SQLAuthRequest, PreLoginRequest
from aiomssql.tds.response import TDSPreLoginResponse, TDSLogin7Response
from aiomssql.tds.types import TDSPacketType, TDSStatus, TokenType


@dataclass
class TDSPacketHeader:
    """Parsed TDS packet header"""
    packet_type: TDSPacketType
    status: TDSStatus
    length: int
    spid: int
    packet_id: int
    window: int


class TDSConnector:
    """
    Async-native TDS connector for SQL Server communication.
    Provides both low-level packet operations and high-level authentication methods.
    """

    def __init__(self, cfg: ConnectionConfig, name: str = "unnamed_app"):
        self._name: Final[str] = name
        self.cfg: ConnectionConfig = cfg
        self.io: Optional[AIO] = None
        self.spid: int = 0
        self.is_connected: bool = False
        self._packet_id: int = 0

    async def connect(self) -> None:
        """Establish TCP connection to SQL Server"""
        if self.is_connected:
            raise TDSError("Already connected")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.cfg.host, self.cfg.port),
                timeout=self.cfg.timeout
            )
            self.io = AIO(reader, writer)
            self.is_connected = True
            print(f"Connected to {self.cfg.host}:{self.cfg.port}")
        except asyncio.TimeoutError:
            raise TDSError(f"Connection timeout to {self.cfg.host}:{self.cfg.port}")
        except Exception as e:
            raise TDSError(f"Connection failed: {str(e)}")

    async def disconnect(self) -> None:
        """Close the connection"""
        if self.io:
            await self.io.close()
            self.io = None
        self.is_connected = False
        self.spid = 0
        print("Disconnected")

    def _next_packet_id(self) -> int:
        """Get next packet ID (wraps at 255)"""
        self._packet_id = (self._packet_id % 255) + 1
        return self._packet_id

    async def _send_packet(self, packet: TDSPacket,
                           status: TDSStatus = TDSStatus.EOM) -> None:
        """Send a TDS packet using a packet"""
        if not self.is_connected:
            raise TDSError("Not connected")

        if packet.packet_type is None:
            raise ValueError("Builder must have packet type set")

        # Send the complete packet
        packet_data = packet.serialize(status, self.spid, self._next_packet_id())
        print(f"Sending {packet.packet_type.name} packet, total size: {len(packet_data)}")
        await self.io.write(packet_data)

    async def _read_packet_header(self) -> TDSPacketHeader:
        """Read and parse TDS packet header"""
        if not self.io:
            raise TDSError("Not connected")

        print("Reading TDS packet header...")
        header_data = await self.io.read(8)

        packet_type = header_data[0]
        status = header_data[1]
        length = struct.unpack('>H', header_data[2:4])[0]
        spid = struct.unpack('>H', header_data[4:6])[0]
        packet_id = header_data[6]
        window = header_data[7]

        return TDSPacketHeader(
            packet_type=TDSPacketType(packet_type),
            status=TDSStatus(status),
            length=length,
            spid=spid,
            packet_id=packet_id,
            window=window
        )

    async def _read_packet(self) -> Tuple[TDSPacketHeader, bytes]:
        """Read complete TDS packet"""
        print("Reading TDS packet...")
        header = await self._read_packet_header()

        # Read packet data (excluding header)
        data_length = header.length - 8
        if data_length > 0:
            data = await self.io.read(data_length)
        else:
            data = b''
        print(f"Received packet type: {header.packet_type.name}, length: {len(data)}")
        return header, data

    async def _read_response(self) -> bytes:
        """Read complete response (may span multiple packets)"""
        response = bytearray()

        print("Reading TDS response...")
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

    async def _pre_login(self) -> TDSPreLoginResponse:
        """
        Perform pre-login handshake with the SQL Server.

        This method sends a pre-login packet and reads the response.

        Returns:
            TDSPreLoginResponse: Parsed pre-login response containing server options.
        """
        if not self.is_connected:
            raise TDSError("Not connected")

        print("Sending pre-login request...")
        packet = PreLoginRequest()
        # parse_pre_login_request(packet.serialize())
        await self._send_packet(packet)

        print("Waiting for pre-login response...")
        header, data = await self._read_packet()
        print(f"Pre-login response received, header: {header}")
        if header.packet_type != TDSPacketType.TABULAR_RESULT:
            raise TDSProtocolError(f"Expected TABULAR_RESULT, got {header.packet_type}")
        return TDSPreLoginResponse.deserialize(data)

    async def login7_sql_credentials(self, login_cfg: LoginConfig) -> None:
        """
        Perform SQL Server authentication using username/password.

        Args:
            login_cfg: Login configuration containing username, password, database
        """
        if not self.is_connected:
            raise TDSError("Not connected")

        # Send pre-login
        pre_login_response = await self._pre_login()
        print(f"Pre-login response options: {pre_login_response}")

        login7_request = Login7SQLAuthRequest(
            username=login_cfg.username,
            password=login_cfg.password,
            appname=self._name,
            database=login_cfg.database,
        )
        # parse_login7_request_packet(login7_request.serialize())
        await self._send_packet(login7_request)

        b = await self._read_response()
        login7_response = TDSLogin7Response.deserialize(b)
        print(f"Login7 response: {login7_response}")

        # TODO: Parse login response for success/failure
        # For now, assume success if we got a response
        print(f"Login successful for user '{login_cfg.username}'")

    async def login7_windows_auth(
        self, database: str = "master",
        sspi_token: Optional[bytes] = None
    ) -> None:
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

    async def read_raw(self) -> Tuple[TDSPacketHeader, bytes]:
        """
        Read raw packet (low-level interface).

        Returns:
            Tuple of (header, data)
        """
        return await self._read_packet()
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

    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
