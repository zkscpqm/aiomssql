import os
import socket
import struct
from typing import Optional

from aiomssql.tds.packet import TDSPacket
from aiomssql.tds.types import TDSPacketType, OptionFlags1, OptionFlags2, TypeFlags, OptionFlags3, Timezone, ClientLCID, \
    EncryptionOption, PreLoginOptionToken
from aiomssql.util import VERSION, AIOMSSQL


class PreLoginRequest(TDSPacket):

    def __init__(
        self,
        encryption: EncryptionOption = EncryptionOption.NOT_SUPPORTED,
        named_instance: bool = False,
        mars_enabled: bool = False
    ):
        """
        Pre-login packet for SQL Server.

        :param encryption: Encryption option for the connection. Default is NOT_SUPPORTED.
        :param named_instance: Whether to connect to a named instance (default is False). Alternative not supported yet.
        :param mars_enabled: Whether to enable MARS (Multiple Active Result Sets). Default is False.

        The packet is defined as:

        - TDS Header: (8 bytes) # See TDSPacket for more details.
        - Pre-login option definitions (Option Type + Option Data Length): TODO: Support all options
            - Version(0x00) (len = 6)
            - Encryption(0x01) (len = 1)
            - Instance(0x02) (len = 1)
            - Thread ID(0x03) (len = 4)
            - MARS (0x04) (len = 1)
        - Terminator (0xFF) (1 byte)

        - Version: This refers to the client/driver version and it can be anything. Can even be all 0s.
            - Major (1 byte)
            - Minor (1 byte)
            - Build (2 bytes) # This is called "patch" in modern version naming
            - Sub Build (2 bytes)  # Not used in modern versions, always 0 for us

        - Encryption (1 byte)  # See EncryptionOption, currently only NOT_SUPPORTED)  # TODO: Support encryption
        - Named Instance (1 byte, 0 = no, 1 = yes)  # See below for more info
        - Thread ID (4 bytes)  # This is the process ID of the client as you would see in the OS.
        - MARS (1 byte, 0 = no, 1 = yes)  # Multiple Active Result Sets support. See below for more info

        -----------------------------------
        Named Instance (NOT SUPPORTED YET):
        Instance refers to SQL Server's ability to run multiple independent database engines on the same machine.

        Default Instance:
         - Listens on port 1433
         - Connect using just the hostname: server.example.com
         - Only ONE default instance per machine

        Named Instance:
         - Listen on dynamic ports (assigned at startup)
         - Connect using: server.example.com\SQLEXPRESS or server.example.com\DEV
         - Can have multiple named instances on one machine

        In the Pre-Login packet:

        When connecting to a named instance, you first need to:

         - Connect to SQL Server Browser service (UDP port 1434)
         - Ask "What port is instance 'SQLEXPRESS' running on?"
         - Get the actual port number
         - Connect to that port
        ------------------------------------
        MARS (Multiple Active Result Sets):
        MARS allows multiple queries to be active on a single connection simultaneously.

        Without MARS (Default):
        ```
            # This would fail:
            result1 = await conn.execute("SELECT * FROM Users")
            # Can't run another query while result1 is still open!
            result2 = await conn.execute("SELECT * FROM Orders")  # ERROR!

            # Must fully consume result1 first:
            users = await result1.fetch_all()
            # Now we can run another query
            result2 = await conn.execute("SELECT * FROM Orders")  # OK
        ```

        With MARS:
        ```
            # Both queries can be active at once:
            result1 = await conn.execute("SELECT * FROM Users")
            result2 = await conn.execute("SELECT * FROM Orders")  # OK!

            # Can interleave reading from both
            user = await result1.fetch_one()
            order = await result2.fetch_one()
        ```

        Important MARS limitations:

         - Not truly parallel - SQL Server still processes one statement at a time
         - Transaction complexity - All active requests share the same transaction
         - Performance overhead - Additional packet headers and coordination
         - Connection pooling issues - MARS connections can't always be reused
        """
        self._encryption: EncryptionOption = encryption
        self._named_instance: bool = named_instance
        self._mars_enabled: bool = mars_enabled
        super().__init__(TDSPacketType.PRELOGIN)

    def prepare(self):
        options = [
            (PreLoginOptionToken.VERSION, 6),  # 6 bytes for version
            (PreLoginOptionToken.ENCRYPTION, 1),  # 1 byte for encryption
            (PreLoginOptionToken.INSTOPT, 1),  # 1 byte for instance
            (PreLoginOptionToken.THREADID, 4),  # 4 bytes for thread ID
            (PreLoginOptionToken.MARS, 1),  # 1 byte for MARS
        ]

        option_definitions_offset = len(options) * 5 + 1  # X options * 5 bytes each + terminator

        offset = option_definitions_offset
        for token, length in options:
            self.write_uint8(token)
            self.write_uint16(offset, '>')  # Big-endian offset
            self.write_uint16(length, '>')  # Big-endian length
            offset += length
        self.write_uint8(PreLoginOptionToken.TERMINATOR)

        self.write_uint8(VERSION.major)
        self.write_uint8(VERSION.minor)
        self.write_uint16(VERSION.build, '>')  # Build number
        self.write_uint16(VERSION.sub_build, '>')  # Sub-build (not used)

        self.write_uint8(self._encryption.value)
        self.write_uint8(int(self._named_instance))
        self.write_uint32(os.getpid() % 0xFFFFFFFF)  # Thread ID
        self.write_uint8(int(self._mars_enabled))  # MARS enabled


class Login7SQLAuthRequest(TDSPacket):

    def __init__(
        self,
        username: str,
        password: str,
        hostname: str = socket.gethostname()[:128],
        appname: str = 'unnamed_app',
        server_name: str = '',
        database: str = 'master',
        option_flags1: OptionFlags1 = OptionFlags1.DEFAULT,
        option_flags2: OptionFlags2 = OptionFlags2.ODBC_ON,
        type_flags: TypeFlags = TypeFlags.SQL_DEFAULT,
        option_flags3: OptionFlags3 = 0x0,
        client_tz: Timezone = Timezone.UTC,
        client_lcid: ClientLCID = ClientLCID.ENGLISH_US,
        language: str = "",  # This is the language used by the server (independent of LCID), leave blank
    ):
        self.default_encoding = 'utf-16le'  # Default encoding for TDS protocol and Login7
        self._username: bytes = username.encode(self.default_encoding)
        self._encrypted_password: bytes = self._encrypt_password(password)
        self._hostname: bytes = hostname.encode(self.default_encoding)
        self._appname: bytes = appname.encode(self.default_encoding)
        self._server_name: bytes = server_name.encode(self.default_encoding)
        self._database: bytes = database.encode(self.default_encoding)
        self._len_offset: Optional[int] = None
        self._option_flags1: OptionFlags1 = option_flags1
        self._option_flags2: OptionFlags2 = option_flags2
        self._type_flags: TypeFlags = type_flags
        self._option_flags3: OptionFlags3 = option_flags3
        self._client_tz: Timezone = client_tz
        self._client_lcid: ClientLCID = client_lcid
        self._language: bytes = language.encode(self.default_encoding)
        super().__init__(packet_type=TDSPacketType.LOGIN7)

    def prepare(self):
        self._write_fixed_fields()
        self._write_variable_offset_length_metadata()
        self._write_variable_data()
        self._set_length()

    def _set_length(self):
        """
        Set the total length of the packet in the fixed-length fields.
        This must be called after all data is written.
        """
        if self._len_offset is None:
            raise ValueError("Length offset not set. Call _write_fixed_fields() first.")
        struct.pack_into('<I', self._data, self._len_offset, len(self._data))

    def _write_fixed_fields(self):
        len_data = self.write_uint32(0)
        self._len_offset = len_data.offset
        self.write_uint32(self.TDS_VERSION)
        self.write_uint32(4096)  # Default login packet size. Can be adjusted later.
        self.write_uint32(VERSION.to_uint32())  # Client program version
        self.write_uint32(os.getpid() % 0xFFFFFFFF)  # Client PID
        self.write_uint32(0)  # Connection ID

        self.write_uint8(self._option_flags1)
        self.write_uint8(self._option_flags2)
        self.write_uint8(self._type_flags)
        self.write_uint8(self._option_flags3)
        self.write_int32(self._client_tz)
        self.write_uint32(self._client_lcid)

    def _write_variable_offset_length_metadata(self):
        offset = 0
        offset_indices = []
        for field in (
            self._hostname, self._username, self._encrypted_password, self._appname,
            self._server_name, b"", AIOMSSQL.encode(self.default_encoding), self._language, self._database
        ):
            offset_data = self.write_uint16(offset)
            self.write_uint16(len(field) // 2)  # Length in UTF-16 characters, NOT BYTES
            offset += len(field)
            offset_indices.append(offset_data.offset)
        self._write_additional_offset_length_metadata()
        self.increment_offsets(offset_indices, len(self._data))

    def _write_additional_offset_length_metadata(self):
        self.write_bytes(b"\x00"*6)  # Client ID placeholder (6 bytes)

        self.write_uint16(0)  # SSPI placeholder - For Windows auth (2 bytes each)
        self.write_uint16(0)

        self.write_uint16(0)  # Attach DB file placeholder (2 bytes each)
        self.write_uint16(0)

        self.write_uint16(0)  # Change password fields. 0 on-login (2 bytes each)
        self.write_uint16(0)

        self.write_uint32(0)  # SSPI long placeholder (4 bytes)

    def _write_variable_data(self):
        self.write_bytes(self._hostname)
        self.write_bytes(self._username)
        self.write_bytes(self._encrypted_password)
        self.write_bytes(self._appname)
        self.write_bytes(self._server_name)
        self.write_utf16le_string(AIOMSSQL)
        self.write_bytes(self._language)
        self.write_bytes(self._database)

    @staticmethod
    def _encrypt_password(password: str) -> bytes:
        """Encrypt password using SQL Server Login7 algorithm"""
        return bytes((((b << 4) | (b >> 4)) ^ 0xA5) & 0xFF for b in password.encode('utf-16le'))


