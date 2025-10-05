import struct

from aiomssql.tds.error import TDSProtocolError
from aiomssql.tds.types import EncryptionOption, PreLoginOptionToken, TDSVersion, TokenType
from aiomssql.util import Version


class TDSPreLoginResponse:

    def __init__(self, version: Version, encryption: EncryptionOption, mars_supported: bool):
        self.version: Version = version
        self.encryption: EncryptionOption = encryption
        self.mars_supported: bool = mars_supported

    @classmethod
    def deserialize(cls, data: bytes) -> 'TDSPreLoginResponse':
        """
        Deserialize a TDS Pre-Login response from raw bytes.

        Args:
            data: Raw byte data from the TDS Pre-Login response.

        Returns:
            TDSPreLoginResponse instance with parsed fields.
        """
        options = {}
        pos = 0

        while pos < len(data):
            # Read token
            token = data[pos]
            if token == PreLoginOptionToken.TERMINATOR:
                break

            # Read offset and length (big-endian)
            offset = struct.unpack('>H', data[pos + 1:pos + 3])[0]
            length = struct.unpack('>H', data[pos + 3:pos + 5])[0]

            # Extract the option data
            options[token] = data[offset:offset + length]
            pos += 5

        # Parse VERSION (required)
        version_data = options.get(PreLoginOptionToken.VERSION)
        if not version_data or len(version_data) < 6:
            raise TDSProtocolError("Invalid or missing VERSION in Pre-Login response")

        version = Version(
            major=version_data[0],
            minor=version_data[1],
            build=struct.unpack('>H', version_data[2:4])[0],
            sub_build=struct.unpack('>H', version_data[4:6])[0]
        )

        # Parse ENCRYPTION (required)
        encryption_data = options.get(PreLoginOptionToken.ENCRYPTION)
        if not encryption_data:
            raise TDSProtocolError("Missing ENCRYPTION in Pre-Login response")

        try:
            encryption = EncryptionOption(encryption_data[0])
        except ValueError:
            raise TDSProtocolError(f"Invalid encryption option: {encryption_data[0]}")

        # Parse MARS (optional, default to not supported)
        mars_data = options.get(PreLoginOptionToken.MARS, b'\x00')
        mars_supported = mars_data[0] == 0x01 if mars_data else False

        print(f"MARS SUPPORTED: {mars_supported}")

        return cls(
            version=version,
            encryption=encryption,
            mars_supported=mars_supported
        )

    def __str__(self) -> str:
        return (f"TDSPreLoginResponse(version={self.version}, "
                f"encryption={self.encryption.name}, "
                f"MARS supported={self.mars_supported})")

    __repr__ = __str__


class TDSLogin7Response:

    def __init__(self, tds_version: TDSVersion, version: Version, tsql: bool, server_name: str):
        self.version: Version = version
        self.tds_version: TDSVersion = tds_version
        self.server_name: str = server_name
        self.tsql: bool = tsql

    @classmethod
    def deserialize(cls, data: bytes) -> 'TDSLogin7Response':
        """
        Deserialize a TDS Login7 response from raw bytes.

        Args:
            data: Raw byte data from the TDS Login7 response.

        Returns:
            TDSLogin7Response instance with parsed fields.

        """
        pos = 0

        token_type = TokenType(data[pos])
        pos += 1
        if token_type != TokenType.LOGINACK:
            raise TDSProtocolError(f"Unexpected token type: {token_type} ({token_type.name})")
        pos += 2  # Skip length
        tsql_enabled = bool(data[pos])
        pos += 1
        tds_version = TDSVersion(struct.unpack('<I', data[pos:pos+4])[0])
        pos += 4
        prog_name_len = int(data[pos])
        pos += 1
        prog_name_utf16_byte_len = prog_name_len * 2
        bytes_ = data[pos:pos+prog_name_utf16_byte_len]
        prog_name = bytes_.decode('utf-16le', errors='ignore').strip("\x00")
        pos += prog_name_utf16_byte_len
        version = Version(
            major=data[pos],
            minor=data[pos + 1],
            build=data[pos + 2],
            sub_build=data[pos + 3]
        )  # Wtf? Why is this different?
        return cls(
            tds_version=tds_version,
            version=version,
            tsql=tsql_enabled,
            server_name=prog_name
        )

    def __str__(self) -> str:
        return (f"TDSLogin7Response(version={self.version}, "
                f"tds_version={self.tds_version.name}, "
                f"server_name='{self.server_name}', "
                f"tsql_supported={self.tsql})")

    __repr__ = __str__


class SQLBatchResponse:

    def __init__(self, affected_rows: int):
        self.affected_rows: int = affected_rows

    @classmethod
    def deserialize(cls, data: bytes) -> 'SQLBatchResponse':
        """
        Deserialize a SQL Batch response from raw bytes.

        Args:
            data: Raw byte data from the SQL Batch response.

        Returns:
            SQLBatchResponse instance with parsed fields.
        """
        if len(data) < 8:
            raise TDSProtocolError("Invalid SQL Batch response length")

        token_type = TokenType(data[0])
        if token_type != TokenType.DONE:
            raise TDSProtocolError(f"Unexpected token type: {token_type} ({token_type.name})")

        # Skip status (2 bytes) and current command (2 bytes)
        affected_rows = struct.unpack('<I', data[4:8])[0]
        return cls(affected_rows=affected_rows)

    def __str__(self) -> str:
        return f"SQLBatchResponse(affected_rows={self.affected_rows})"

    __repr__ = __str__
