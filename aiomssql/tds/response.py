import struct
from typing import Optional

from aiomssql.tds.error import TDSProtocolError
from aiomssql.tds.types import EncryptionOption, PreLoginOptionToken, OptionFlags3, TypeFlags, OptionFlags2, \
    OptionFlags1, TDSVersion
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

    def __init__(self,
                 version: Version,
                 tds_version: TDSVersion,
                 packet_size: int,
                 client_prog_ver: int,
                 option_flags1: OptionFlags1,
                 option_flags2: OptionFlags2,
                 type_flags: TypeFlags,
                 option_flags3: OptionFlags3,
                 client_time_zone: int,
                 client_lcid: int,
                 hostname: Optional[str] = None,
                 username: Optional[str] = None,
                 appname: Optional[str] = None,
                 server_name: Optional[str] = None,
                 database: Optional[str] = None):
        self.version = version
        self.tds_version = tds_version
        self.packet_size = packet_size
        self.client_prog_ver = client_prog_ver
        self.option_flags1 = option_flags1
        self.option_flags2 = option_flags2
        self.type_flags = type_flags
        self.option_flags3 = option_flags3
        self.client_time_zone = client_time_zone
        self.client_lcid = client_lcid
        self.hostname = hostname
        self.username = username
        self.appname = appname
        self.server_name = server_name
        self.database = database

    @classmethod
    def deserialize(cls, data: bytes) -> 'TDSLogin7Response':
        """
        Deserialize a TDS Login7 response from raw bytes.

        Args:
            data: Raw byte data from the TDS Login7 response.

        Returns:
            TDSLogin7Response instance with parsed fields.
        """
        if len(data) < 32:  # Minimum size for fixed-length fields
            raise TDSProtocolError("Login7 response too short")

        pos = 0

        # Parse fixed-length fields
        length = int.from_bytes(data[pos:pos+4], 'little')
        pos += 4

        tds_version = TDSVersion(int.from_bytes(data[pos:pos+4], 'little'))
        pos += 4

        packet_size = int.from_bytes(data[pos:pos+4], 'little')
        pos += 4

        client_prog_ver = int.from_bytes(data[pos:pos+4], 'little')
        pos += 4

        # Skip client PID (4 bytes) and connection ID (4 bytes)
        pos += 8

        option_flags1 = OptionFlags1(data[pos])
        pos += 1

        option_flags2 = OptionFlags2(data[pos])
        pos += 1

        type_flags = TypeFlags(data[pos])
        pos += 1

        option_flags3 = OptionFlags3(data[pos])
        pos += 1

        client_time_zone = int.from_bytes(data[pos:pos+4], 'little', signed=True)
        pos += 4

        client_lcid = int.from_bytes(data[pos:pos+4], 'little')
        pos += 4

        # Parse variable-length fields offsets
        offsets_start = pos
        variable_fields = {}

        # List of all possible variable fields in order
        field_names = [
            'hostname', 'username', 'password', 'appname',
            'server_name', 'extension', 'clt_int_name', 'language',
            'database', 'client_id', 'sspi', 'atch_db_file',
            'change_password', 'extension_end'
        ]

        for field_name in field_names:
            if pos + 4 > len(data):
                break

            offset = int.from_bytes(data[pos:pos+2], 'little')
            length = int.from_bytes(data[pos+2:pos+4], 'little')
            pos += 4

            if offset > 0 and length > 0:
                # Variable data starts at offset 0x60 from start of Login7 message
                var_data_start = offsets_start + 2 * 18 * 2  # 18 fields * (offset+length)
                field_start = var_data_start + (offset - 0x60)
                field_end = field_start + length

                if field_end <= len(data):
                    try:
                        variable_fields[field_name] = data[field_start:field_end].decode('utf-16le')
                    except UnicodeDecodeError:
                        variable_fields[field_name] = None

        # Create version object (not present in Login7 response, using TDS version)
        version = Version(
            major=(tds_version.value >> 24) & 0xFF,
            minor=(tds_version.value >> 16) & 0xFF,
            build=(tds_version.value >> 8) & 0xFF,
            sub_build=tds_version.value & 0xFF
        )

        return cls(
            version=version,
            tds_version=tds_version,
            packet_size=packet_size,
            client_prog_ver=client_prog_ver,
            option_flags1=option_flags1,
            option_flags2=option_flags2,
            type_flags=type_flags,
            option_flags3=option_flags3,
            client_time_zone=client_time_zone,
            client_lcid=client_lcid,
            hostname=variable_fields.get('hostname'),
            username=variable_fields.get('username'),
            appname=variable_fields.get('appname'),
            server_name=variable_fields.get('server_name'),
            database=variable_fields.get('database')
        )

    def __str__(self) -> str:
        return (f"TDSLogin7Response(version={self.version}, "
                f"tds_version={self.tds_version.name}, "
                f"packet_size={self.packet_size}, "
                f"client_prog_ver=0x{self.client_prog_ver:08X}, "
                f"hostname={self.hostname!r}, "
                f"username={self.username!r}, "
                f"database={self.database!r})")

    __repr__ = __str__
