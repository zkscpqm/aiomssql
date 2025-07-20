import abc
import struct
from collections import namedtuple
from typing import Optional

from aiomssql.tds.types import TDSPacketType, TDSStatus


ByteData = namedtuple('ByteData', ['offset', 'length'])


class TDSPacket(abc.ABC):
    """
    Generic byte builder for TDS protocol communication.
    Handles primitive data types, byte ordering, and encoding.
    """

    TDS_VERSION = 0x74000004  # Default TDS version (TDS 7.4)

    def __init__(self, packet_type: TDSPacketType, prepare: bool = True):
        """
        Initialize a new TDS ByteBuilder.

        Args:
            packet_type: Optional TDS packet type for automatic header creation
        """
        self._header: Optional[bytes] = None
        self._data = bytearray()
        self.packet_type = packet_type

        # TDS-specific defaults
        self.default_encoding: str = 'utf-16le'
        if prepare:
            self.prepare()

    @abc.abstractmethod
    def prepare(self):
        raise NotImplemented

    @classmethod
    def set_tds_version(cls, version: int):
        """
        Set the TDS version for this packet type.
        This is used to determine how to serialize certain fields.

        Args:
            version: TDS version as an integer (e.g., 0x74000004 for TDS 7.4)
        """
        cls.TDS_VERSION = version & 0xFFFFFFFF  # Ensure it's a 32-bit value

    def _set_header(self, status: TDSStatus = TDSStatus.EOM, spid: int = 0, packet_id: int = 1):
        """
        Finalize TDS header with actual packet length.
        Must be called after all data is added.

        Args:
            status: TDS packet status flags
            spid: Server process ID
            packet_id: Packet ID in message
        """
        header = bytearray()
        header.extend(struct.pack('<B', self.packet_type))
        header.extend(struct.pack('<B', status))
        header.extend(struct.pack('>H', len(self._data) + 8))  # Big-endian!
        header.extend(struct.pack('>H', spid))  # Big-endian!
        header.extend(struct.pack('<B', packet_id))
        header.extend(struct.pack('<B', 0))  # Window (unused)
        self._header = bytes(header)

    def write(self, b: bytes) -> ByteData:
        """Write raw bytes and return offset and length"""
        offset = len(self._data)
        self._data.extend(b)
        return ByteData(offset, len(b))
    
    def write_at(self, position: int, b: bytes) -> ByteData:
        """
        Write raw bytes at specific position.
        Returns offset and length of written data.
        """
        if position < 0 or position > len(self._data):
            raise ValueError("Position out of bounds")
        offset = position
        self._data[offset:offset + len(b)] = b
        return ByteData(offset, len(b))
    
    def write_uint8(self, value: int) -> ByteData:
        """Write unsigned 8-bit integer"""
        return self.write(struct.pack('<B', value & 0xFF))

    def write_int8(self, value: int) -> ByteData:
        """Write signed 8-bit integer"""
        return self.write(struct.pack('<b', value))

    def write_uint16(self, value: int, byte_order: str = '<') -> ByteData:
        """Write unsigned 16-bit integer"""
        value &= 0xFFFF
        return self.write(struct.pack(f'{byte_order}H', value))

    def write_int16(self, value: int, byte_order: str = '<') -> ByteData:
        """Write signed 16-bit integer"""
        return self.write(struct.pack(f'{byte_order}h', value))

    def write_uint32(self, value: int, byte_order: str = '<') -> ByteData:
        """Write unsigned 32-bit integer"""
        return self.write(struct.pack(f'{byte_order}I', value & 0xFFFFFFFF))

    def write_int32(self, value: int, byte_order: str = '<') -> ByteData:
        """Write signed 32-bit integer"""
        return self.write(struct.pack(f'{byte_order}i', value))

    def write_uint64(self, value: int, byte_order: str = '<') -> ByteData:
        """Write unsigned 64-bit integer"""
        return self.write(struct.pack(f'{byte_order}Q', value & 0xFFFFFFFFFFFFFFFF))

    def write_int64(self, value: int, byte_order: str = '<') -> ByteData:
        """Write signed 64-bit integer"""
        return self.write(struct.pack(f'{byte_order}q', value))

    def write_float(self, value: float) -> ByteData:
        """Write 32-bit float"""
        return self.write(struct.pack('<f', value))

    def write_double(self, value: float) -> ByteData:
        """Write 64-bit double"""
        return self.write(struct.pack('<d', value))

    def write_bytes(self, data: bytes) -> ByteData:
        """Write raw bytes"""
        return self.write(data)

    def write_utf16le_string(self, text: str) -> ByteData:
        """
        Write UTF-16LE encoded string
        """
        return self.write_string(text, encoding='utf-16le')

    def write_string(self, text: str, encoding: str = None) -> ByteData:
        """
        Write string with specified or default encoding.
        Does NOT include length prefix.
        """
        enc = encoding or self.default_encoding
        return self.write(text.encode(enc))

    def write_varchar(self, text: Optional[str], encoding: Optional[str] = None) -> ByteData:
        """
        Write length-prefixed string (2-byte length prefix).
        Length is in characters for UTF-16, bytes for UTF-8/ASCII.
        """
        if text is None or text == '':
            return self.write_uint16(0)
        else:
            enc = encoding or self.default_encoding
            encoded = text.encode(enc)
            # For UTF-16 encodings, length is in characters
            if enc.lower().startswith('utf-16'):
                data = self.write_uint16(len(encoded) // 2)
            else:
                data = self.write_uint16(len(encoded))
            offset, written = self.write(encoded)
        return ByteData(
            offset=offset,
            length=data.length + written
        )

    def serialize(self, status: TDSStatus = TDSStatus.EOM, spid: int = 0, packet_id: int = 1) -> bytes:
        """Build final byte array, finalizing header if needed"""
        self._set_header(status, spid, packet_id)
        return self._header + bytes(self._data)

    def get_data_copy(self) -> bytearray:
        """Get a copy of current buffer (for debugging)"""
        return self._data.copy()

    def increment_value_at(self, position: int, size: int, delta: int):
        """
        Increment a value at a specific position in the data buffer.

        Args:
            position: Position in the buffer to modify
            size: Size of the value (1, 2, 4, or 8 bytes)
            delta: Amount to increment the value by
        """
        if position < 0 or position + size > len(self._data):
            raise ValueError("Position out of bounds")

        # Read current value
        if size == 1:
            fmt = '<B'
        elif size == 2:
            fmt = '<H'
        elif size == 4:
            fmt = '<I'
        elif size == 8:
            fmt = '<Q'
        else:
            raise ValueError("Invalid size for increment")

        current_value = struct.unpack_from(fmt, self._data, position)[0]

        # Increment and write back
        new_value = current_value + delta
        struct.pack_into(fmt, self._data, position, new_value)

    def increment_offsets(self, offset_indexes: list[int], delta: int):
        """
        Increment multiple offsets in the data buffer by a delta value.

        Args:
            offset_indexes: List of offsets to increment
            delta: Amount to increment each offset by
        """
        for offset_index in offset_indexes:
            self.increment_value_at(offset_index, 2, delta)

    def length(self, include_tds_header: bool = True) -> int:
        return len(self._data) + (int(include_tds_header) * 8)

    def __repr__(self) -> str:
        """String representation"""
        return f"TDSByteBuilder(type={self.packet_type}, length={len(self._data)})"

