import asyncio
import json
import ssl
import subprocess
from typing import Any

from aiomssql.tds.types import OptionFlags1, OptionFlags2, TypeFlags, OptionFlags3, TDSPacketType, \
    TDSStatus, PreLoginOptionToken
from aiomssql.util import Version


def _chop(data: bytes, length: int) -> tuple[bytes, bytes]:
    if length < 0 or length > len(data):
        raise ValueError("Length must be non-negative and less than or equal to the length of data")
    return data[:length], data[length:]


def hexdump(data: bytes, name: str = "hex-dump", offset: int = 0, length: int = None, width: int = 16):
    """
    Generate a hexdump of the given bytes.

    Args:
        data: Bytes to dump
        name: Name of the data being dumped (for context)
        offset: Starting offset (default 0)
        length: Number of bytes to dump (default to all)
        width: Bytes per line (default 16)
    """
    if length is None:
        length = len(data) - offset

    data = data[offset:offset + length]

    # Max possible printed width
    header_footer_len = 8 + 3 * width + 2  # 8 for offset, 3 for each byte, and 2 for the ASCII bar
    name += f' ({length} bytes)'
    if len(name) > header_footer_len:
        name = name[:header_footer_len - 3] + '...'
    side_len = (header_footer_len - len(name)) // 2
    print("-" * side_len + name + "-" * (header_footer_len - len(name) - side_len))
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        # Hex portion
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        # ASCII portion
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        # Format with 8-digit offset, hex, and ASCII
        print(f'{i + offset:08X}  {hex_str.ljust(width * 3)}  |{ascii_str}|')


def parse_tds_header(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        raise ValueError("Data too short to contain TDS header")
    header = data[:8]
    packet_type = header[0]
    status = header[1]
    length = int.from_bytes(header[2:4], 'big')
    spid = int.from_bytes(header[4:6], 'big')
    packet_id = header[6]
    window = header[7]
    return {
        'packet_type': f"{TDSPacketType(packet_type).name} (0x{packet_type:02X})",
        'status': f"{TDSStatus(status).name} (0x{status:02X})",
        'length': length,
        'spid': spid,
        'packet_id': packet_id,
        'window': window
    }


def parse_pre_login_request(data: bytes, show: bool = True) -> dict[str, Any]:
    
    if show:
        hexdump(data, name="TDS Pre-Login Request Packet")
    
    if len(data) < 8:
        raise ValueError("Data too short to contain Pre-Login request")

    rv: dict[str, Any] = {
        ".header": parse_tds_header(data[:8]),
    }
    body = data[8:]
    token_metadata = {}
    n_options = 5
    frame_size = 5
    for i in range(n_options):
        slc = body[i * frame_size:(i + 1) * frame_size]
        token = PreLoginOptionToken(slc[0])
        offset = int.from_bytes(slc[1:3], 'big')
        length = int.from_bytes(slc[3:5], 'big')
        token_metadata[token.name] = {
            'token_value': f"0x{token.value:02X}",
            'offset': offset,
            'length': length,
            'raw_data': str(body[offset:offset + length])
        }
    rv['tokens'] = token_metadata
    if show:
        print(f"\n=== Pre-Login Request ===\n{json.dumps(rv, indent=4)}")
    return rv


def parse_login7_request_packet(data: bytes, show: bool = True):
    """Parse a TDS Login7 request packet and print its contents."""
    
    if show:
        hexdump(data, name="TDS Login7 Request Packet")

    if len(data) < 8:
        print("Packet too short to contain Login7 data")
        return

    rv: dict[str, Any] = {
        ".header": parse_tds_header(data[:8]),
    }

    body = data[8:]

    fixed_length_fields, rem = _chop(body, 36)
    offset_length_metadata, rem = _chop(rem, 36)
    additional_fixed_fields, variables = _chop(rem, 22)

    if show:
        hexdump(fixed_length_fields, name="Fixed Length Fields")
        hexdump(offset_length_metadata, name="Offset/Length Variable Metadata")
        hexdump(additional_fixed_fields, name="Zero-fields")
        hexdump(variables, name="Variables")

    rdi32le = lambda byte_data, idx, signed=False: int.from_bytes(byte_data[idx:idx + 4], 'little', signed=signed)

    i = 0
    rv["length"] = rdi32le(fixed_length_fields, i)
    i += 4
    rv["tds_version"] = hex(rdi32le(fixed_length_fields, i))
    i += 4
    rv["packet_size"] = rdi32le(fixed_length_fields, i)
    i += 4
    rv["client_prog_ver"] = str(Version.from_uint32(rdi32le(fixed_length_fields, i)))
    i += 4
    rv["client_pid"] = rdi32le(fixed_length_fields, i)
    i += 4
    rv["connection_id"] = rdi32le(fixed_length_fields, i)
    i += 4
    rv["option_flags1"] = str(OptionFlags1(fixed_length_fields[i]))
    i += 1
    rv["option_flags2"] = str(OptionFlags2(fixed_length_fields[i]))
    i += 1
    rv["type_flags"] = str(TypeFlags(fixed_length_fields[i]))
    i += 1
    rv["option_flags3"] = str(OptionFlags3(fixed_length_fields[i]))
    i += 1
    rv["client_time_zone"] = rdi32le(fixed_length_fields, i, signed=True)
    i += 4
    rv["client_lcid"] = hex(rdi32le(fixed_length_fields, i))
    assert i+4 == len(fixed_length_fields), "Fixed-length fields parsing error"

    def _extract_var(i_: int) -> dict[str, Any]:
        offset = int.from_bytes(offset_length_metadata[i_:i_ + 2], 'little')
        length = int.from_bytes(offset_length_metadata[i_ + 2:i_ + 4], 'little')

        if length == 0:
            return {
                "offset": offset,
                "length": length,
                "raw_data": None,
                "value": None
            }
        value_bytes = body[offset:offset + length]
        return {
            "offset": offset,
            "length": length,
            "raw_data": str(value_bytes),
            "value": value_bytes.decode('utf-16le', errors='replace')
        }

    for i, field in enumerate([
        "hostname", "username", "password", "appname",
        "server_name", "extension", "clt_int_name", "language",
        "database"
    ]):
        rv[field] = _extract_var(i * 4)

    rv["additional_fixed_fields"] = str(additional_fixed_fields)

    if show:
        print(f"\n=== Login7 Request ===\n{json.dumps(rv, indent=4)}")
    return rv


def _create_ssl_context() -> ssl.SSLContext:
    """Create SQL Server-compatible SSL context"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Mandatory protocol settings
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Approved cipher suites
    ctx.set_ciphers(
        'ECDHE-ECDSA-AES256-GCM-SHA384:'
        'ECDHE-RSA-AES256-GCM-SHA384:'
        'ECDHE-ECDSA-AES128-GCM-SHA256:'
        'ECDHE-RSA-AES128-GCM-SHA256'
    )

    # Certificate verification
    ctx.load_default_certs()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    return ctx


async def test_tls_handshake(host: str = 'localhost', port: int = 1433):
    """Standalone TLS verification"""
    ctx = _create_ssl_context()
    try:
        reader, writer = await asyncio.open_connection(
            host, port,
            ssl=ctx,
            server_hostname=host
        )

        # Verify negotiated protocol
        ssl_info = writer.get_extra_info('ssl_object')
        print(f"Negotiated: {ssl_info.version()}, Cipher: {ssl_info.cipher()}")

        writer.close()
        await writer.wait_closed()
        return True
    except Exception as e:
        print(f"TLS test failed: {type(e).__name__}: {e}")
        return False


async def test_sql_server_cert():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.open_connection(
            'localhost', 1433,
            ssl=ctx,
            server_hostname='localhost'
        )
        cert = writer.get_extra_info('ssl_object').getpeercert()
        print(f"Server certificate: {cert['subject']}")
        writer.close()
        return True
    except Exception as e:
        print(f"No certificate detected: {e}")
        return False


def get_sql_server_encryption_data():
    reg = r'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib'
    rv = {}
    for key in ['ForceEncryption', 'Certificate']:
        try:
            out = subprocess.check_output(['powershell', '-Command', f'(Get-ItemProperty -Path "{reg}" -Name "{key}")']).decode()
            value = "UNSET"
            for line in out.splitlines():
                if line.startswith(key):
                    value = line.split(':')[1].strip()
                    if value.isdigit():
                        value = int(value)
            rv[key] = value
        except subprocess.CalledProcessError:
            rv[key] = None
    return rv
