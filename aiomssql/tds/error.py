import struct

from aiomssql.tds.types import TokenType, EncryptionOption


class TDSError(Exception):
    """Base TDS exception"""
    pass


class TDSLoginError(TDSError):
    """Login failed exception"""
    pass


class TDSProtocolError(TDSError):
    """Protocol violation exception"""
    pass


class SSLNegotiationError(TDSError):

    def __init__(self, client_encryption: EncryptionOption, server_encryption: EncryptionOption):
        self.client_encryption = client_encryption
        self.server_encryption = server_encryption
        message = (
            f"SSL/TLS negotiation failed: Client: {client_encryption.name}, Server: {server_encryption.name}"
        )
        super().__init__(message)


class TDSResponseError(Exception):
    """
    Parse and represent SQL Server error responses from TDS tokens.
    """

    def __init__(self, response_bytes: bytes):
        self.errors = []
        self.infos = []
        self.env_changes = []
        self._parse_response(response_bytes)

        # Build the exception message
        if self.errors:
            primary_error = self.errors[0]
            message = f"SQL Server Error {primary_error['number']}: {primary_error['message']}"
            if len(self.errors) > 1:
                message += f" (and {len(self.errors) - 1} more errors)"
        else:
            message = "SQL Server returned an error response with no specific error tokens"

        super().__init__(message)

    def _parse_response(self, data: bytes):
        """Parse all tokens in the error response."""
        pos = 0

        while pos < len(data):
            if pos >= len(data):
                break

            token_type = data[pos]
            pos += 1

            if token_type == TokenType.ERROR:
                error_info, consumed = self._parse_error_info_token(data[pos:], is_error=True)
                self.errors.append(error_info)
                pos += consumed

            elif token_type == TokenType.INFO:
                info, consumed = self._parse_error_info_token(data[pos:], is_error=False)
                self.infos.append(info)
                pos += consumed

            elif token_type == TokenType.ENVCHANGE:
                env_change, consumed = self._parse_envchange_token(data[pos:])
                self.env_changes.append(env_change)
                pos += consumed

            elif token_type in (TokenType.DONE, TokenType.DONEPROC, TokenType.DONEINPROC):
                pos += 12  # Fixed size

            else:
                # Try to skip unknown token
                if pos + 2 <= len(data):
                    length = struct.unpack('<H', data[pos:pos + 2])[0]
                    pos += 2 + length
                else:
                    break

    def _parse_error_info_token(self, data: bytes, is_error: bool) -> tuple[dict, int]:
        """Parse ERROR or INFO token (same structure)."""
        pos = 0

        # Length
        length = struct.unpack('<H', data[pos:pos + 2])[0]
        pos += 2

        # Number
        number = struct.unpack('<I', data[pos:pos + 4])[0]
        pos += 4

        # State
        state = data[pos]
        pos += 1

        # Severity
        severity = data[pos]
        pos += 1

        # Message length (in characters)
        msg_len = struct.unpack('<H', data[pos:pos + 2])[0]
        pos += 2

        # Message
        message = data[pos:pos + msg_len * 2].decode('utf-16le', errors='replace')
        pos += msg_len * 2

        # Server name length
        server_len = data[pos]
        pos += 1

        # Server name
        server_name = ""
        if server_len > 0:
            server_name = data[pos:pos + server_len * 2].decode('utf-16le', errors='replace')
            pos += server_len * 2

        # Procedure name length
        proc_len = data[pos]
        pos += 1

        # Procedure name
        proc_name = ""
        if proc_len > 0:
            proc_name = data[pos:pos + proc_len * 2].decode('utf-16le', errors='replace')
            pos += proc_len * 2

        # Line number
        line_number = struct.unpack('<I', data[pos:pos + 4])[0]
        pos += 4

        return {
            'type': 'ERROR' if is_error else 'INFO',
            'number': number,
            'state': state,
            'severity': severity,
            'message': message,
            'server_name': server_name,
            'proc_name': proc_name,
            'line_number': line_number
        }, pos

    def _parse_envchange_token(self, data: bytes) -> tuple[dict, int]:
        """Parse ENVCHANGE token."""
        pos = 0

        # Length
        length = struct.unpack('<H', data[pos:pos + 2])[0]
        pos += 2

        # Type
        env_type = data[pos]
        pos += 1

        # Parse based on type (simplified - just store raw data)
        env_data = data[pos:pos + length - 1]

        return {
            'type': 'ENVCHANGE',
            'env_type': env_type,
            'data': env_data
        }, 2 + length

    def __str__(self):
        """Detailed string representation."""
        lines = []

        # Errors
        for i, error in enumerate(self.errors):
            if i == 0:
                lines.append(f"SQL Server Error {error['number']}: {error['message']}")
            else:
                lines.append(f"  Additional Error {error['number']}: {error['message']}")

            if error['severity'] > 10:
                lines.append(f"    Severity: {error['severity']}, State: {error['state']}")

            if error['proc_name']:
                lines.append(f"    Procedure: {error['proc_name']}, Line: {error['line_number']}")
            elif error['line_number'] > 0:
                lines.append(f"    Line: {error['line_number']}")

        # Info messages
        for info in self.infos:
            lines.append(f"  Info: {info['message']}")

        return '\n'.join(lines)