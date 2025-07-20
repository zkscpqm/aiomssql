import asyncio
from typing import AsyncGenerator

from aiomssql.tds.error import TDSError, TDSProtocolError


class AIO:
    """Async I/O wrapper with enhanced functionality"""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self._rlock: asyncio.Lock = asyncio.Lock()
        self._wlock: asyncio.Lock = asyncio.Lock()
        self._closed: bool = False

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
                print(f"Error closing connection: {e}")
            finally:
                self.writer = None
                self.reader = None

    @property
    def is_closed(self) -> bool:
        """Check if connection is closed"""
        return self._closed