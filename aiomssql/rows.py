from typing import Optional


class Row:

    def __init__(self, raw_data: Optional[bytes] = None):
        self._raw_data: Optional[bytes] = raw_data

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Row':
        return cls(data)

    @property
    def raw_data(self) -> Optional[bytes]:
        return self._raw_data
