from enum import IntEnum, IntFlag
from typing import Union


class TDSPacketType(IntEnum):
    """TDS Packet Types"""
    SQL_BATCH = 0x01
    PRE_TDS7_LOGIN = 0x02
    RPC = 0x03
    TABULAR_RESULT = 0x04
    ATTENTION = 0x06
    BULK_LOAD = 0x07
    FEDAUTH_TOKEN = 0x08
    TRANSACTION_MANAGER = 0x0E
    LOGIN7 = 0x10
    SSPI = 0x11
    PRELOGIN = 0x12


class TDSStatus(IntFlag):
    """TDS Packet Status Flags"""
    NORMAL = 0x00
    EOM = 0x01  # End of Message
    IGNORE = 0x02
    RESET_CONNECTION = 0x08
    RESET_CONNECTION_SKIP_TRAN = 0x10


class TDSVersion(IntEnum):
    """Common TDS Versions"""
    TDS_70 = 0x00000070
    TDS_71 = 0x01000071
    TDS_72 = 0x02000072
    TDS_73 = 0x03000073
    TDS_74 = 0x04000074
    TDS_80 = 0x05000080

    TDS_7X = 0x00000070  # Alias for TDS 7.x
    TDS_8X = 0x00000080  # Alias for TDS 8.x


class OptionFlags1(IntFlag):
    """Login7 Option Flags 1 (LSB order)"""
    BYTE_ORDER_X86 = 0x00  # Little-endian (x86)
    BYTE_ORDER_68000 = 0x01  # Big-endian (Motorola 68000)

    CHAR_ASCII = 0x00  # ASCII charset
    CHAR_EBCDIC = 0x02  # EBCDIC charset

    FLOAT_IEEE_754 = 0x00  # IEEE 754 floats
    FLOAT_VAX = 0x04  # VAX floats
    FLOAT_ND5000 = 0x08  # ND5000 floats

    DUMPLOAD_OFF = 0x10  # 1=No BCP/dump capability needed
    USE_DB_ON = 0x20  # 1=Warn on database change
    INIT_DB_FATAL = 0x40  # 1=DB change must succeed
    SET_LANG_ON = 0x80  # 1=Warn on language change

    # Helpers for common combinations
    DEFAULT = BYTE_ORDER_X86 | CHAR_ASCII | FLOAT_IEEE_754


class OptionFlags2(IntFlag):
    """Login7 Option Flags 2 (LSB order)"""
    INIT_LANG_FATAL = 0x01  # 1=Language change must succeed
    ODBC_ON = 0x02  # 1=ODBC client
    TRAN_BOUNDARY = 0x04  # Transaction boundary support
    CACHE_CONNECT = 0x08  # Connection caching

    # User types (mutually exclusive)
    USER_NORMAL = 0x00  # Regular login
    USER_SERVER = 0x10  # Reserved
    USER_REMOTE = 0x20  # Distributed query login
    USER_SQLREPL = 0x30  # Replication login

    INTEGRATED_SECURITY_ON = 0x80  # 1=Windows auth


class TypeFlags(IntFlag):
    """Login7 Type Flags (LSB order)"""
    SQL_DEFAULT = 0x00  # Default SQL dialect
    SQL_TSQL = 0x01  # T-SQL dialect
    OLEDB_ON = 0x10  # 1=OLEDB client
    READ_ONLY_INTENT = 0x20  # 1=Read-only connection intent


class OptionFlags3(IntFlag):
    """Login7 Option Flags 3 - Advanced features (LSB order)"""
    CHANGE_PASSWORD = 0x01  # 1=Password change requested
    SEND_YUKON_BINARY_XML = 0x02  # 1=Supports binary XML
    USER_INSTANCE = 0x04  # 1=Request user instance
    UNKNOWN_COLLATION = 0x08  # 1=Handle unknown collations
    EXTENSION = 0x10  # 1=Extension block present


class PreLoginOptionToken(IntEnum):
    """Pre-login option tokens"""
    VERSION = 0x00
    ENCRYPTION = 0x01
    INSTOPT = 0x02
    THREADID = 0x03
    MARS = 0x04
    TRACEID = 0x05
    FEDAUTHREQUIRED = 0x06
    NONCEOPT = 0x07
    TERMINATOR = 0xFF


class EncryptionOption(IntEnum):
    """Encryption options for pre-login"""
    OFF = 0b00
    ON = 0b01
    NOT_SUPPORTED = 0b10
    REQUIRED = 0b11


class ClientLCID(IntEnum):
    """Common Windows Locale IDs (LCID) for SQL Server"""
    # English
    ENGLISH_US = 0x0409  # en-US (default)
    ENGLISH_UK = 0x0809  # en-GB
    ENGLISH_AU = 0x0C09  # en-AU
    ENGLISH_CA = 0x1009  # en-CA

    # Spanish
    SPANISH_ES = 0x0C0A  # es-ES (Spain)
    SPANISH_MX = 0x080A  # es-MX (Mexico)
    SPANISH_AR = 0x2C0A  # es-AR (Argentina)

    # French
    FRENCH_FR = 0x040C  # fr-FR (France)
    FRENCH_CA = 0x0C0C  # fr-CA (Canada)
    FRENCH_BE = 0x080C  # fr-BE (Belgium)

    # German
    GERMAN_DE = 0x0407  # de-DE (Germany)
    GERMAN_AT = 0x0C07  # de-AT (Austria)
    GERMAN_CH = 0x0807  # de-CH (Switzerland)

    # Italian
    ITALIAN_IT = 0x0410  # it-IT (Italy)
    ITALIAN_CH = 0x0810  # it-CH (Switzerland)

    # Portuguese
    PORTUGUESE_BR = 0x0416  # pt-BR (Brazil)
    PORTUGUESE_PT = 0x0816  # pt-PT (Portugal)

    # Asian languages
    CHINESE_CN = 0x0804  # zh-CN (Simplified, PRC)
    CHINESE_TW = 0x0404  # zh-TW (Traditional, Taiwan)
    CHINESE_HK = 0x0C04  # zh-HK (Hong Kong)
    JAPANESE = 0x0411  # ja-JP
    KOREAN = 0x0412  # ko-KR

    # Other European
    DUTCH_NL = 0x0413  # nl-NL (Netherlands)
    DUTCH_BE = 0x0813  # nl-BE (Belgium)
    RUSSIAN = 0x0419  # ru-RU
    POLISH = 0x0415  # pl-PL
    SWEDISH = 0x041D  # sv-SE
    NORWEGIAN_NO = 0x0414  # nb-NO (Bokmål)
    DANISH = 0x0406  # da-DK
    FINNISH = 0x040B  # fi-FI

    # Middle East
    ARABIC_SA = 0x0401  # ar-SA (Saudi Arabia)
    HEBREW = 0x040D  # he-IL
    TURKISH = 0x041F  # tr-TR

    # Other
    GREEK = 0x0408  # el-GR
    HUNGARIAN = 0x040E  # hu-HU
    CZECH = 0x0405  # cs-CZ
    THAI = 0x041E  # th-TH
    HINDI = 0x0439  # hi-IN

    # Neutral/Invariant
    INVARIANT = 0x007F  # Invariant culture


class TokenType(IntEnum):
    """TDS Token Types"""
    # Data tokens
    ALTMETADATA = 0x88
    ALTROW = 0xD3
    COLMETADATA = 0x81
    COLINFO = 0xA5
    DONE = 0xFD
    DONEINPROC = 0xFF
    DONEPROC = 0xFE
    ENVCHANGE = 0xE3
    ERROR = 0xAA
    FEATUREEXTACK = 0xAE
    FEDAUTHINFO = 0xEE
    INFO = 0xAB
    LOGINACK = 0xAD
    NBCROW = 0xD2
    OFFSET = 0x78
    ORDER = 0xA9
    RETURNSTATUS = 0x79
    RETURNVALUE = 0xAC
    ROW = 0xD1
    SESSIONSTATE = 0xE4
    SSPI = 0xED
    TABNAME = 0xA4
    TVPROW = 0x01


class Timezone(IntEnum):
    """
    Common timezone offsets in minutes from UTC.
    Positive = east of UTC, Negative = west of UTC
    """
    # UTC
    UTC = 0
    GMT = 0

    # Americas (negative = west of UTC)
    HAWAII = -600  # UTC-10
    ALASKA = -540  # UTC-9
    PST = -480  # UTC-8 Pacific Standard Time
    PDT = -420  # UTC-7 Pacific Daylight Time
    MST = -420  # UTC-7 Mountain Standard Time
    MDT = -360  # UTC-6 Mountain Daylight Time
    CST = -360  # UTC-6 Central Standard Time
    CDT = -300  # UTC-5 Central Daylight Time
    EST = -300  # UTC-5 Eastern Standard Time
    EDT = -240  # UTC-4 Eastern Daylight Time
    ATLANTIC = -240  # UTC-4 Atlantic Standard Time
    ARGENTINA = -180  # UTC-3 Argentina Time
    BRAZIL = -180  # UTC-3 Brasília Time

    # Europe (positive = east of UTC)
    WET = 0  # UTC+0 Western European Time
    BST = 60  # UTC+1 British Summer Time
    CET = 60  # UTC+1 Central European Time
    CEST = 120  # UTC+2 Central European Summer Time
    EET = 120  # UTC+2 Eastern European Time
    EEST = 180  # UTC+3 Eastern European Summer Time
    MSK = 180  # UTC+3 Moscow Time

    # Middle East/Africa
    SAST = 120  # UTC+2 South Africa Standard Time
    EAT = 180  # UTC+3 East Africa Time
    IRST = 210  # UTC+3:30 Iran Standard Time
    GST = 240  # UTC+4 Gulf Standard Time

    # Asia
    PKT = 300  # UTC+5 Pakistan Standard Time
    IST = 330  # UTC+5:30 India Standard Time
    BST_BANGLADESH = 360  # UTC+6 Bangladesh Standard Time
    WIB = 420  # UTC+7 Western Indonesian Time
    CST_CHINA = 480  # UTC+8 China Standard Time
    HKT = 480  # UTC+8 Hong Kong Time
    SGT = 480  # UTC+8 Singapore Time
    JST = 540  # UTC+9 Japan Standard Time
    KST = 540  # UTC+9 Korea Standard Time

    # Oceania
    AEST = 600  # UTC+10 Australian Eastern Standard Time
    AEDT = 660  # UTC+11 Australian Eastern Daylight Time
    NZST = 720  # UTC+12 New Zealand Standard Time
    NZDT = 780  # UTC+13 New Zealand Daylight Time

    @classmethod
    def from_offset(cls, hours: float) -> 'Timezone':
        """
        Create a Timezone from hours offset.

        Examples:
            Timezone.from_offset(-5)    # EST
            Timezone.from_offset(5.5)   # IST (India)
            Timezone.from_offset(9)     # JST
        """
        minutes = int(hours * 60)
        # Try to find exact match
        for tz in cls:
            if tz.value == minutes:
                return tz
        # Return custom offset
        return cls._create_custom(minutes)

    @classmethod
    def offset(cls, base: Union['Timezone', int], delta_minutes: int) -> 'Timezone':
        """
        Create a timezone offset from a base timezone.

        Args:
            base: Base timezone or minutes from UTC
            delta_minutes: Additional offset in minutes

        Examples:
            Timezone.offset(Timezone.EST, 60)    # EST + 1 hour = EDT
            Timezone.offset(Timezone.UTC, -330)  # UTC - 5:30 = EST with 30min offset
        """
        base_minutes = base.value if isinstance(base, cls) else base
        total_minutes = base_minutes + delta_minutes

        # Try to find exact match
        for tz in cls:
            if tz.value == total_minutes:
                return tz

        # Return custom offset
        return cls._create_custom(total_minutes)

    @classmethod
    def _create_custom(cls, minutes: int) -> 'Timezone':
        """Create a custom timezone offset"""

        # This creates a temporary instance with the custom value
        # In practice, you might want to cache these
        class CustomTimezone(int):
            def __new__(cls, value):
                return int.__new__(cls, value)

            @property
            def name(self):
                hours = abs(self) // 60
                mins = abs(self) % 60
                sign = '+' if self >= 0 else '-'
                if mins:
                    return f"UTC{sign}{hours}:{mins:02d}"
                return f"UTC{sign}{hours}"

        return cls(CustomTimezone(minutes))

    @classmethod
    def auto_detect(cls) -> 'Timezone':
        """Auto-detect system timezone offset"""
        import time

        if time.daylight:
            utc_offset = time.altzone
        else:
            utc_offset = time.timezone

        # Convert seconds to minutes and invert sign
        minutes = -(utc_offset // 60)

        # Try to find matching timezone
        for tz in cls:
            if tz.value == minutes:
                return tz

        return cls._create_custom(minutes)

    def to_hours(self) -> float:
        """Convert to hours offset from UTC"""
        return self.value / 60.0

    def __str__(self):
        """String representation with UTC offset"""
        hours = abs(self.value) // 60
        minutes = abs(self.value) % 60
        sign = '+' if self.value >= 0 else '-'

        if minutes:
            offset_str = f"UTC{sign}{hours}:{minutes:02d}"
        else:
            offset_str = f"UTC{sign}{hours}"

        # Add name if it's a named timezone
        if hasattr(self, '_name_'):
            return f"{self._name_} ({offset_str})"
        return offset_str


class TLSHandshakeProgress(IntEnum):
    DONE = 0x0
    WAITING_FOR_DATA = 0x1
    MUST_SEND_DATA = 0x2
