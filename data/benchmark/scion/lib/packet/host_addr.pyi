from ..types import AddrType
from .packet_base import Serializable
from typing import Optional, Type


class HostAddrBase(Serializable):
    TYPE = None  # type: Optional[int]
    LEN = None  # type: Optional[int]

    def __init__(self, addr: bytes) -> None:
        ...

    def __str__(self) -> str:
        ...

    def name(self) -> str:
        ...

    def pack(self) -> bytes:
        ...

    def __len__(self) -> int:
        ...

class HostAddrNone(HostAddrBase):  # pragma: no cover
    """
    Host "None" address. Used to indicate there's no address.
    """
    TYPE = AddrType.NONE
    LEN = 0


class HostAddrSVC(HostAddrBase):
    """
    Host "SVC" address. This is a pseudo- address type used for SCION services.
    """
    TYPE = AddrType.SVC
    LEN = 2
    NAME = "HostAddrSVC"
    MCAST = 0x8000


IPV4LENGTH = 32
IPV6LENGTH = 128


class HostAddrIPv4(HostAddrBase):
    """
    Host IPv4 address.
    """
    TYPE = AddrType.IPV4
    LEN:int


class HostAddrIPv6(HostAddrBase):
    """
    Host IPv6 address.
    """
    TYPE = AddrType.IPV6
    LEN:int

def haddr_get_type(type_: int) -> Type[HostAddrBase]:  # pragma: no cover
    ...