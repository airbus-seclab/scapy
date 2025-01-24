# /usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024, 2025 Airbus Operations GmbH and SAS


from __future__ import annotations

import typing

from scapy.packet import Packet
from scapy.fields import (
    BitField,
    XBitField,
    PacketField,
    PacketListField,
    Field,
)


def bytes_shift(
    b: bytes,
    lshift: int = 0,
    rshift: int = 0,
    endian: typing.Literal["little", "big"] = "big",
) -> bytes:
    i = int.from_bytes(b, endian)
    i = i << lshift >> rshift
    return i.to_bytes(len(b), endian)


def _A429_guess_payload_class(
    p: typing.Tuple[bytes, int, int], **kargs: dict
) -> A429Payload:
    a429 = int.from_bytes(p[0], "big")
    for cls in sorted(
        A429Payload.__subclasses__(),
        key=lambda cls: bin(cls.mask).count("1"),
        reverse=True,
    ):
        if (a429 & cls.mask) == cls.match:
            return cls(p, **kargs)
    return A429Payload(p, **kargs)


class A429Payload(Packet):
    name: str = "ARINC 429 (Data/Payload)"
    label: int = 0

    mask: int = 0x0
    match: int = 0

    fields_desc: typing.List[Field] = [XBitField("load", 0, 23)]

    def do_dissect(self, s):
        """Hotpatches a bug in scapy; checked for commit #d71014a5.

        *Bug Description:*
        `do_dissect` sets the value of `raw_packet_cache`; however, line #1038 is not
        capable of processing a tuple inside `_raw`, which is the case if a PacketField
        is not aligned to full bytes.
        The following pseudo-code patch should be included before using `_raw`:
        |  if type(_raw) is tuple:
        |    _raw = _raw[0] << _raw[1]
        However, python out of the box does not support bitshift of `bytes()`.
        The shift also need to handle (omit?) overflow.

        *Hot Patch:*
        Resetting `raw_packet_cache` hot patches the issue, which seems to appear if
        `copy` is used on the ARINC429 packet, which appears to be the case for
        example in scapypipes.
        """
        r = Packet.do_dissect(self, s)
        self.raw_packet_cache = None
        return r

    def post_build(self, pkt: typing.Tuple[bytes, int, int], pay: bytes) -> bytes:
        r = pkt[0] + (pkt[2] << 1).to_bytes(1, "big") + pay
        return r

    def extract_padding(
        self, s: bytes
    ) -> typing.Tuple[typing.Optional[bytes], typing.Optional[bytes]]:
        return None, s


class _A429PacketField(PacketField):
    def addfield(
        self, pkt: ARINC429, s: typing.Tuple[bytes, int, int], val: A429Payload
    ) -> bytes:
        v = bytes_shift(bytes(val), rshift=s[1])
        parity = s[2] << (8 - s[1])

        r = (v[0] | parity).to_bytes(1, "big") + v[1:]
        return r


class A429Label(BitField):
    @staticmethod
    def reverse(label: int) -> int:
        label = (label & 0xF0) >> 4 | (label & 0x0F) << 4
        label = (label & 0xCC) >> 2 | (label & 0x33) << 2
        label = (label & 0xAA) >> 1 | (label & 0x55) << 1
        return label

    def m2i(self, pkt: ARINC429, m: int) -> int:
        return A429Label.reverse(m)

    def i2m(self, pkt: ARINC429, m: typing.Optional[int]) -> int:
        return A429Label.reverse(m) if m else 0

    def i2repr(self, pkt, x):
        return f"o{x:03o}" if x is not None else None  # noqa E231


class ARINC429(Packet):
    name: str = "ARINC 429"

    fields_desc: typing.List[Field] = [
        BitField("parity", None, 1),
        _A429PacketField("data", A429Payload(), _A429_guess_payload_class),
        A429Label("label", None, 8),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.label is None:
            pkt = pkt[:3] + A429Label.reverse(self.data.label).to_bytes(1, "big")

        if self.parity is None:
            self.parity: int = self.calc_parity(pkt + pay)
            pkt = ((self.parity << 7) | pkt[0]).to_bytes(1, "big") + pkt[1:]
        return pkt + pay

    def calc_parity(self, pkt: bytes):
        parity = 0
        for n in pkt:
            parity += "{0:b}".format(n).count("1")
        return (parity + 1) % 2

    def extract_padding(
        self, s: bytes
    ) -> typing.Tuple[typing.Optional[bytes], typing.Optional[bytes]]:
        return None, s

    def to_int(self, reverse_label: bool = False) -> int:
        frame = int.from_bytes(bytes(self), "big")
        if reverse_label:
            frame = self.__class__.label_reverse(frame)
        return frame

    @classmethod
    def from_int(cls, frame: int, reverse_label: bool = False):
        if reverse_label:
            frame = cls.label_reverse(frame)
        frame_bytes = frame.to_bytes(4, "big")
        return cls(frame_bytes)

    @staticmethod
    def word_reverse(word: int) -> int:
        word = ((word & 0xAAAAAAAA) >> 1) | ((word & 0x55555555) << 1)
        word = ((word & 0xCCCCCCCC) >> 2) | ((word & 0x33333333) << 2)
        word = ((word & 0xF0F0F0F0) >> 4) | ((word & 0x0F0F0F0F) << 4)
        word = ((word & 0xFF00FF00) >> 8) | ((word & 0x00FF00FF) << 8)
        word = (word >> 16) | (word << 16)
        word &= 0xFFFFFFFF
        return word

    @staticmethod
    def label_reverse(frame: int) -> int:
        label = frame & 0x000000FF
        label = (label & 0xF0) >> 4 | (label & 0x0F) << 4
        label = (label & 0xCC) >> 2 | (label & 0x33) << 2
        label = (label & 0xAA) >> 1 | (label & 0x55) << 1
        return (frame & 0xFFFFFF00) | label


class ARINC429Multiple(Packet):
    name: str = "ARINC 429 (Multiple)"
    fields_desc: typing.List[Field] = [PacketListField("a429", [], ARINC429)]


class A429GenericPayload(A429Payload):
    # cf. test/scapy/layers/a429.uts for examples for custom A429Payload
    name: str = "ARINC 429 (Generic Data/Payload with sdi/ssm)"
    label: int = 0  # label needs to be set according to use case

    mask: int = 0x000000FF
    match: int = A429Label.reverse(label)

    fields_desc: typing.List[Field] = [
        BitField("ssm", 0, 2),
        XBitField("load", 0, 19),
        BitField("sdi", 0, 2),
    ]
