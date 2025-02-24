# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Airbus S.A.S.

# scapy.contrib.description = ARINC 429
# scapy.contrib.status = loads

"""
Provides an implementation for ARINC 429 words.

Implemented following specification as per ARINC 429 Part 1
"""

from __future__ import annotations
import struct
import sys
from typing import Any, Callable, Dict, Mapping, Sequence, Type, cast
from typing_extensions import Self

from scapy.fields import (
    _BitField,
    BitField,
    BitEnumField,
    ByteField,
    XBitField,
    TrailerField,
    I,
    M,
    AnyField,
    warnings,
)
from scapy.packet import Packet


#############################################################################

if sys.version_info >= (3, 10):

    def parity(v: int) -> int:
        """
        Calculate parity of a raw A429 word
        """
        return v.bit_count() % 2

else:

    def parity(v: int) -> int:
        """
        Calculate parity of a raw A429 word
        """
        return (bin(v).count("1") + 1) % 2


def parity_fix(w: int) -> int:
    """
    fix the parity of an raw A429 word
    """
    w = w & 0x7FFF_FFFF
    p = parity(w)
    return ((p ^ 1) << 31) | w


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b[:4], "big")


def int_to_bytes(v: int) -> bytes:
    return v.to_bytes(4, "big")


#############################################################################
# A429 Fields


class ParityField(BitField):
    """
    Parity field of an A429 word.
    """

    def __init__(self, name: str = "parity", default: int | None = None):
        super().__init__(name=name, default=default, size=1)

    def i2repr(self, pkt: Packet | None, x: I) -> str:
        rep = super().i2repr(pkt, x)
        if x is not None:
            w = bytes_to_int(bytes(pkt))
            if not parity(w):
                rep += " (bad)"
        return rep


class SSMField(BitEnumField):
    # A429 Part 1 2.1.5 p4
    _ssm_values = {
        0b00: "Failure Warning",
        0b01: "No Computed Data",
        0b10: "Functional Test",
        0b11: "Normal Operation",
    }

    def __init__(
        self,
        name: str = "ssm",
        default: int | str = "Normal Operation",
        size: int = 2,
    ):
        super().__init__(name, default, size=size, enum=SSMField._ssm_values)


class BCDSSMField(BitEnumField):
    # A429 Part 1 2.1.5.1 p4

    __slots__ = ("value_from",)

    _ssm_values = {
        0b00: "+",
        0b01: "No Computed Data",
        0b10: "Functional Test",
        0b11: "-",
    }

    def __init__(
        self,
        name: str = "ssm",
        default: int | None = None,
        value_from: Callable[[A429], I] | None = lambda p: p.val,
    ):
        super().__init__(name, default, size=2, enum=BCDSSMField._ssm_values)
        self.value_from = value_from

    def i2m(self, pkt: A429 | None, x: I | None) -> M:
        match x, self.value_from is None:
            case None, False:
                x = 0b11 if self.value_from(pkt) < 0 else 0
            case None:
                x = 0
        return super().i2m(pkt, x)


class SSMSignField(BitField):
    """
    Sign Bit used in BNR A429 words.

    In the A429 specification it represents the 3rd bit in the SSM.
    See A429 Part 1 - 2.1.5.
    """

    __slots__ = ("value_from",)

    def __init__(
        self,
        name: str = "sign",
        default: int | None = None,
        value_from: Callable[[A429], I] | None = lambda p: p.val,
    ):
        super().__init__(name, default, size=1)
        self.value_from = value_from

    def i2m(self, pkt: A429 | None, x: I | None) -> M:
        match x, self.value_from is None:
            case None, False:
                x = 1 if self.value_from(pkt) < 0 else 0
            case None:
                x = 0
        return super().i2m(pkt, x)


class LabelField(ByteField):
    """
    A429 Label.
    """

    def __init__(self, name="label", default=0, **kargs):
        super().__init__(name=name, default=default, **kargs)

    @staticmethod
    def reverse(label: int) -> int:
        label = (label & 0xF0) >> 4 | (label & 0x0F) << 4
        label = (label & 0xCC) >> 2 | (label & 0x33) << 2
        label = (label & 0xAA) >> 1 | (label & 0x55) << 1
        return label

    def i2repr(self, pkt: A429 | None, x: I) -> str:
        return "o{:03o}".format(x)

    def m2i(self, pkt: A429 | None, x: M) -> I:
        return cast(I, self.reverse(x) if pkt and pkt.reverse_label else x)

    def i2m(self, pkt: A429 | None, x: I | None) -> M:
        return cast(M, self.reverse(x) if pkt and pkt.reverse_label else x)


class BNRField(BitField):
    """
    BNR A429 number field.

    See ARINC 429 Part 1 - §2.0 Digital Information Transfer System Standards
    """

    __slots__ = "unit", "res", "sign_from"

    def __init__(
        self,
        name: str,
        default: float,
        *,
        size: int,
        range: float = 1,  # range (as shown in A429 P1)
        unit: str = "",
        sign_from: Callable[[A429], int] | None = lambda p: p.sign,
        **kargs,
    ):
        """
        Args:
            range (float): range of the field
            unit (str): the field value's "unit", used in textual representation
        """
        self.res = range / (1 << size)
        self.unit = unit
        self.sign_from = sign_from
        super().__init__(name, default, size=size, **kargs)

    def i2repr(self, pkt: A429 | None, x: Any) -> str:
        return f"{x:+}{self.unit}"

    def i2m(self, pkt: A429 | None, x: I | None) -> M:
        x = int(x // self.res if x else 0)

        if x < 0 and (self.sign_from is None or self.sign_from(pkt) == 0):
            warnings.warn("SSM sign value doesn't match field's sign")

        return x & ((1 << self.size) - 1)

    def m2i(self, pkt: A429 | None, x: M) -> I:
        if self.sign_from and self.sign_from(pkt) == 1:
            # negative values use two's complement encoding (see A429 Part 1 -
            # 2.3.1.1)
            x = -((~x & ((1 << self.size) - 1)) + 1)
        x *= self.res
        return x


class BNRAngleField(BNRField):
    """
    Specific BNR encoding for angle measurement w/ sign bit included
    """

    def __init__(
        self,
        name: str,
        default: float,
        *,
        size: int,
        range: float = 180,
        **kargs,
    ):
        super().__init__(
            name, default, size=size, range=range, unit="°", **kargs
        )


class BCDField(BitField):
    """
    ARINC 429 BCD encoded field

    A BCD field **includes** the SSM bits.

    TODO: as of this impl, there is no simple way to set the SSM
          to "No Computed Data" or "Functional Test"
    """

    __slots__ = "unit", "res"

    def __init__(
        self, name, default, size: int, res: float = 1, unit: str = "", **kargs
    ):
        super().__init__(name, default, size=size, **kargs)
        self.res = res
        self.unit = unit

    def i2m(self, pkt: A429 | None, x: I | None) -> M:
        x = abs(x) / self.res if x else 0

        m = 0

        for shift in range(0, self.size, 4):
            if x == 0:
                break
            x, r = divmod(int(x), 10)
            m |= (r & 0xF) << shift

        m = m & ((1 << self.size) - 1)

        return m

    def m2i(self, pkt: A429 | None, x: M) -> I:
        ssm = pkt.ssm if pkt else 0
        i = 0
        shift = 0
        while x:
            i += (x & 0xF) * 10**shift
            x >>= 4
            shift += 1
        i *= self.res
        if ssm == 0b11:
            i = -i
        return i

    def i2repr(self, pkt: A429 | None, x: Any) -> str:
        return f"{x:+}{self.unit}"


class SDIField(BitEnumField):
    def __init__(self, name="sdi", default=0, **kargs):
        super().__init__(
            "sdi", default, enum={1: "L", 2: "R"}, size=2, **kargs
        )


class BitPadField(BitField):
    """
    Pad bits to a given target length
    """

    __slots__ = ("pad_to_size",)

    def __init__(
        self, name: str = "pad", default: int = 0, pad_to_size: int = 0
    ):
        super().__init__(name=name, default=default, size=0)
        self.pad_to_size = pad_to_size

    def register_owner(self, cls: Type[Packet]):
        """
        Callback from Packet_metaclass when a Packet class that uses
        this field is created.
        """

        sz: int = 0

        for i, f in enumerate(cls.fields_desc):
            if isinstance(f, TrailerField):
                continue
            if f is self:
                # pad field found
                break
            if not isinstance(f, _BitField):
                raise ValueError(
                    f"{BitPadField.__name__} can only be used when all "
                    "preceding fields in the Packet are Bitfields"
                )
            sz += f.size
        else:
            raise ValueError(
                f"BitPadField not encountered when initializing Packet class "
                f"{cls}"
            )
        if (pad_size := self.pad_to_size - sz) < 0:
            warnings.warn(
                f"Fields preceding pad field ({sz} bits) larger "
                f"than pad_to_size ({self.pad_to_size} bits)"
            )

        # Create a copy of the field, to assign its final size
        # `_BitField.tot_size` and `end_tot_size` aren't updated because
        # `_BitField.rev` is left to its initial `False` value. Because `rev`
        # is `True`, neither `tot_size` or `end_tot_size` are used, and
        # only `BitField.size` needs to be set.
        f = f.copy()
        f.size = max(0, pad_size)
        cls.fields_desc[i] = f


##############################################################################
# A429 Packets

# `struct` format of an A429 word
A429_FMT = "!I"


class A429(Packet):
    """
    A429 word represented as a Scapy Packet

    The class itself is abstract and serves as a common parent for concrete
    A429 subclasses.

    Subclasses should define a `label` class variable defining the value that
    will serve to match raw 429 to the subclass when dissecting.

    Subclasses should have `A429` as the first element in their
    `fields_desc` followed by their own specific `BitField`s.

    Subclasses can set `reverse_label` to True/False to control the bit
    order of their label in M (Machine) format.
    """

    # Whether labels have their bits in reverse order
    reverse_label: bool = True

    # Dispatch table based on 429 label
    _lbl2cls: Dict[int, Type[Packet]] = {}

    # Generic content for an A429 word, subclasses can specialize
    # the interpretation
    fields_desc: Sequence[AnyField] = [
        ParityField(),
        XBitField("data", 0, size=23),
        LabelField(),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        # the label is kept in a trailer field so it will be passed in
        # the `pay` parameter
        pkt = pkt + pay
        if self.parity is None:
            w = bytes_to_int(pkt)
            pkt = int_to_bytes(parity_fix(w))
        return pkt

    def as_int(self) -> int:
        return bytes_to_int(bytes(self))

    @classmethod
    def from_int(cls, w: int) -> Self:
        return cls(int_to_bytes(w))

    @classmethod
    def dispatch_hook(
        cls, _pkt: bytes | None = None, *args, **kargs
    ) -> Type[Self]:
        """
        return the A429 subclass to use to create a new Packet instance
        based on its label (as determined from the arguments) and
        subclasses registered with the A429 super class.
        """
        lbl: int | None = None

        # When `_pkt` is None, the label is looked for in the `kargs`,
        # otherwise the label's value is extracted directly from `_pkt`.
        # If no mapping is found just return `cls`
        if _pkt is None:
            lbl = kargs.get("label")
        else:
            a429_len = struct.calcsize(A429_FMT)
            if len(_pkt) >= a429_len:
                # Extract low byte of first word
                lbl = _pkt[a429_len - 1] & 0xFF
                if cls.reverse_label:
                    lbl = LabelField.reverse(lbl)
        dispatch_cls = cls.packet_class_for_label(lbl)
        return dispatch_cls

    @classmethod
    def _copy_and_reparent(
        cls,
        sub: Type[Self],
        *,
        from_parent: Type[Self],
        label: int | None,
        cmap: Mapping[Type[Self], Type[Self]],
    ) -> Type[Self]:
        """
        Return a copy of the A429 subclass provided as an argument.

        The purpose of this function is to support the `with_config` method.

        The copy will use `cls` its parent and will have its `label` field's
        default value set to the value of the `label` argument.

        Reparenting the `sub` class ensures that when the parent class (`cls`)
        is used to instantiate a packet, its class will be of the appropriate
        subclass (`sub`):
        ```
        # using a raw packet value
        pkt = cls(b'\0\0\0\3')

        # or using a constructor with a label
        pkt = cls(label=3)
        ```
        """
        if sub is cls:
            raise ValueError

        if not issubclass(sub, from_parent):
            raise ValueError

        def cls_tree_copy(sub: Type[Self]) -> Type[Self]:
            # Don't reparent subclasses that aren't derived from cls
            if not issubclass(sub, from_parent):
                return sub

            # if we've reached the top of the hierarchy (from_parent)
            # just return the new parent (cls)
            if sub is from_parent:
                return cls

            # If we've already generated a reparented version
            # of sub, return that
            if nsc := cmap.get(sub):
                return nsc

            # Create a new version of sub and recursively copy
            # its base classes.
            #
            # Bcs we're using `type` here we're not going through the full
            # metaclass initialization (it's already been done), but we do need
            # to call `register_variant`
            nsc = type(
                sub.__name__,
                tuple(map(cls_tree_copy, sub.__bases__)),
                dict(sub.__dict__),
            )
            if hasattr(sub, "fields_desc"):
                nsc.fields_desc = [f.copy() for f in sub.fields_desc]

            cmap[sub] = nsc
            return nsc

        nsc = cls_tree_copy(sub)

        if label is not None:
            nsc.label.default = label
            nsc.register_variant()
        return nsc

    @classmethod
    def register_variant(cls):
        """
        Register an A429 subclass.

        This will allow subsequent label-based lookups.
        """
        # only register a variant if its label isn't None or 0
        if (label := cls.label.default) and label:
            cls._lbl2cls[label] = cls

    @classmethod
    def packet_class_for_label(cls, label: int) -> Type[Self]:
        """
        Return an A429 subclass for a specific label.
        """
        return cls._lbl2cls.get(label, cls)

    @classmethod
    def with_config(
        cls,
        label_map: Dict[int, Type[Self]] | None = None,
        *,
        reverse_label: bool | None = None,
    ) -> Type[Self]:
        """
        Return a version of the A429 class configured with an alternate
        Label-to-Packet-class mapping.

        The method is intended to be called on A429 (or copies of the
        same) directly, and not on A429 subclasses.

        It's purpose is to support the creation of A429Equipment-specific
        label-to-A429-subclass mappings.
        """

        if cls is not A429:
            raise TypeError(
                "with_config should only be called directly on " "A429"
            )

        d = cls.__dict__ | {
            "_lbl2cls": {},
            "reverse_label": (
                getattr(cls, "reverse_label", False)
                if reverse_label is None
                else reverse_label
            ),
        }
        ncls = type(cls.__name__, cls.__bases__, d)

        # For each A429 subclass provided in the label_map, copy the class
        # so that we can reparent it to `ncls` and modify the default value of
        # its label field.

        label_map = label_map or cls._lbl2cls
        class_map = {}
        for lbl, c in label_map.items():
            ncls._copy_and_reparent(
                c, from_parent=cls, label=lbl, cmap=class_map
            )

        return ncls


class A429BCDHeader(Packet):
    fields_desc = [
        ParityField(),
        BCDSSMField(),
    ]


class A429BNRHeader(Packet):
    fields_desc = [
        ParityField(),
        SSMField(),
        SSMSignField(),
    ]


class A429Trailer(Packet):
    """
    Convenience Packet that gathers a pad field and the SDI field

    Ideally this would be an actural `TrailerField` but as of writing the
    latter only supports byte-aligned fields.
    """

    fields_desc = [
        BitPadField(pad_to_size=22),
        SDIField(),
        LabelField(),
    ]


##############################################################################
# Equipment
#


class A429Equipment:
    """
    Abstract superclass for A429 equipment.

    An A429 equipment will usually have its own interpretation of each
    label. In the present context, this amounts to a per equipment
    mapping between labels and A429 subclasses.

    When a new equipment is declared, a copy of A429 configured
    with the equipment's `label_map` is automatically generated.
    The copy is accessible as static member variable of the Equipment subclass.

    The generated A429 classes for the equipment are available
    as static members of the Equipment subclass.
    ```python

    class MyEquipment(A429Equipment):
        ...

    pkt = MyEquipment.A429(0b'...')
    pkt = MyEquipment.<SomeA429SubClass>(val=0x42)
    ```
    """

    # Equipment id
    eqpt_id: int | None = None

    # mapping from labels to an A429 subclass
    label_map: Dict[int, A429] = {}

    # does the equipment use reversed labels
    reverse_label: bool = True

    _id2eqpt = {}

    def __init_subclass__(cls, **kwargs):
        """
        New A429 Equipment, automatically define an A429 Packet with
        its private mapping
        """
        super().__init_subclass__(**kwargs)

        pkt_class = A429.with_config(
            cls.label_map,
            reverse_label=cls.reverse_label,
        )

        setattr(cls, A429.__name__, pkt_class)

        for sc in pkt_class._lbl2cls.values():
            setattr(cls, sc.__name__, sc)

        if eid := cls.eqpt_id:
            cls._id2eqpt[eid] = cls

    @staticmethod
    def by_id(cls, eqpt_id: int) -> Type[Self] | None:
        return cls._id2eqpt.get(eqpt_id)


##############################################################################
# Definitions from ARINC 429 Part 1 - Table 1 & 2
#
# Packets are defined without a default label value as they are intended
# to be used via an `Equipment` definition. The latter is in charge of
# creating copies of these classes for a specific equipment while assigning
# default label values at that point.
#
# The list of A429 words isn't exhaustive, as of writing it covers ADIRS and
# a few of the examples from A429 Part 1 Attachment 6.

class BCDGroundSpeed(A429):
    fields_desc = [
        A429BCDHeader,
        BCDField("val", 0, unit="Knots", size=15),
        A429Trailer,
    ]


class BCDTrackAngle(A429):
    fields_desc = [
        A429BCDHeader,
        BCDField("val", 0, unit="Deg", res=0.1, size=15),
        A429Trailer,
    ]


class BCDTotalAirTemp(A429):
    fields_desc = [
        A429BCDHeader,
        BCDField("val", 0, size=15, res=0.1, unit="°C"),
        A429Trailer,
    ]


class WindSpeed(A429):
    fields_desc = [
        A429BCDHeader,
        BCDField("val", 0, unit="Knots", size=11),
        A429Trailer,
    ]


class SelectedHeading(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, range=180, size=12),
        A429Trailer,
    ]


class SelectedAltitude(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, range=65536, size=16, unit="Ft"),
        A429Trailer,
    ]


class FlightDirectorPitch(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=12, range=180),
        A429Trailer,
    ]


class RightStaticPressure(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="mb", range=2048, size=18),
        A429Trailer,
    ]


class Altitude(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Feet", range=131072, size=17),
        A429Trailer,
    ]


class BaroCorrectedAltitude(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Feet", range=131072, size=17),
        A429Trailer,
    ]


class BaroCorrectedAltitude1(BaroCorrectedAltitude):
    name = "BaroCorrectedAltitude #1"


class Mach(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Mach", range=4.096, size=16),
        A429Trailer,
    ]


class ComputedAirspeed(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Knots", range=1024, size=14),
        A429Trailer,
    ]


class AltitudeRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Ft/Min", range=32768, size=11),
        A429Trailer,
    ]

class StaticAirTemperature(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="℃", range=512, size=11),
        A429Trailer,
    ]


class StaticPressure(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Hg", range=64, size=16),
        A429Trailer,
    ]


class CorrectedAngleOfAttack(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, range=180, size=12),
        A429Trailer,
    ]


class AvgUncorrectedStaticPressure(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="mb", range=2048, size=16),
        A429Trailer,
    ]


class AvgCorrectedStaticPressure(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="mb", range=2048, size=16),
        A429Trailer,
    ]


class BaroCorrectedAltitude3(BaroCorrectedAltitude):
    name = "BaroCorrectedAltitude #3"


class BaroCorrectedAltitude4(BaroCorrectedAltitude):
    name = "BaroCorrectedAltitude #4"


# TODO specification states 20 bits (where 18 are used here), however
# there are only 19 bits available!?
class IntegratedVerticalAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Ft/s", range=256, size=18),
        A429Trailer,
    ]


class BNRGroundSpeed(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Knots", range=4096, size=15),
        A429Trailer,
    ]


class BNRTrackAngle(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=15, range=180),
        A429Trailer,
    ]


class TrueHeading(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=15, range=180),
        A429Trailer,
    ]


class TrackAngleMagnetic(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=15, range=180),
        A429Trailer,
    ]


class MagneticHeading(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=15, range=180),
        A429Trailer,
    ]


class DriftAngle(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=12, range=180),
        A429Trailer,
    ]


class FlightPathAngle(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=12, range=180),
        A429Trailer,
    ]


class FlightPathAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class PitchAngle(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=14, range=180),
        A429Trailer,
    ]


class RollAngle(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=14, range=180),
        A429Trailer,
    ]


class BodyPitchRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Deg/s", range=128, size=13),
        A429Trailer,
    ]


class BodyRollRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Deg/s", range=128, size=13),
        A429Trailer,
    ]


class BodyYawRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Deg/s", range=128, size=13),
        A429Trailer,
    ]


class BodyLongitudinalAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class BodyLateralAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class BodyNormalAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class TrackAngleRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Deg/s", range=32, size=11),
        A429Trailer,
    ]


class InertialPitchRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Deg/s", range=128, size=13),
        A429Trailer,
    ]


class InertialRollRate(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Deg/s", range=128, size=13),
        A429Trailer,
    ]


class GridHeading(A429):
    fields_desc = [
        A429BNRHeader,
        BNRAngleField("val", 0, size=15, range=128),
        A429Trailer,
    ]


class PotentialVerticalSpeed(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Ft/Min", range=32768, size=15),
        A429Trailer,
    ]


class AlongTrackHorizontalAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class CrossTrackAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class VerticalAcceleration(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="g", range=4, size=12),
        A429Trailer,
    ]


class InertialVerticalVelocity(A429):
    fields_desc = [
        A429BNRHeader,
        BNRField("val", 0, unit="Ft/Mn", range=32768, size=15),
        A429Trailer,
    ]
