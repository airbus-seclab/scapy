# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Airbus S.A.S.

# scapy.contrib.description = ARINC 429 equipment configurations
# scapy.contrib.status = skip

"""
Module intended for A429 equipment definitions
"""


from scapy.contrib.aero.a429 import (
    A429Equipment,
    BCDGroundSpeed,
    BCDTrackAngle,
    WindSpeed,
    RightStaticPressure,
    Altitude,
    BaroCorrectedAltitude,
    Mach,
    ComputedAirspeed,
    AltitudeRate,
    StaticAirTemperature,
    StaticPressure,
    CorrectedAngleOfAttack,
    AvgUncorrectedStaticPressure,
    AvgCorrectedStaticPressure,
    BaroCorrectedAltitude3,
    BaroCorrectedAltitude4,
    IntegratedVerticalAcceleration,
    BNRGroundSpeed,
    BNRTrackAngle,
    TrueHeading,
    TrackAngleMagnetic,
    MagneticHeading,
    DriftAngle,
    FlightPathAngle,
    FlightPathAcceleration,
    PitchAngle,
    RollAngle,
    BodyPitchRate,
    BodyRollRate,
    BodyYawRate,
    BodyLongitudinalAcceleration,
    BodyLateralAcceleration,
    BodyNormalAcceleration,
    TrackAngleRate,
    InertialPitchRate,
    InertialRollRate,
    GridHeading,
    PotentialVerticalSpeed,
    AlongTrackHorizontalAcceleration,
    CrossTrackAcceleration,
    VerticalAcceleration,
    InertialVerticalVelocity,
)


class ADIRS(A429Equipment):
    eqpt_id = 0x38
    label_map = {
        0o012: BCDGroundSpeed,
        0o013: BCDTrackAngle,
        0o015: WindSpeed,
        0o177: RightStaticPressure,
        0o203: Altitude,
        0o204: BaroCorrectedAltitude,
        0o205: Mach,
        0o206: ComputedAirspeed,
        0o212: AltitudeRate,
        0o213: StaticAirTemperature,
        0o217: StaticPressure,
        0o241: CorrectedAngleOfAttack,
        0o245: AvgUncorrectedStaticPressure,
        0o246: AvgCorrectedStaticPressure,
        0o251: BaroCorrectedAltitude3,
        0o252: BaroCorrectedAltitude4,
        0o265: IntegratedVerticalAcceleration,
        0o312: BNRGroundSpeed,
        0o313: BNRTrackAngle,
        0o314: TrueHeading,
        0o317: TrackAngleMagnetic,
        0o320: MagneticHeading,
        0o321: DriftAngle,
        0o322: FlightPathAngle,
        0o323: FlightPathAcceleration,
        0o324: PitchAngle,
        0o325: RollAngle,
        0o326: BodyPitchRate,
        0o327: BodyRollRate,
        0o330: BodyYawRate,
        0o331: BodyLongitudinalAcceleration,
        0o332: BodyLateralAcceleration,
        0o333: BodyNormalAcceleration,
        0o335: TrackAngleRate,
        0o336: InertialPitchRate,
        0o337: InertialRollRate,
        0o341: GridHeading,
        0o360: PotentialVerticalSpeed,
        0o362: AlongTrackHorizontalAcceleration,
        0o363: CrossTrackAcceleration,
        0o364: VerticalAcceleration,
        0o365: InertialVerticalVelocity,
    }
