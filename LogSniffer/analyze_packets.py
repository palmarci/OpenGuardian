#!/usr/bin/env python3

# TODO: Requires Python 3.7+ for ordered keys in dict. Make sure this is
# satisfied. Results will be garbage otherwise. Alternatively, use OrderedDict.

import argparse
import struct

import os
import sys

from decryptor import parse_file


class EventType:
    BOLUS_PROGRAMMED_P1              = 0x005a
    BOLUS_PROGRAMMED_P2              = 0x0066
    BOLUS_DELIVERED_P1               = 0x0069
    BOLUS_DELIVERED_P2               = 0x0096
    # custom Medtronic types:
    AUTO_BASAL_DELIVERY_EVENT        = 0xF001
    CL1_TRANSITION_EVENT             = 0xF002
    THERAPY_CONTEXT_EVENT            = 0xF004
    MEAL                             = 0xF005
    BG_READING                       = 0xF007
    CALIBRATION_COMPLETE             = 0xF008
    CALIBRATION_REJECTED             = 0xF009
    INSULIN_DELIVERY_STOPPED_EVENT   = 0xF00A
    INSULIN_DELIVERY_RESTARTED_EVENT = 0xF00B
    SG_MEASUREMENT                   = 0xF00C
    CGM_ANALYTICS_DATA_BACKFILL      = 0xF00D
    NGP_REFERENCE_TIME               = 0xF00E
    ANNUNCIATION_CLEARED_EVENT       = 0xF00F
    ANNUNCIATION_CONSOLIDATED_EVENT  = 0xF010
    MAX_AUTO_BASAL_RATE_CHANGED      = 0xF01A

# look up EventType's name by its value
event_type_lookup = {}
for k,v in vars(EventType).items():
    if not k.startswith("__"):
        event_type_lookup[v] = k


class NullHandler:
    type_label = ""

    def parse(self, data):
        pass


class BolusProgrammedP1:
    type_label = "Bolus Programmed Part 1 of 2"

    def parse(self, data):
        c, data = get_components(data, [
            (2, "Bolus ID"),
            (1, "Bolus Type"),
            (4, "Programmed Bolus Fast Amount", "f32"),
            (4, "Programmed Bolus Extended Amount", "f32"),
            (2, "Effective Bolus Duration"),
        ])
        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


class BolusProgrammedP2:
    type_label = "Bolus Programmed Part 2 of 2"

    def parse(self, data):
        c, data = get_components(data, [
            # TODO: print decoded flags
            (1, "Flags"),
        ])

        # parse remaining data depending on flags
        flags = c["Flags"]["value"]
        c_def = []
        if flags & 0x01:  # Bolus Delay Time Present
            c_def.append((2, "Bolus Delay Time"))
        if flags & 0x02:  # Bolus Template Number Present
            c_def.append((1, "Bolus Template Number"))
        if flags & 0x04:  # Bolus Activation Type Present
            c_def.append((1, "Bolus Activation Type"))

        if c_def:
            cc, data = get_components(data, c_def, len(c))
            # append new components
            c = {**c, **cc}

        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


class BolusDeliveredP1:
    type_label = "Bolus Delivered Part 1 of 2"

    def parse(self, data):
        c, data = get_components(data, [
            (2, "Bolus ID"),
            (1, "Bolus Type"),
            (4, "Delivered Bolus Fast Amount", "f32"),
            (4, "Delivered Bolus Extended Amount", "f32"),
            (2, "Effective Bolus Duration"),
        ])
        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


class BolusDeliveredP2:
    type_label = "Bolus Delivered Part 2 of 2"

    def parse(self, data):
        c, data = get_components(data, [
            # TODO: print decoded flags
            (1, "Flags"),
            (4, "Bolus Start Time Offset"),
        ])

        # parse remaining data depending on flags
        flags = c["Flags"]["value"]
        c_def = []
        if flags & 0x01:  # Bolus Activation Type Present
            c_def.append((1, "Bolus Activation Type"))
        if flags & 0x02:  # Bolus End Reason Present
            c_def.append((1, "Bolus End Reason"))
        if flags & 0x04:  # Annunciation Instance ID
            c_def.append((2, "Annunciation Instance ID"))

        if c_def:
            cc, data = get_components(data, c_def, len(c))
            # append new components
            c = {**c, **cc}

        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


class MicroBolusData:
    type_label = "Micro Bolus Data"

    def parse(self, data):
        c, data = get_components(data, [
            (1, "Bolus Number"),
            (4, "Bolus Amount", "f32"),
        ])
        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


class SGMeasurementData:
    type_label = "SG Measurement Data"

    def parse(self, data):
        c, data = get_components(data, [
            (2, "Time Offset"),
            (2, "SG Value"),
            (2, "ISIG"),
            (2, "V Counter"),
        ])
        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


class CGMAnalyticsData:
    type_label = "CGM Analytics Data"

    def parse(self, data):
        c, data = get_components(data, [
            (2, "Time Offset"),
            (2, "PSGV", "f16"),
            (2, "Cal Factor"),
        ])
        assert len(data) == 0, \
            "Expected handler to consume all of the data"
        return c


event_type_handlers = {
    EventType.BOLUS_PROGRAMMED_P1:         BolusProgrammedP1,
    EventType.BOLUS_PROGRAMMED_P2:         BolusProgrammedP2,
    EventType.BOLUS_DELIVERED_P1:          BolusDeliveredP1,
    EventType.BOLUS_DELIVERED_P2:          BolusDeliveredP2,
    EventType.AUTO_BASAL_DELIVERY_EVENT:   MicroBolusData,
    EventType.SG_MEASUREMENT:              SGMeasurementData,
    EventType.CGM_ANALYTICS_DATA_BACKFILL: CGMAnalyticsData,
}


def as_f16(value):
    e = (value & 0xf000) >> 12
    m = (value & 0x0fff)
    if e & 0x8:
        e = e - 256
    if m & 0x800:
        m = m - 4096
    return m * 10**e


def as_f32(value):
    e = (value & 0xff000000) >> 24
    m = (value & 0x00ffffff)
    if e & 0x80:
        e = e - 256
    if m & 0x800000:
        m = m - 4096
    return m * 10**e


def get_components(data, components, first_index=0):
    out = {}
    for i, c in enumerate(components):
        size, name = c[0:2]

        if size is None:
            value = data[0:]
        else:
            value = int.from_bytes(data[0:size], "little")
            if len(c) > 2:
                ctype = c[2]
                if ctype == "f16":
                    value = as_f16(value)
                elif ctype == "f32":
                    value = as_f32(value)

        out[name] = {
            "index": first_index + i,
            "size":  size,
            "value": value,
            "hex":   data[0:size].hex(),
            "child": None,
        }

        data = data[size:]

    return out, data


def print_components(components, indent=0):
    indent_str = " " * indent
    for i in range(len(components)):
        print(" " * indent, end="")
        name = ""
        child_name = ""
        for k, v in components.items():
            if i == v["index"]:
                print(v["hex"], end="")
                name = k
                if v["child"] is not None:
                    child_name = v["child_name"]
            else:
                print("." * len(v["hex"]), end="")
            print(" ", end="")

        # print child if there is one
        child = components[name]["child"]
        if child is None:
            value = components[name]["value"]
            # HACK: Replace event type with its constant's name for better
            # readability. This is specific to "IDD History Data" though.
            # Other characteristics do not have a field "Event Type".
            if name == "Event Type":
                value = event_type_lookup.get(value, value)
            print(" %s: %s" % (name, str(value)))
        else:
            print(" %s: %s" % (name, child_name))
            indent = 1 + sum([len(x["hex"]) + 1 for x in components.values()])
            print_components(child, indent)


def int_or_range(string):
    try:
        # single number
        n = int(string)
    except ValueError:
        n = None

    if n is not None:
        # range without lower bound is misdetected as single negative number
        if n < 0:
            bounds = [1, abs(n)]
        else:
            bounds = [n, n]
    else:
        # try number range
        bounds = string.split("-")
        if len(bounds) != 2:
            raise argparse.ArgumentTypeError("not a number or number range")

        if not bounds[0] and not bounds[1]:
            raise argparse.ArgumentTypeError("not a number or number range")

        if bounds[0]:
            try:
                bounds[0] = int(bounds[0])
            except ValueError:
                raise argparse.ArgumentTypeError("first part of range not a number")
        else:
            bounds[0] = None

        if bounds[1]:
            try:
                bounds[1] = int(bounds[1])
            except ValueError:
                raise argparse.ArgumentTypeError("second part of range not a number")
        else:
            bounds[1] = None

    return bounds


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dissect decrypted payloads from GATTLOG file")

    parser.add_argument("input",
        help="Decrypted GATTLOG file which to read from")

    parser.add_argument("-c", "--char-uuid",
        help="keep only entries with characteristics matching this UUID")

    parser.add_argument("-n", "--frame-number",
        help="keep only entries with Bluetooth frame numbers matching this number or number range (M-N, M-, -N)",
        type=int_or_range)

    args = parser.parse_args()

    header, entries = parse_file(args.input)

    # briefly check whether we are dealing with the correct type of input file
    decryption_state = header.get("decryption_state", None)
    if decryption_state != "decrypted":
        raise ValueError("Input does not seem to be a decrypted GATTLOG file")

    entries_f = entries

    # filter entries by frame number
    if args.frame_number is not None:
        lo, hi = args.frame_number
        if hi is None:
            # range M-
            entries_f = filter(lambda e: e["frame"] >= lo, entries_f)
        elif lo is None:
            # range -N
            entries_f = filter(lambda e: e["frame"] <= hi, entries_f)
        else:
            # range M-N
            entries_f = filter(lambda e: lo <= e["frame"] <= hi, entries_f)

    # filter entries by characteristic's UUID
    if args.char_uuid is not None:
        entries_f = filter(lambda e: e["char_uuid"] == args.char_uuid, entries_f)

    for i,v in enumerate(entries_f):
        d = v["data"]
        print("#%-4d: [%s->%s] %s" % (v["frame"], v["source"], v["dest"], d.hex()))

        # IDD History Data
        if v["char_uuid"] == "00000108000010000000009132591325":
            c, d = get_components(d, [
                (2,    "Event Type"),
                (4,    "Sequence Number"),
                (2,    "Relative Offset"),
                (None, "Event Data"),
            ])

            event_type = c["Event Type"]["value"]
            handler = event_type_handlers.get(event_type, NullHandler)()
            c["Event Data"]["child"]      = handler.parse(d)
            c["Event Data"]["child_name"] = handler.type_label

            m = map(lambda x: x["hex"], c.values())
            print(" ".join(m))
            print_components(c)

        print()

