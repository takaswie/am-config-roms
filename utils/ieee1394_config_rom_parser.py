#!/usr/bin/env python3

from struct import unpack


class Ieee1394ConfigRomParser():
    __BUS_NAME = 0x31333934

    # added by IEEE 1394:1995
    __BUS_CAPS_1995 = {
        'irmc': (0x80000000, 31),  # Isochronous resource manager capable.
        'cmc': (0x40000000, 30),  # cycle master capable.
        'isc': (0x20000000, 29),  # isochronous capable.
        'bmc': (0x10000000, 28),  # bus namager capable.
        'cyc-clk-acc': (0x00ff0000, 16),  # cycle clock accuracy.
        'max_rec': (0x0000f000, 12),  # maximum data record size.
    }

    # added by IEEE 1394a:2000
    __BUS_CAPS_2000 = {
        'pmc': (0x08000000, 28),  # power manager capable.
        'gen': (0x000000c0, 6),  # generation.
        'link-spd': (0x00000007, 0),  # link speed.
    }

    # added by IEEE 1394:2008
    __BUS_CAPS_2008 = {
        'adj': (0x04000000, 27),  # compliant to IEEE 1394.1:2004.
    }

    @classmethod
    def parse_bus_info(cls, raw):
        meta = unpack('>I', raw[:4])[0]
        if meta != cls.__BUS_NAME:
            raise ValueError('The bus_name field mismatch')

        bus_info = {}
        meta = unpack('>I', raw[4:8])[0]

        for caps in (cls.__BUS_CAPS_1995, cls.__BUS_CAPS_2000, cls.__BUS_CAPS_2008):
            for key, (mask, shift) in caps.items():
                bus_info[key] = (meta & mask) >> shift

        meta = unpack('>I', raw[8:12])[0]
        bus_info['node-vendor-id'] = (meta & 0xffffff00) >> 8
        bus_info['chip-id'] = ((meta & 0x000000ff) << 32) | unpack('>I', raw[12:16])[0]

        return bus_info

    # IEEE 1394:1995 refers to ISO/IEC 13213:1994 (ANSI/IEEE Std 1212:1994).
    __NODE_CAPABILITIES = {
        'misc': {
            'spt': (0x008000, 15),  # The SPLIT_TIMEOUT register is implemented.
            'ms': (0x004000, 14),  # The messages-passing registers are implemented.
            'int': (0x002000, 13),  # The INTERRUPT_TARGET and INTERRUPT_MASK registers are implemented.
        },
        'testing': {
            'ext': (0x001000, 12),  # The ARGUMENT registers are implemented.
            'bas': (0x000800, 11),  # Node implements TEST_START&TEST_STATUS registers and testing state.
        },
        'addressing': {
            'prv': (0x000400, 10),  # The node implements the private space.
            '64': (0x000200, 9),  # The node uses 64-bit aaddressing (otherwise 32-bit addressing).
            'fix': (0x000100, 8),  # The node uses the fixed addressing scheme (otherwise extended addressing).
        },
        'state': {
            'lst': (0x000080, 7),  # The STATE_BITS.lost bit is implemented.
            'drq': (0x000040, 6),  # The STATE_BITS.dreq bit is implemented.
            'elo': (0x000020, 4),  # The STATE_BITS.elog bit and the ERROR_LOG registers are implementd.
            'atn': (0x000008, 3),  # The STATE_BITS.atn bit is implemented.
            'off': (0x000004, 2),  # The STATE_BITS.off bit is implemented.
            'ded': (0x000002, 1),  # The node supports the dead state.
            'init': (0x000001, 0),  # The node supports the initializing state.
        },
    }

    @classmethod
    def parse_node_caps(cls, val):
        node_caps = {}
        for category, caps in cls.__NODE_CAPABILITIES.items():
            if category not in node_caps:
                node_caps[category] = {}
            for key, (mask, shift) in caps.items():
                node_caps[category][key] = (val & mask) >> shift

        return node_caps
