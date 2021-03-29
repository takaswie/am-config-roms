#!/usr/bin/env python3

from enum import Enum
from struct import unpack


class EntryType(Enum):
    IMMEDIATE = 0x00
    CSR_OFFSET = 0x01
    LEAF = 0x02
    DIRECTORY = 0x03

    @classmethod
    def check_value(cls, value):
        return value in (item.value for item in cls)

    def __repr__(self):
        return "'" + self.name + "'"


class Ieee1212ConfigRomLexer():
    @classmethod
    def detect_entries(cls, raw):
        entries = {}

        bus_info_length = cls.__detect_bus_info_length(raw)
        entries['bus-info'] = raw[4:4 + bus_info_length]
        raw = raw[4 + bus_info_length:]

        entries['root-directory'] = cls.__detect_directory_entries(raw)

        return entries

    @classmethod
    def __detect_bus_info_length(cls, raw):
        meta = unpack('>I', raw[:4])[0]
        bus_info_quadlet_count = (meta & 0xff000000) >> 24
        # crc_quadlet_count = (meta & 0x00ff0000) >> 16
        # crc = meta & 0x0000ffff
        return bus_info_quadlet_count * 4

    @classmethod
    def __detect_immediate(cls, key, value, raw):
        return value

    @classmethod
    def __detect_csr_offset(cls, key, value, raw):
        return 0xfffff0000000 + value * 4

    @classmethod
    def __detect_leaf_or_directory_length(cls, raw):
        meta = unpack('>I', raw[:4])[0]
        quadlet_count = (meta & 0xffff0000) >> 16
        # crc = meta & 0x0000ffff
        return quadlet_count * 4

    @classmethod
    def __detect_leaf(cls, key, value, raw):
        offset = value * 4
        raw = raw[offset:]
        length = cls.__detect_leaf_or_directory_length(raw)
        return raw[4:4 + length]

    @classmethod
    def __detect_directory(cls, key, value, raw):
        raw = raw[value * 4:]
        return cls.__detect_directory_entries(raw)

    @classmethod
    def __detect_directory_entries(cls, raw):
        # Table 7 - Directory entry types
        type_handles = {
            EntryType.IMMEDIATE: cls.__detect_immediate,
            EntryType.CSR_OFFSET: cls.__detect_csr_offset,
            EntryType.LEAF: cls.__detect_leaf,
            EntryType.DIRECTORY: cls.__detect_directory,
        }
        entries = []

        length = cls.__detect_leaf_or_directory_length(raw)
        raw = raw[4:]

        while length > 0:
            meta = unpack('>I', raw[:4])[0]
            key_type_id = (meta & 0xc0000000) >> 30
            key_id = (meta & 0x3f000000) >> 24
            entry_value = meta & 0x00ffffff

            if not EntryType.check_value(key_type_id):
                raise ValueError('Type {0} is not defined.'.format(key_type_id))
            key_type = EntryType(key_type_id)
            handle = type_handles[key_type]

            entry = [(key_id, key_type), handle(key_id, entry_value, raw)]
            entries.append(entry)

            raw = raw[4:]
            length -= 4

        return entries
