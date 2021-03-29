#!/usr/bin/env python3

from enum import Enum, auto
from struct import unpack

from utils.ieee1212_config_rom_lexer import EntryType


class DirectoryContext(Enum):
    VENDOR = auto()
    SPECIFIER = auto()
    BUS_DEPENDENT = auto()
    KEYWORD = auto()


class DescriptorType(Enum):
    TEXTUAL = 0x00
    ICON = 0x01

    @classmethod
    def check_value(cls, value):
        return value in (item.value for item in cls)


#
# Table 16 - Key definitions
#
class KeyType(Enum):
    ROOT = 0x00  # For my convenience.
    DESCRIPTOR = 0x01
    BUS_DEPENDENT_INFO = 0x02
    VENDOR = 0x03
    HARDWARE_VERSION = 0x04
    MODULE = 0x07
    NODE_CAPABILITIES = 0x0c
    EUI_64 = 0x0d
    UNIT = 0x11
    SPECIFIER_ID = 0x12
    VERSION = 0x13
    DEPENDENT_INFO = 0x14
    UNIT_LOCATION = 0x15
    MODEL = 0x17
    INSTANCE = 0x18
    KEYWORD = 0x19
    FEATURE = 0x1a
    MODIFIABLE_DESCRIPTOR = 0x1f
    DIRECTORY_ID = 0x20

    @classmethod
    def check_value(cls, value):
        return value in (item.value for item in cls)


class Ieee1212RootDirectoryParser():
    # Table 16 - Key definitions
    COMMON_KEYS = {
        # key:  (name, available types of parser)
        KeyType.DESCRIPTOR: (EntryType.LEAF,
                             EntryType.DIRECTORY),
        # 0x02 is for root directory only.
        KeyType.VENDOR: (EntryType.IMMEDIATE,
                         EntryType.LEAF,
                         EntryType.DIRECTORY),
        KeyType.HARDWARE_VERSION: (EntryType.IMMEDIATE, ),
        # 0x05-06: reserved.
        # 0x07 is for root directory only.
        # 0x08-0b: reserved.
        # 0x07 is for root directory only.
        KeyType.EUI_64: (EntryType.LEAF, ),
        # 0x0e-10: reserved.
        # 0x11 is for root and instance directory only.
        KeyType.SPECIFIER_ID: (EntryType.IMMEDIATE, ),
        KeyType.VERSION: (EntryType.IMMEDIATE, ),
        KeyType.DEPENDENT_INFO: (EntryType.IMMEDIATE,
                                 EntryType.CSR_OFFSET,
                                 EntryType.LEAF,
                                 EntryType.DIRECTORY, ),
        KeyType.UNIT_LOCATION: (EntryType.LEAF, ),
        KeyType.MODEL: (EntryType.IMMEDIATE, ),
        # 0x18 and 0x19 are for root and instance directory only.
        # 0x21-2f: reserved.
        # 0x11 is for instance and unit directory only.
        # NOTE: keys for extended data are not supported.
        KeyType.MODIFIABLE_DESCRIPTOR: (EntryType.LEAF, ),
        KeyType.DIRECTORY_ID: (EntryType.IMMEDIATE, ),
        # 0x30-37: by bus standard.
    }

    def __init__(self):
        self.__bus_dep_handles = {}
        self.__spec_dep_handles = {}
        self.__vendor_dep_handles = {}
        self.__keyword_dep_handles = {}

    def add_bus_dep_handle(self, name, handle):
        if name not in self.__bus_dep_handles:
            self.__bus_dep_handles[name] = []
        self.__bus_dep_handles[name].append(handle)

    def add_spec_dep_handle(self, spec_id, version, handle):
        specifier = (spec_id, version)
        if specifier not in self.__spec_dep_handles:
            self.__spec_dep_handles[specifier] = []
        self.__spec_dep_handles[specifier].append(handle)

    def add_vendor_dep_handle(self, vendor_id, handle):
        if vendor_id not in self.__vendor_dep_handles:
            self.__vendor_dep_handles[vendor_id] = []
        self.__vendor_dep_handles[vendor_id].append(handle)

    def add_keyword_dep_handle(self, keyword, handle):
        if keyword not in self.__keyword_dep_handles:
            self.__keyword_dep_handles[keyword] = []
        self.__keyword_dep_handles[keyword].append(handle)

    def __parse_immediate(self, key_type, ctx, value):
        # 7.7.7 Node_Capabilities entry
        if key_type == KeyType.NODE_CAPABILITIES:
            if self.__bus_name in self.__bus_dep_handles:
                for handle in self.__bus_dep_handles[self.__bus_name]:
                    data = handle(KeyType.NODE_CAPABILITIES.name, EntryType.IMMEDIATE.name, value)
                    if data:
                        value = data
                        break
        return value

    # 7.5.4.1 Textual descriptors
    def __parse_textual_descriptor(self, raw):
        width_definitions = {
            0x00: 'Fixed one-byte characters',
            0x01: 'Fixed two-byte characters',
            0x02: 'Fixed four-byte characters',
            # 0x03-07: reserved
            0x08: 'Not to be used',
            0x09: 'Variable width characters up to a two byte maximum',
            0x0a: 'Variable width characters up to a four byte maximum',
            # 0x0b-0f: reserved
        }

        meta = unpack('>I', raw[:4])[0]
        width = (meta & 0xf0000000) >> 24
        character_set = (meta & 0x0fff0000) >> 16
        language = meta & 0x0000ffff

        if width not in width_definitions or width != 0x00:
            raise OSError('Width {0} is not supported.'.format(width))

        # character_set == IANA MIBenum
        if character_set != 0:
            return OSError('Character set {0} is not supported.'.format(
                character_set))

        # At present, 'US-ASCII' is supported only.
        if language & 0x8000 or language > 0:
            raise OSError('Language {0} is not supported.'.format(language))

        content = raw[4:].decode('US-ASCII') + '\0'
        return content[:content.find('\0')]

    # 7.5.4.2 Icon descriptor
    def __parse_icon_descriptor(self, raw):
        raise OSError('Icon descriptor is not supported.')

    # 7.5.4 Descriptors
    def __parse_descriptor_leaf(self, raw):
        type_parsers = {
            DescriptorType.TEXTUAL: self.__parse_textual_descriptor,
            DescriptorType.ICON: self.__parse_icon_descriptor,
        }

        meta = unpack('>I', raw[:4])[0]
        descriptor_type = (meta & 0xff000000) >> 24
        specifier_id = meta & 0x00ffffff
        raw = raw[4:]

        if specifier_id == 0x00:
            if not DescriptorType.check_value(descriptor_type):
                raise OSError('Descritpor type {0} is not supported.'.format(descriptor_type))
            type_id = DescriptorType(descriptor_type)
            return type_parsers[type_id](raw)

        if specifier_id in self.__vendor_dep_handles:
            for handle in self.__vendor_dep_handles[specifier_id]:
                elem = handle(KeyType.DESCRIPTOR.value, EntryType.LEAF.name, raw)
                if elem:
                    return elem

        return raw

    def __parse_bus_dependent_info_leaf(self, raw):
        # See explanation of Table 9 – Leaf format specifiers.
        if self.__bus_name in self.__bus_dep_handles:
            for handle in self.__bus_dep_handles[self.__bus_name]:
                elem = handle(KeyType.BUS_DEPENDENT_INFO.value, EntryType.LEAF.name, raw)
                if elem:
                    return elem
        return None

    def __parse_vendor_leaf(self, raw):
        # TODO: handle VENDOR/SPECIFIER_ID in parent directory.
        if self.__vendor_id in self.__vendor_dep_handles:
            for handle in self.__vendor_dep_handles[self.__vendor_id]:
                elem = handle(KeyType.VENDOR.value, EntryType.IMMEDIATE.name, raw)
                if elem:
                    return elem
        return None

    # 7.7.5 Module_Primary_EUI_64
    # 7.7.8 EUI_64 entry
    def __parse_eui_64_leaf(self, raw):
        info = (unpack('>I', raw[:4])[0] << 32) | unpack('>I', raw[4:8])[0]
        return info

    def __parse_dependent_info_leaf(self, raw):
        # TODO: handle VENDOR/SPECIFIER_ID in parent directory.
        if self.__vendor_id in self.__vendor_dep_handles:
            for handle in self.__vendor_dep_handles[self.__vendor_id]:
                elem = handle(KeyType.VENDOR.value, EntryType.IMMEDIATE.name, raw)
                if elem:
                    return elem
        return None

    # 7.7.13 Unit_Location entry
    def __parse_unit_location_leaf(self, raw):
        info = {}

        info['base-address'] = \
            (unpack('>I', raw[:4])[0] << 32) | unpack('>I', raw[4:8])[0]
        raw = raw[4:]
        info['upper-bound'] = \
            (unpack('>I', raw[:4])[0] << 32) | unpack('>I', raw[4:8])[0]
        return info

    # 7.6.5 Keyword leaves
    def __parse_keyword_leaf(self, raw):
        return raw.rstrip('\0').decode('US-ASCII')

    def __parse_modifiable_desc_leaf(self, raw):
        meta = unpack('>I', raw[:4])[0]
        info = {}
        info['max-descriptor-size'] = (meta & 0xffff0000) >> 16
        info['descriptor-address'] = (meta & 0x0000ffff) << 32
        info['descriptor-address'] |= unpack('>I', raw[4:8])[0]
        return info

    def __parse_leaf(self, key_type, ctx, raw):
        leaf_parsers = {
            KeyType.DESCRIPTOR: self.__parse_descriptor_leaf,
            KeyType.BUS_DEPENDENT_INFO: self.__parse_bus_dependent_info_leaf,
            KeyType.VENDOR: self.__parse_vendor_leaf,
            KeyType.MODULE: self.__parse_eui_64_leaf,
            KeyType.EUI_64: self.__parse_eui_64_leaf,
            KeyType.DEPENDENT_INFO: self.__parse_dependent_info_leaf,
            KeyType.UNIT_LOCATION: self.__parse_unit_location_leaf,
            KeyType.KEYWORD: self.__parse_keyword_leaf,
            KeyType.MODIFIABLE_DESCRIPTOR: self.__parse_modifiable_desc_leaf,
        }
        if key_type not in leaf_parsers or not leaf_parsers[key_type]:
            raise OSError('Key {0} is not supported.'.format(key_type))
        return leaf_parsers[key_type](raw)

    def __merge_common_keys(self, defined_keys):
        keys = self.COMMON_KEYS
        if defined_keys:
            keys = dict(keys)
            keys.update(defined_keys)
        return keys

    # 7.5.4 Descriptors
    def __parse_descriptor_directory(self, ctx, key_type, entries):
        # See annotation of Table 16 – Key definitions.
        defined_keys = {
            KeyType.DESCRIPTOR: (EntryType.LEAF,
                                 EntryType.DIRECTORY, ),
            KeyType.MODIFIABLE_DESCRIPTOR: (EntryType.LEAF, ),
        }

        return self.__parse_directory_entries(key_type, ctx, entries, defined_keys)

    # 7.7.1 Bus_Dependent_Info entry
    def __parse_bus_dependent_directory(self, ctx, key_type, entries):
        # See explanation of Table 8 – Key ID allocations
        defined_keys = {
            KeyType.BUS_DEPENDENT_INFO: (EntryType.IMMEDIATE,
                                         EntryType.CSR_OFFSET,
                                         EntryType.LEAF, ),
        }

        ctx = (DirectoryContext.BUS_DEPENDENT, self.__NAME)

        return self.__parse_directory_entries(key_type, ctx, entries, defined_keys)

    # 7.7.3 Vendor_Info entry
    def __parse_vendor_directory(self, ctx, key_type, entries):
        # See explanation of Table 8 – Key ID allocations.
        for entry in entries:
            if entry[0] == (KeyType.SPECIFIER_ID.value, EntryType.IMMEDIATE):
                vendor_id = entry[1]
                break
        else:
            for entry in entries:
                if entry[0] == (KeyType.VENDOR.value, EntryType.IMMEDIATE):
                    vendor_id = entry[1]
                    break
            else:
                vendor_id = self.__vendor_id

        if (ctx[0] != DirectoryContext.VENDOR or ctx[1] == vendor_id):
            ctx = (DirectoryContext.VENDOR, vendor_id)

        return self.__parse_directory_entries(key_type, ctx, entries, self.COMMON_KEYS)

    # 7.7.6 Module_Info entry
    def __parse_module_directory(self, ctx, key_type, entries):
        # See explanation of Table 8 – Key ID allocations.
        for entry in entries:
            if entry[0] == (KeyType.SPECIFIER_ID.value, EntryType.IMMEDIATE):
                vendor_id = entry[1]
                break
        else:
            for entry in entries:
                if entry[0] == (KeyType.VENDOR.value, EntryType.IMMEDIATE):
                    vendor_id = entry[1]
                    break
            else:
                vendor_id = self.__vendor_id

        if (ctx[0] != DirectoryContext.VENDOR or ctx[1] == vendor_id):
            ctx = (DirectoryContext.VENDOR, vendor_id)

        return self.__parse_directory_entries(key_type, ctx, entries, self.COMMON_KEYS)

    # 7.6.4 Feature directories
    def __parse_feature_directory(self, ctx, key_type, entries):
        defined_keys = {
            # name:  (key_type, available types of parser)
            KeyType.SPECIFIER_ID: (EntryType.IMMEDIATE, ),
            KeyType.VERSION: (EntryType.IMMEDIATE, ),
            KeyType.DEPENDENT_INFO: (EntryType.IMMEDIATE,
                                     EntryType.CSR_OFFSET,
                                     EntryType.LEAF,
                                     EntryType.DIRECTORY, ),
        }

        # Mandatory entries are required to decide directory context.
        for entry in entries:
            if entry[0] == (KeyType.SPECIFIER_ID.value, EntryType.IMMEDIATE):
                specifier_id = entry[1]
            elif entry[0] == (KeyType.VERSION.value, EntryType.IMMEDIATE):
                version = entry[1]
                break
        else:
            raise ValueError(
                'Mandatory entries are missing in feature directory.')
        ctx = (DirectoryContext.SPECIFIER, (specifier_id, version))

        keys = self.__merge_common_keys(defined_keys)

        return self.__parse_directory_entries(key_type, ctx, entries, keys)

    # 7.6.3 Unit directories
    def __parse_unit_directory(self, ctx, key_type, entries):
        defined_keys = {
            # name:  (key_type, available types of parser)
            KeyType.VENDOR: (EntryType.IMMEDIATE,
                             EntryType.LEAF,
                             EntryType.DIRECTORY, ),
            KeyType.MODEL: (EntryType.IMMEDIATE, ),
            KeyType.SPECIFIER_ID: (EntryType.IMMEDIATE, ),
            KeyType.VERSION: (EntryType.IMMEDIATE, ),
            KeyType.DEPENDENT_INFO: (EntryType.IMMEDIATE,
                                     EntryType.CSR_OFFSET,
                                     EntryType.LEAF,
                                     EntryType.DIRECTORY, ),
            KeyType.FEATURE: (EntryType.DIRECTORY, ),
        }

        # Mandatory entries are required to decide directory context.
        for entry in entries:
            if entry[0] == (KeyType.SPECIFIER_ID.value, EntryType.IMMEDIATE):
                specifier_id = entry[1]
            elif entry[0] == (KeyType.VERSION.value, EntryType.IMMEDIATE):
                version = entry[1]
                break
        else:
            raise ValueError(
                'Mandatory entries are missing in unit directory.')
        ctx = (DirectoryContext.SPECIFIER, (specifier_id, version))

        keys = self.__merge_common_keys(defined_keys)

        return self.__parse_directory_entries(key_type, ctx, entries, keys)

    # 7.7.12 Dependent_Info entry
    def __parse_dependent_info_directory(self, ctx, key_type, entries):
        # Mandatory entries are required to decide directory context.
        for entry in entries:
            if entry[0] == (KeyType.SPECIFIER_ID.value, EntryType.IMMEDIATE):
                specifier_id = entry[1]
            elif entry[0] == (KeyType.VERSION.value, EntryType.IMMEDIATE):
                version = entry[1]
                ctx = (DirectoryContext.SPECIFIER, (specifier_id, version))
                break
        else:
            # TODO: this is a work around. Precisely, need to decide according
            # to entries in parent directory voluntarily.
            pass

        return self.__parse_directory_entries(key_type, ctx, entries, self.COMMON_KEYS)

    # 7.6.2 Instance directories
    def __parse_instance_directory(self, ctx, key_type, entries):
        defined_keys = {
            # name:  (key_type, available types of parser)
            KeyType.VENDOR: (EntryType.IMMEDIATE,
                             EntryType.LEAF,
                             EntryType.DIRECTORY, ),
            KeyType.KEYWORD: (EntryType.LEAF, ),
            KeyType.FEATURE: (EntryType.DIRECTORY, ),
            KeyType.INSTANCE: (EntryType.DIRECTORY, ),
            KeyType.UNIT: (EntryType.DIRECTORY, ),
            KeyType.MODEL: (EntryType.IMMEDIATE, ),
            KeyType.DEPENDENT_INFO: (EntryType.DIRECTORY, ),
        }

        # Keyword leaf entry can decide the context of content.
        for entry in entries:
            if entry[0] == (KeyType.KEYWORD, EntryType.LEAF):
                keyword = self.__parse_leaf(entry[0][0], ctx, entry[1])
                ctx = (DirectoryContext.KEYWORD, keyword)
                break

        keys = self.__merge_common_keys(defined_keys)

        return self.__parse_directory_entries(key_type, ctx, entries, keys)

    def __parse_directory(self, key_type, ctx, entries):
        directory_parsers = {
            KeyType.DESCRIPTOR: self.__parse_descriptor_directory,
            KeyType.BUS_DEPENDENT_INFO: self.__parse_bus_dependent_directory,
            KeyType.VENDOR: self.__parse_vendor_directory,
            KeyType.MODULE: self.__parse_module_directory,
            KeyType.FEATURE: self.__parse_feature_directory,
            KeyType.UNIT: self.__parse_unit_directory,
            KeyType.DEPENDENT_INFO: self.__parse_dependent_info_directory,
            KeyType.INSTANCE: self.__parse_instance_directory,
        }

        return directory_parsers[key_type](ctx, key_type, entries)

    def __parse_directory_entries(self, dir_key_type, ctx, entries, keys):
        type_parsers = {
            EntryType.IMMEDIATE: self.__parse_immediate,
            EntryType.CSR_OFFSET: lambda key_type, ctx, raw: raw,
            EntryType.LEAF: self.__parse_leaf,
            EntryType.DIRECTORY: self.__parse_directory,
        }
        external_handles = {
            DirectoryContext.VENDOR: self.__vendor_dep_handles,
            DirectoryContext.SPECIFIER: self.__spec_dep_handles,
            DirectoryContext.BUS_DEPENDENT: self.__bus_dep_handles,
            DirectoryContext.KEYWORD: self.__keyword_dep_handles,
        }
        info = []

        for entry in entries:
            key = entry[0]
            data = entry[1]
            parser = type_parsers[key[1]]

            key_type = KeyType(key[0]) if KeyType.check_value(key[0]) else None

            if key_type in keys and key[1] in keys[key_type]:
                elem = [key_type.name, parser(key_type, ctx, data)]
            else:
                ctx_name, ctx_value = ctx
                if ctx_value not in external_handles[ctx_name]:
                    elem = entry
                else:
                    for handle in external_handles[ctx_name][ctx_value]:
                        elem = handle(key[0], key[1].name, data)
                        if elem:
                            break
                    else:
                        elem = entry

            info.append(elem)

        return info

    def parse_root_directory(self, bus_name, entries):
        defined_keys = {
            # key_type:  available types of parser
            KeyType.BUS_DEPENDENT_INFO: (EntryType.IMMEDIATE,
                                         EntryType.CSR_OFFSET,
                                         EntryType.LEAF, ),
            KeyType.VENDOR: (EntryType.IMMEDIATE,
                             EntryType.LEAF,
                             EntryType.DIRECTORY, ),
            KeyType.HARDWARE_VERSION: (EntryType.IMMEDIATE, ),
            KeyType.MODULE: (EntryType.LEAF,
                             EntryType.DIRECTORY, ),
            KeyType.NODE_CAPABILITIES: (EntryType.IMMEDIATE, ),
            KeyType.INSTANCE: (EntryType.DIRECTORY, ),
            KeyType.UNIT: (EntryType.DIRECTORY, ),
            KeyType.MODEL: (EntryType.IMMEDIATE, ),
            KeyType.DEPENDENT_INFO: (EntryType.DIRECTORY, ),
            # Node_Unique_ID was obsoleted.
        }

        # Mandatory entries are required to decide directory context.
        for entry in entries:
            if entry[0] == (KeyType.VENDOR.value, EntryType.IMMEDIATE):
                self.__vendor_id = entry[1]
                break
        else:
            raise ValueError('Mandatory entry is missing in root directory.')
        ctx = (DirectoryContext.VENDOR, self.__vendor_id)

        self.__bus_name = bus_name

        keys = self.__merge_common_keys(defined_keys)

        return self.__parse_directory_entries(KeyType.ROOT, ctx, entries, keys)
