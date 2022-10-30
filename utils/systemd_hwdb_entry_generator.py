#!/usr/bin/env python3

class SystemdHwdbEntryGenerator:
    @classmethod
    def generate(cls, filename, bus_info, root_directory, verbose):
        node_attrs = cls.__emulate_node_attrs(bus_info, root_directory)

        units_attrs = []
        if 'units' in node_attrs:
            for (key_type, key_value) in root_directory:
                if key_type == 'UNIT':
                    units_attrs.append(cls.__emulate_unit_attrs(key_value))

        if len(units_attrs) > 0:
            for i, unit_attrs in enumerate(units_attrs):
                node_key = cls.__generate_custom_node_key(node_attrs, i)
                modalias = cls.__generate_unit_modalias(node_attrs, unit_attrs)
                data = cls.__generate_unit_data(node_attrs, unit_attrs)

                if len(units_attrs) > 1:
                    print('# generated with {} for unit {}'.format(filename, i))
                else:
                    print('# generated with {}'.format(filename))
                print(node_key)
                print(modalias)
                for key, value in data.items():
                    print('  {}={}'.format(key, value))
        else:
            print('This node includes no unit.')

        if verbose:
            print('')
            cls.__print_attrs(node_attrs, units_attrs)

    # I decide it for hwdb of systemd. Two types of format are used depending on cases.
    @classmethod
    def __generate_custom_node_key(cls, attrs, unit_index):
        if 'units' in attrs:
            units = attrs['units'].split(' ')
            if len(units) == 1:
                unit = 'units{}'.format(units[unit_index])
            else:
                unit = 'units*{}*'.format(units[unit_index])
        else:
            unit = ''

        if 'model' in attrs:
            model = 'mo{}'.format(attrs['model'])
        else:
            model = ''
        return 'ieee1394:node:ven{}{}{}'.format(attrs['vendor'], model, unit)

    # Linux FireWire subsystem decides.
    @classmethod
    def __generate_unit_modalias(cls, node_attrs, unit_attrs):
        ven = 0
        for attrs in (unit_attrs, node_attrs):
            if 'vendor' in attrs:
                ven = int(attrs['vendor'], 16)

        mo = 0
        for attrs in (unit_attrs, node_attrs):
            if 'model' in attrs:
                mo = int(attrs['model'], 16)

        spec = 0
        if 'specifier_id' in unit_attrs:
            spec = int(unit_attrs['specifier_id'], 16)

        ver = 0
        if 'version' in unit_attrs:
            ver = int(unit_attrs['version'], 16)

        return 'ieee1394:ven{:08X}mo{:08X}sp{:08X}ver{:08X}'.format(ven, mo, spec, ver)

    @classmethod
    def __generate_unit_data(cls, node_attrs, unit_attrs):
        iidc_pairs = (
            ('0x00a02d', '0x000100'),  # IIDC v1.04
            ('0x00a02d', '0x000101'),  # IIDC v1.20
            ('0x00a02d', '0x000102'),  # IIDC v1.30, v1.31, v1.32
            ('0x00a02d', '0x000110'),  # IIDC2 v1.0.0, v1.1.0
        )
        pgrey_pairs = (
            ('0x00b09d', '0x000100'),
            ('0x00b09d', '0x000101'),
            ('0x00b09d', '0x000102'),
        )
        generic_avc_pairs = (
            ('0x00a02d', '0x010001'),   # AV/C Device 1.0 compliant (TA Document 1999027).
        )
        vendor_avc_pairs = (
            ('0x00a02d', '0x014001'),
        )

        data = {}

        data['ID_VENDOR_FROM_DATABASE'] = '(fill this entry!)'
        for attrs in (node_attrs, unit_attrs):
            if 'vendor_name' in attrs and isinstance(attrs['vendor_name'], str):
                data['ID_VENDOR_FROM_DATABASE'] = attrs['vendor_name']

        data['ID_MODEL_FROM_DATABASE'] = '(fill this entry!)'
        for attrs in (node_attrs, unit_attrs):
            if 'model_name' in attrs and isinstance(attrs['model_name'], str):
                data['ID_MODEL_FROM_DATABASE'] = attrs['model_name']

        if 'specifier_id' in unit_attrs and 'version' in unit_attrs:
            unit_pair = (unit_attrs['specifier_id'], unit_attrs['version'])
            if unit_pair in iidc_pairs:
                data['IEEE1394_UNIT_FUNCTION_VIDEO'] = '1'
            elif unit_pair in pgrey_pairs:
                data['IEEE1394_UNIT_FUNCTION_VIDEO'] = '1'
            elif unit_pair in generic_avc_pairs:
                data['IEEE1394_UNIT_FUNCTION_MUSIC'] = '(1 if supported else remove)'
                data['IEEE1394_UNIT_FUNCTION_AUDIO'] = '(1 if supported else remove)'
                data['IEEE1394_UNIT_FUNCTION_VIDEO'] = '(1 if supported else remove)'
            elif unit_pair in vendor_avc_pairs:
                data['IEEE1394_UNIT_FUNCTION_MUSIC'] = '(1 if supported else remove)'
                data['IEEE1394_UNIT_FUNCTION_AUDIO'] = '(1 if supported else remove)'
                data['IEEE1394_UNIT_FUNCTION_VIDEO'] = '(1 if supported else remove)'
            else:
                data['IEEE1394_UNIT_FUNCTION_MUSIC'] = '(1 if supported else remove)'
                data['IEEE1394_UNIT_FUNCTION_AUDIO'] = '(1 if supported else remove)'
                data['IEEE1394_UNIT_FUNCTION_VIDEO'] = '(1 if supported else remove)'

        return data

    @classmethod
    def __print_attrs(cls, node_attrs, units_attrs):
        print('Attributes emulated for Linux FireWire subsystem:')

        print('  Node attributes:')
        for key, value in node_attrs.items():
            print('    ATTR{{{}}}=="{}"'.format(key, value))
        for i, unit_attrs in enumerate(units_attrs):
            print('  Unit {} attributes:'.format(i))
            for key, value in unit_attrs.items():
                print('    ATTR{{{}}}=="{}"'.format(key, value))

    @classmethod
    def __emulate_node_attrs(cls, bus_info, root_directory):
        attrs = {}

        attrs['guid'] = '0x{:06x}{:012x}'.format(bus_info['node-vendor-id'], bus_info['chip-id'])

        vendor_flag = False
        model_flag = False
        units = []
        for key_type, key_value in root_directory:
            if key_type == 'VENDOR':
                # Legacy layout of configuration ROM has two vendor entries in root directory for
                # immediate and directory. The directory stores numeric model indentifier and leaf
                # for model name. It's described in annexes of 'Configuration ROM for AV/C Devices
                # 1.0 (December 12, 2000, 1394 Trading Association, TA Document 1999027)'
                if isinstance(key_value, int):
                    attrs['vendor'] = '0x{:06x}'.format(key_value)
                    vendor_flag = True
            elif key_type == 'MODEL':
                attrs['model'] = '0x{:06x}'.format(key_value)
                model_flag = True
            elif key_type == 'DESCRIPTOR':
                if vendor_flag:
                    attrs['vendor_name'] = key_value
                    vendor_flag = False
                elif model_flag:
                    attrs['model_name'] = key_value
                    model_flag = False
            elif key_type == 'UNIT':
                specifier_id = None
                version = None
                for (unit_key_type, unit_key_value) in key_value:
                    if unit_key_type == 'SPECIFIER_ID':
                        specifier_id = unit_key_value
                    elif unit_key_type == 'VERSION':
                        version = unit_key_value
                if specifier_id is not None and version is not None:
                    units.append('0x{:06x}:0x{:06x}'.format(specifier_id, version))

        if len(units):
            attrs['units'] = ' '.join(units)

        return attrs

    @classmethod
    def __emulate_unit_attrs(cls, entries):
        attrs = {}
        model_name_flag = False
        for (key_type, key_value) in entries:
            if key_type == 'SPECIFIER_ID':
                attrs['specifier_id'] = '0x{:06x}'.format(key_value)
            elif key_type == 'VERSION':
                attrs['version'] = '0x{:06x}'.format(key_value)
            elif key_type == 'MODEL':
                attrs['model'] = '0x{:06x}'.format(key_value)
                model_name_flag = True
            elif key_type == 'DESCRIPTOR' and model_name_flag:
                attrs['model_name'] = key_value
                model_name_flag = False
        return attrs
