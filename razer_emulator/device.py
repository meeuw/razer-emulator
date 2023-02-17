"""
Razer Emulator
"""
from enum import Enum
import struct
import functools
import sys
import toml
import pkg_resources
from collections import namedtuple

import functionfs
from functionfs.gadget import (
    GadgetSubprocessManager,
    ConfigFunctionFFSSubprocess,
)
from functionfs import ch9, hid

trace = functools.partial(print, file=sys.stderr)

CommandType = namedtuple("CommandType", "command_class, command_id")


def _traverse_config(config, accumulated, flattened):
    for k, value in config.items():
        if isinstance(value, list):
            for i in value:
                accumulated_copy = accumulated.copy()
                flattened[k] = _traverse_config(i, accumulated_copy, flattened)
        else:
            accumulated[k] = value

    return accumulated


def parse_config(config):
    """
    flatten/fold configurations
    """
    flattened = {}
    _traverse_config(config, {}, flattened)
    for pk, pv in flattened.items():
        for k, v in pv.items():
            if isinstance(v, str):
                pv[k] = v
    return flattened


def crc(buf):
    """
    Calculate Razer CRC
    """

    result = 0
    for i in range(2, 86):
        result ^= buf[i]
    return result


# from https://github.com/cyanogen/uchroma/blob/master/uchroma/server/report.py
class Status(Enum):
    """
    Enumeration of status codes returned by the hardware
    """

    UNKNOWN = 0x00
    BUSY = 0x01
    OK = 0x02
    FAIL = 0x03
    TIMEOUT = 0x04
    UNSUPPORTED = 0x05
    BAD_CRC = 0xFE
    OSERROR = 0xFF


class Command(Enum):
    """
    Enumeration of commands
    """

    SET_DEVICE_MODE = CommandType(command_class=0x00, command_id=0x04)

    GET_POLLING_RATE = CommandType(command_class=0x00, command_id=0x85)
    SET_POLLING_RATE = CommandType(command_class=0x00, command_id=0x05)

    GET_POLLING_RATE2 = CommandType(command_class=0x00, command_id=0xC0)
    SET_POLLING_RATE2 = CommandType(command_class=0x00, command_id=0x40)

    GET_DEVICE_MODE = CommandType(command_class=0x00, command_id=0x84)
    GET_SERIAL = CommandType(command_class=0x00, command_id=0x82)
    GET_FIRMWARE_VERSION = CommandType(command_class=0x00, command_id=0x81)

    SET_PRESET_DATA = CommandType(command_class=0x05, command_id=0x08)
    GET_PRESET_DATA = CommandType(command_class=0x05, command_id=0x88)
    GET_DATA_MAX_FREE = CommandType(command_class=0x06, command_id=0x8E)

    UNKNOWN0212 = CommandType(command_class=0x02, command_id=0x12) # bind keys
    UNKNOWN0292 = CommandType(command_class=0x02, command_id=0x92)
    UNKNOWN0502 = CommandType(command_class=0x05, command_id=0x02) # write preset / start up
    UNKNOWN0503 = CommandType(command_class=0x05, command_id=0x03) # delete preset / start up
    UNKNOWN0580 = CommandType(command_class=0x05, command_id=0x80) # start up (amount of presets?)
    UNKNOWN0581 = CommandType(command_class=0x05, command_id=0x81) # start up
    UNKNOWN058A = CommandType(command_class=0x05, command_id=0x8A) # start up (amount of available presets?)
    UNKNOWN0680 = CommandType(command_class=0x06, command_id=0x80) # delete preset / start up

    UNKNOWN0F80 = CommandType(command_class=0x0F, command_id=0x80) # synapse quit / write preset
    UNKNOWN0F82 = CommandType(command_class=0x0F, command_id=0x82) # synapse quit / write preset

    UNKNOWN0087 = CommandType(command_class=0x00, command_id=0x87) # synapse start
    UNKNOWN07 = CommandType(command_class=0x03, command_id=0x07)
    UNKNOWN08 = CommandType(command_class=0x00, command_id=0x08)
    UNKNOWN09 = CommandType(command_class=0x07, command_id=0x01)
    UNKNOWN10 = CommandType(command_class=0x07, command_id=0x08)
    UNKNOWN11 = CommandType(command_class=0x07, command_id=0x0B)
    UNKNOWN12 = CommandType(command_class=0x0D, command_id=0x82)
    UNKNOWN13 = CommandType(command_class=0x0D, command_id=0x07)
    UNKNOWN14 = CommandType(command_class=0x0D, command_id=0x83)
    UNKNOWN15 = CommandType(command_class=0x0D, command_id=0x8B)
    UNKNOWN16 = CommandType(command_class=0x0D, command_id=0x89)
    UNKNOWN17 = CommandType(command_class=0x0D, command_id=0x02)
    UNKNOWN18 = CommandType(command_class=0x00, command_id=0x89)
    UNKNOWN19 = CommandType(command_class=0x00, command_id=0xB9)

    READ_KBD_LAYOUT = CommandType(command_class=0x00, command_id=0x86)

    FN_KEY_TOGGLE = CommandType(command_class=0x02, command_id=0x06)
    SET_KEYSWITCH_OPTIMIZATION_COMMAND1 = CommandType(
        command_class=0x02, command_id=0x02
    )
    SET_KEYSWITCH_OPTIMIZATION_COMMAND2 = CommandType(
        command_class=0x02, command_id=0x15
    )
    GET_KEYSWITCH_OPTIMIZATION = CommandType(command_class=0x02, command_id=0x82)
    SET_SCROLL_MODE = CommandType(command_class=0x02, command_id=0x14)
    GET_SCROLL_MODE = CommandType(command_class=0x02, command_id=0x94)
    SET_SCROLL_ACCELERATION = CommandType(command_class=0x02, command_id=0x16)
    GET_SCROLL_ACCELERATION = CommandType(command_class=0x02, command_id=0x96)

    SET_SCROLL_SMART_REEL = CommandType(command_class=0x02, command_id=0x17)
    GET_SCROLL_SMART_REEL = CommandType(command_class=0x02, command_id=0x97)

    MATRIX_EFFECT = CommandType(command_class=0x03, command_id=0x0A)
    MATRIX_SET_CUSTOM_FRAME = CommandType(command_class=0x03, command_id=0x0B)
    SET_LED_STATE = CommandType(command_class=0x03, command_id=0x00)
    SET_LED_BLINKING = CommandType(command_class=0x03, command_id=0x04)
    MATRIX_EFFECT_BASE_MOUSE = CommandType(command_class=0x03, command_id=0x0D)
    GET_LED_STATE = CommandType(command_class=0x03, command_id=0x80)
    SET_LED_RGB = CommandType(command_class=0x03, command_id=0x01)
    GET_LED_RGB = CommandType(command_class=0x03, command_id=0x81)
    SET_LED_EFFECT = CommandType(command_class=0x03, command_id=0x02)
    GET_LED_EFFECT = CommandType(command_class=0x03, command_id=0x82)
    SET_LED_BRIGHTNESS = CommandType(command_class=0x03, command_id=0x03)
    GET_LED_BRIGHTNESS = CommandType(command_class=0x03, command_id=0x83)
    ONE_ROW_SET_CUSTOM_FRAME = CommandType(command_class=0x03, command_id=0x0C)
    MATRIX_REACTIVE_TRIGGER = CommandType(command_class=0x03, command_id=0x0A)
    SET_DOCK_CHARGE_TYPE = CommandType(command_class=0x03, command_id=0x10)

    SET_DPI_XY = CommandType(command_class=0x04, command_id=0x05)
    GET_DPI_XY = CommandType(command_class=0x04, command_id=0x85)
    SET_DPI_XY_BYTE = CommandType(command_class=0x04, command_id=0x01)
    GET_DPI_XY_BYTE = CommandType(command_class=0x04, command_id=0x81)
    SET_DPI_STAGES = CommandType(command_class=0x04, command_id=0x06)
    GET_DPI_STAGES = CommandType(command_class=0x04, command_id=0x86)

    GET_BATTERY_LEVEL = CommandType(command_class=0x07, command_id=0x80)
    GET_CHARGING_STATE = CommandType(command_class=0x07, command_id=0x84)
    SET_DOCK_BRIGHTNESS = CommandType(command_class=0x07, command_id=0x02)
    GET_IDLE_TIME = CommandType(command_class=0x07, command_id=0x83)
    SET_IDLE_TIME = CommandType(command_class=0x07, command_id=0x03)
    GET_LOW_BATTERY_THRESHOLD = CommandType(command_class=0x07, command_id=0x81)

    SET_BLADE_BRIGHTNESS = CommandType(command_class=0x0E, command_id=0x04)
    GET_BLADE_BRIGHTNESS = CommandType(command_class=0x0E, command_id=0x84)

    TRINITY_EFFECT = CommandType(command_class=0x0F, command_id=0x03)
    GET_BRIGHTNESS = CommandType(command_class=0x0F, command_id=0x84)
    MATRIX_SET_CUSTOM_FRAME2 = CommandType(command_class=0x0F, command_id=0x03)
    MATRIX_BRIGHTNESS = CommandType(command_class=0x0F, command_id=0x04)
    MATRIX_EFFECT_BASE = CommandType(command_class=0x0F, command_id=0x02)

@functools.cache
class KeyboardStatus:
    def __init__(self):
        self.leds = []
        for row in range(5):
            self.leds.append([])
            for key in range(15):
                self.leds[row].append([0,0,0])
        self.last_print = ""
        self.device_mode = b"\x00\x00"
        self.preset_data = bytearray(64*4)

    def parse_trinity_effect(self, data):
        row = 0
        start = 0
        end = 0
        for i, b in enumerate(data):
            if i == 2:
                row = b
            if i == 3:
                start = b
            if i == 4:
                end = b
            if i >= 5 and ((i - 5) < ((end - start + 1) * 3)):
                key = start + int((i - 5) / 3)
                self.leds[row][key][(i - 5) % 3] = b

    def print(self):
        lines = f"DM: {self.device_mode[0]:02X}{self.device_mode[1]:02X}\n"
        lines += self.preset_data.hex() + "\n"
        for row in self.leds:
            line = ""
            for key in row:
                line += f"{key[0]:02X}{key[1]:02X}{key[2]:02X}"
            lines += f"{line}\n"

        if self.last_print != lines:
            print(lines)
            self.last_print = lines


    def set_device_mode(self, device_mode):
        self.device_mode = device_mode


    def get_device_mode(self):
        return self.device_mode

    def set_preset_data(self, preset_data):
        print('set_preset_data', preset_data.hex())
        offset = preset_data[2]
        for i, b in enumerate(preset_data[5:]):
            self.preset_data[offset+i] = b

    def get_preset_data(self, preset, offset):
        return b'\x02\x00' + bytes((offset,0x00,0xfa)) + self.preset_data[offset:offset+64]


def onSetupRazer(self, request_type, request, value, index, length):
    if (request_type & ch9.USB_TYPE_MASK) == ch9.USB_TYPE_CLASS:
        is_in = (request_type & ch9.USB_DIR_IN) == ch9.USB_DIR_IN
        recipient = request_type & ch9.USB_RECIP_MASK
        if request == hid.HID_REQ_SET_REPORT:
            if not is_in:
                if recipient == ch9.USB_RECIP_INTERFACE:
                    if value == 0x300:
                        if index != get_config("controlling_interface"):
                            trace("WARNING Using invalid interface, probably not parsing HID descriptor")
                        #trace("hid req set report")
                        buf = self.ep0.read(length)
                        #trace(buf)
                        header = struct.unpack(">BBHBBBB", buf[:8])

                        command = Command(
                            CommandType(command_class=header[5], command_id=header[6])
                        )

                        self.razer_report = {
                            "status": Status(header[0]),
                            "transaction_id": header[1],
                            "remaining_packets": header[2],
                            "protocol_type": header[3],
                            "data_size": header[4],
                            "command": command,
                        }

                        self.razer_report["data"] = buf[
                            8 : 8 + self.razer_report["data_size"]
                        ]
                        self.razer_report["crc"] = buf[88]
                        self.razer_report["reserved"] = buf[89]

                        if self.razer_report["command"] == Command.TRINITY_EFFECT:
                            KeyboardStatus().parse_trinity_effect(self.razer_report["data"])
                            KeyboardStatus().print()
                        elif self.razer_report["command"] == Command.SET_DEVICE_MODE:
                            KeyboardStatus().set_device_mode(self.razer_report["data"])
                            KeyboardStatus().print()
                        elif self.razer_report["command"] == Command.SET_PRESET_DATA:
                            KeyboardStatus().set_preset_data(self.razer_report["data"])
                            KeyboardStatus().print()
                        else:
                            trace(self.razer_report)

                        return True
        if request == hid.HID_REQ_GET_REPORT:
            if is_in:
                if recipient == ch9.USB_RECIP_INTERFACE:
                    if value == 0x300:
                        if index != get_config("controlling_interface"):
                            trace("WARNING Using invalid interface, probably not parsing HID descriptor")
                        trace("hid req get report")
                        command = self.razer_report["command"]
                        if command == Command.GET_SERIAL:
                            data = get_config("serial").encode("utf-8")
                        elif command == Command.GET_FIRMWARE_VERSION:
                            data = b"\x01\x00"
                        elif command == Command.READ_KBD_LAYOUT:
                            data = b"\x01\x00"
                        elif command == Command.UNKNOWN0580:
                            data = b"\x02"
                        elif command == Command.GET_DEVICE_MODE:
                            data = KeyboardStatus().get_device_mode()
                        elif command == Command.GET_PRESET_DATA:
                            data = KeyboardStatus().get_preset_data(self.razer_report["data"][0], self.razer_report["data"][2])
                        elif command == Command.UNKNOWN058A:
                            data = b"\x05"
                        elif command == Command.GET_DATA_MAX_FREE:
                            d_max = 458736
                            d_free = 457336
                            data = b"\xff\xff" + struct.pack(">II", d_max, d_free) + b"\x00\x00\x00\x00"
                        else:
                            data = b""

                        buf = struct.pack(
                            ">BBHBBBB",
                            Status.OK.value,  # status / start marker
                            self.razer_report["transaction_id"],  # transaction_id / id
                            0,  # remaining_packets
                            0,  # protocol_type
                            len(data),  # data_size / num params
                            command.value.command_class,
                            command.value.command_id,
                        )

                        buf += data
                        buf += b"\x00" * (80 - len(data))
                        buf += bytes([crc(buf)])
                        buf += b"\x00"
                        trace(len(buf))
                        self.ep0.write(buf)
                        return True
    return False


PROTOCOLS = {
    "keyboard": functionfs.hid.USB_INTERFACE_PROTOCOL_KEYBOARD,
    "mouse": functionfs.hid.USB_INTERFACE_PROTOCOL_MOUSE,
    "none": functionfs.hid.USB_INTERFACE_PROTOCOL_NONE,
}


class Function0(functionfs.HIDFunction):
    """
    Interface 0
    """

    def __init__(self, **kw):
        super().__init__(
            report_descriptor=bytes.fromhex(get_config("descriptor0")),
            protocol=PROTOCOLS[get_config("protocol0")],
            is_boot_device=get_config("is_boot_device0"),
            in_report_max_length=get_config("in_report_max_length0"),
            full_speed_interval=1,
            high_speed_interval=1,
            **kw,
        )

    def onSetup(self, request_type, request, value, index, length):
        #trace(
        #    f"request_type: {request_type} request: {request} value: {value} index: 0 length: {length}"
        #)
        if not (
            "0" in get_config("allowed_interfaces").split(",")
            and onSetupRazer(self, request_type, request, value, 0, length)
        ):
            super().onSetup(
                request_type,
                request,
                value,
                index,
                length,
            )


class Function1(functionfs.HIDFunction):
    """
    Interface 1
    """

    def __init__(self, **kw):
        super().__init__(
            report_descriptor=bytes.fromhex(get_config("descriptor1")),
            protocol=PROTOCOLS[get_config("protocol1")],
            is_boot_device=get_config("is_boot_device1"),
            in_report_max_length=get_config("in_report_max_length1"),
            full_speed_interval=1,
            high_speed_interval=1,
            **kw,
        )

    def onSetup(self, request_type, request, value, index, length):
        #trace(
        #    f"request_type: {request_type} request: {request} value: {value} index: 1 length: {length}"
        #)
        if not (
            "1" in get_config("allowed_interfaces").split(",")
            and onSetupRazer(self, request_type, request, value, 1, length)
        ):
            super().onSetup(
                request_type,
                request,
                value,
                index,
                length,
            )


class Function2(functionfs.HIDFunction):
    """
    Interface 2
    """

    def __init__(self, **kw):
        super().__init__(
            report_descriptor=bytes.fromhex(get_config("descriptor2")),
            protocol=PROTOCOLS[get_config("protocol2")],
            is_boot_device=get_config("is_boot_device2"),
            in_report_max_length=get_config("in_report_max_length2"),
            full_speed_interval=1,
            high_speed_interval=1,
            **kw,
        )

    def onSetup(self, request_type, request, value, index, length):
        #trace(
        #    f"request_type: {request_type} request: {request} value: {value} index: 2 length: {length}"
        #)
        if not (
            "2" in get_config("allowed_interfaces").split(",")
            and onSetupRazer(self, request_type, request, value, 2, length)
        ):
            super().onSetup(
                request_type,
                request,
                value,
                index,
                length,
            )


class Function3(functionfs.HIDFunction):
    """
    Interface 3
    """

    def __init__(self, **kw):
        self.razer_report = None
        super().__init__(
            report_descriptor=bytes.fromhex(get_config("descriptor3")),
            protocol=PROTOCOLS[get_config("protocol3")],
            is_boot_device=get_config("is_boot_device3"),
            in_report_max_length=get_config("in_report_max_length3"),
            full_speed_interval=1,
            high_speed_interval=1,
            **kw,
        )

    def onSetup(self, request_type, request, value, index, length):
        #trace(
        #    f"request_type: {request_type} request: {request} value: {value} index: 3 length: {length}"
        #)
        if not (
            "3" in get_config("allowed_interfaces").split(",")
            and onSetupRazer(self, request_type, request, value, 3, length)
        ):
            super().onSetup(
                request_type,
                request,
                value,
                index,
                length,
            )


class Function4(functionfs.HIDFunction):
    """
    Interface 4
    """

    def __init__(self, **kw):
        super().__init__(
            report_descriptor=bytes.fromhex(get_config("descriptor4")),
            protocol=PROTOCOLS[get_config("protocol4")],
            is_boot_device=get_config("is_boot_device4"),
            in_report_max_length=get_config("in_report_max_length4"),
            full_speed_interval=1,
            high_speed_interval=1,
            **kw,
        )

    def onSetup(self, request_type, request, value, index, length):
        #trace(
        #    f"request_type: {request_type} request: {request} value: {value} index: 4 length: {length}"
        #)
        if not (
            "4" in get_config("allowed_interfaces").split(",")
            and onSetupRazer(self, request_type, request, value, 4, length)
        ):
            super().onSetup(
                request_type,
                request,
                value,
                index,
                length,
            )


def get_config(key, use_default=None):
    """
    Get configuration
    """
    device_config = get_config.flattened[get_config.device]
    if use_default is None:
        return device_config[key]
    else:
        return device_config.get(key, use_default)


def main():
    """
    Entry point.
    """

    with open(
        pkg_resources.resource_filename("razer_emulator", "devices.toml"),
        encoding="utf-8",
    ) as f:
        get_config.flattened = parse_config(toml.load(f))

    parser = GadgetSubprocessManager.getArgumentParser(
        description="Razer Emulator",
    )
    parser.add_argument(
        "--device", help="device name (from devices.toml)", required=True
    )

    args = parser.parse_args()
    get_config.device = args.device

    function_list = []
    if get_config("descriptor0", ""):

        def get_config_function_subprocess0(**kw):
            return ConfigFunctionFFSSubprocess(getFunction=Function0, **kw)

        function_list.append(get_config_function_subprocess0)

    if get_config("descriptor1", ""):

        def get_config_function_subprocess1(**kw):
            return ConfigFunctionFFSSubprocess(getFunction=Function1, **kw)

        function_list.append(get_config_function_subprocess1)

    if get_config("descriptor2", ""):

        def get_config_function_subprocess2(**kw):
            return ConfigFunctionFFSSubprocess(getFunction=Function2, **kw)

        function_list.append(get_config_function_subprocess2)

    if get_config("descriptor3", ""):

        def get_config_function_subprocess3(**kw):
            return ConfigFunctionFFSSubprocess(getFunction=Function3, **kw)

        function_list.append(get_config_function_subprocess3)

    if get_config("descriptor4", ""):

        def get_config_function_subprocess4(**kw):
            return ConfigFunctionFFSSubprocess(getFunction=Function4, **kw)

        function_list.append(get_config_function_subprocess4)

    with GadgetSubprocessManager(
        args=args,
        config_list=[
            {
                "function_list": function_list,
                "MaxPower": 500,
            }
        ],
        lang_dict={
            0x409: {
                "product": get_config("product"),
                "manufacturer": get_config("manufacturer"),
            },
        },
        idVendor=int(get_config("idVendor"), 16),
        idProduct=int(get_config("idProduct"), 16),
    ) as gadget:
        print("Gadget ready, waiting for function to exit.")
        try:
            gadget.waitForever()
        finally:
            print("Gadget exiting.")
