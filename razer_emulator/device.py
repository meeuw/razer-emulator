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

    BIND_KEYS = CommandType(command_class=0x02, command_id=0x12)
    # used by huntsman mini
    BIND_KEYS_2 = CommandType(command_class=0x02, command_id=0x0d)

    SET_PRESET_DATA = CommandType(command_class=0x05, command_id=0x08)
    GET_PRESET_DATA = CommandType(command_class=0x05, command_id=0x88)
    GET_DATA_MAX_FREE = CommandType(command_class=0x06, command_id=0x8E)
    GET_ACTIVE_PRESETS = CommandType(command_class=0x05, command_id=0x81)
    DEL_PRESET = CommandType(command_class=0x05, command_id=0x03)
    GET_ACTIVE_PRESETS_LEN = CommandType(command_class=0x05, command_id=0x80)


    UNKNOWN0292 = CommandType(command_class=0x02, command_id=0x92)

    UNKNOWN0502 = CommandType(command_class=0x05, command_id=0x02) # write preset / start up
    UNKNOWN058A = CommandType(command_class=0x05, command_id=0x8A) # start up (amount of available presets?)

    UNKNOWN0603 = CommandType(command_class=0x06, command_id=0x03) # macro (rename)
    UNKNOWN0608 = CommandType(command_class=0x06, command_id=0x08) # macro
    UNKNOWN0609 = CommandType(command_class=0x06, command_id=0x09) # macro
    UNKNOWN060C = CommandType(command_class=0x06, command_id=0x0C) # macro
    UNKNOWN0680 = CommandType(command_class=0x06, command_id=0x80) # delete preset / start up

    UNKNOWN060A = CommandType(command_class=0x06, command_id=0x0A) # device reset
    UNKNOWN068A = CommandType(command_class=0x06, command_id=0x8A) # device reset

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
        self.last_print = ""
        self.device_mode = b"\x00\x00"
        self.preset_data = {1: bytearray(64*4-1)}
        self.unhandled = []

    def unhandled_command(self, command):
        if not command in self.unhandled:
            self.unhandled.append(command)

    def parse_trinity_effect(self, data):
        row = 0
        start = 0
        end = 0
        for i, b in enumerate(data):
            if i == 2:
                row = b
                if len(self.leds) <= row:
                    self.leds.append([])
            if i == 3:
                start = b
            if i == 4:
                end = b
            if i >= 5 and ((i - 5) < ((end - start + 1) * 3)):
                key = start + int((i - 5) / 3)
                if len(self.leds[row]) <= key:
                    self.leds[row].append([0,0,0])
                self.leds[row][key][(i - 5) % 3] = b

    def print(self):
        lines = f"DM: {self.device_mode[0]:02X}{self.device_mode[1]:02X}\n"
        for preset, preset_data in self.preset_data.items():
            lines += f"{preset}: {preset_data.hex()}\n"
        for row in self.leds:
            line = ""
            for key in row:
                line += f"{key[0]:02X}{key[1]:02X}{key[2]:02X}"
            lines += f"{line}\n"
        for unhandled in self.unhandled:
            lines += f"Unhandled: {hex(unhandled.value.command_class)} {hex(unhandled.value.command_id)}\n"

        if self.last_print != lines:
            trace(lines)
            self.last_print = lines


    def set_device_mode(self, device_mode):
        self.device_mode = device_mode


    def get_device_mode(self):
        return self.device_mode

    def set_preset_data(self, preset_data):
        trace('set_preset_data', preset_data.hex())
        preset = preset_data[0]
        offset = preset_data[2]
        size = preset_data[4]

        if not preset in self.preset_data:
            self.preset_data[preset] = bytearray(size)

        for i, b in enumerate(preset_data[5:]):
            self.preset_data[preset][offset+i] = b

        self.preset_data[1] = self.preset_data[preset]

    def get_preset_data(self, preset, offset):
        if preset in self.preset_data:
            preset_data = self.preset_data[preset]
        else:
            preset_data = bytes(64 * 4 - 1)
        size = len(preset_data)
        return bytes((preset, 0x00, offset,0x00,size)) + preset_data[offset:min(offset+64, size)]

    def get_active_presets(self):
        return sorted(self.preset_data.keys())

    def del_preset(self, preset):
        if preset in self.preset_data:
            del self.preset_data[preset]


PROTOCOLS = {
    "keyboard": functionfs.hid.USB_INTERFACE_PROTOCOL_KEYBOARD,
    "mouse": functionfs.hid.USB_INTERFACE_PROTOCOL_MOUSE,
    "none": functionfs.hid.USB_INTERFACE_PROTOCOL_NONE,
}


class RazerFunction(functionfs.HIDFunction):
    def __init__(self, **kw):
        super().__init__(
            report_descriptor=bytes.fromhex(get_config(f"descriptor{self.interface_id}")),
            protocol=PROTOCOLS[get_config(f"protocol{self.interface_id}")],
            is_boot_device=get_config(f"is_boot_device{self.interface_id}"),
            in_report_max_length=get_config(f"in_report_max_length{self.interface_id}"),
            full_speed_interval=1,
            high_speed_interval=1,
            **kw,
        )

    def onSetupRazer(self, request_type, request, value, index, length):
        #trace(f"request_type: {request_type} request: {request} value: {value} index: {index} length: {length}")
        if (request_type & ch9.USB_TYPE_MASK) == ch9.USB_TYPE_CLASS:
            is_in = (request_type & ch9.USB_DIR_IN) == ch9.USB_DIR_IN
            recipient = request_type & ch9.USB_RECIP_MASK
            if request == hid.HID_REQ_SET_REPORT:
                if not is_in:
                    if recipient == ch9.USB_RECIP_INTERFACE:
                        # HID_FEATURE_REPORT (HID_FEATURE_REPORT + 1) / REPORT_NUMBER
                        if value == 0x0300:
                            if index != get_config("controlling_interface"):
                                trace(f"WARNING Using invalid interface {index}, probably not parsing HID descriptor")
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

                            if self.razer_report["transaction_id"] != 0x1f:
                                trace("WARNING Using invalid transaction_id")

                            if self.razer_report["command"] == Command.TRINITY_EFFECT:
                                KeyboardStatus().parse_trinity_effect(self.razer_report["data"])
                                KeyboardStatus().print()
                            elif self.razer_report["command"] == Command.SET_DEVICE_MODE:
                                KeyboardStatus().set_device_mode(self.razer_report["data"])
                                KeyboardStatus().print()
                            elif self.razer_report["command"] == Command.SET_PRESET_DATA:
                                KeyboardStatus().set_preset_data(self.razer_report["data"])
                                KeyboardStatus().print()
                            elif self.razer_report["command"] == Command.DEL_PRESET:
                                KeyboardStatus().del_preset(self.razer_report["data"][0])
                                KeyboardStatus().print()
                            elif self.razer_report["command"] == Command.BIND_KEYS:
                                preset = self.razer_report["data"][0]
                                from_key = self.razer_report["data"][1]
                                is_fn = self.razer_report["data"][2]
                                actuation_point = self.razer_report["data"][3]
                                release_point = self.razer_report["data"][4]
                                # type
                                # 0 disable
                                # 1 mouse
                                # 2 keyboard
                                # 3 macro (play once)
                                # 4 macro (play while assigned key is pressed)
                                # 5 macro (toggle continuous playback)
                                # 10 multimedia
                                # 11 double click
                                # 12 fn
                                bind_keys_type = self.razer_report["data"][5]
                                parameters_len = self.razer_report["data"][6]
                                parameters = self.razer_report["data"][7:7+parameters_len]
                                trace(f"preset: {preset} from_key: {from_key} is_fn: {is_fn} actuation_point: {actuation_point} release_point: {release_point} bind_keys_type: {bind_keys_type} parameters: {parameters}")
                            else:
                                KeyboardStatus().unhandled_command(self.razer_report["command"])
                                trace(self.razer_report)

                            return True
            if request == hid.HID_REQ_GET_REPORT:
                if is_in:
                    if recipient == ch9.USB_RECIP_INTERFACE:
                        # HID_FEATURE_REPORT (HID_FEATURE_REPORT + 1) / REPORT_NUMBER
                        if value == 0x0300:
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
                            elif command == Command.GET_ACTIVE_PRESETS_LEN:
                                data = bytes((len(KeyboardStatus().get_active_presets()),))
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
                            elif command == Command.UNKNOWN0087:
                                data = b"\x01"
                            elif command == Command.GET_ACTIVE_PRESETS:
                                active_presets = KeyboardStatus().get_active_presets()
                                data = bytearray(65)
                                if len(active_presets) > 1:
                                    data[0] = len(active_presets)
                                    for offset, preset in enumerate(active_presets):
                                        data[offset + 1] = preset
                            else:
                                data = self.razer_report["data"]

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

    def onSetup(self, request_type, request, value, index, length):
        #trace(
        #    f"request_type: {request_type} request: {request} value: {value} index: 0 length: {length}"
        #)
        if not (
            str(self.interface_id) in get_config("allowed_interfaces").split(",")
            and self.onSetupRazer(request_type, request, value, self.interface_id, length)
        ):
            super().onSetup(
                request_type,
                request,
                value,
                index,
                length,
            )

    def getEndpointClass(self, is_in, descriptor):
        """
        Tall HIDFunction that we want it to use our custom IN endpoint class
        for our only IN endpoint.
        """
        if is_in:
            return HIDINEndpoint
        return super().getEndpointClass(is_in, descriptor)


    def onEnable(self):
        super().onEnable()
        return
        trace("onEnable")
        super().onEnable()
        data1 = bytearray(23)
        data1[0] = 0x07
        data1[1] = 0x16 # Y
        data1[2] = 0xff
        data1[3] = 0x3b # FN
        data1[4] = 0xff
        data2 = bytearray(23)
        data2[0] = 0x07
        data2[1] = 0x16
        data2[2] = 0x0
        data2[3] = 0x3b
        data2[4] = 0x0
        self.getEndpoint(1).submit(
            (data1, data2)
        )


class HIDINEndpoint(functionfs.EndpointINFile):
    """
    Customise what happens on IN transfer completion.
    In a real device, here may be where you would sample and clear the current
    movement deltas, and construct a new HID report to send to the host.
    """
    def onComplete(self, buffer_list, user_data, status):
        #trace("onComplete")
        if status < 0:
            if status == -errno.ESHUTDOWN:
                # Mouse is unplugged, host selected another configuration, ...
                # Stop submitting the transfer.
                return False
            raise IOError(-status)
        # Resubmit the transfer. We did not change its buffer, so the
        # mouse movement will carry on identically.
        return True




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

    for interface in range(5):
        if get_config(f"descriptor{interface}", ""):
            class Function(RazerFunction):
                interface_id = interface

            def get_function(cls):
                def get_config_function_subprocess(**kw):
                    return ConfigFunctionFFSSubprocess(getFunction=cls, **kw)
                return get_config_function_subprocess
            function_list.append(get_function(Function))

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
