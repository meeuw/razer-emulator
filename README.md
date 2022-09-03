# Razer Emulator

## Description

Emulate Razer hardware so it can be tested using Synapse, OpenRazer or other projects.

## Installation

Checkout, run `poetry install`

## Usage

I'm using `dummy_hcd` (a software emulated host controller) and the libcomposite
kernel modules but I guess this should also work with hardware hcds.

Start razer-emulator as root, it's required to specify a device name (from [razer-emulator/devices.toml](devices.toml)).

```bash
razer-emulator --device razer_huntsman
```

Forward the USB device to your virtual machine, for QEMU I use (find the
hostbus/hostaddr using `lsusb`):

```
device_add usb-host,id=razer,hostbus=5,hostaddr=2
```

To remove the device use:

```
device_del razer
```

Razer Emulator will output all received HID reports to stdout. Most requests are
answered by zero values (WIP).

In case an unknown command is received the script will fail. Please add the
unknown command to this script.

## Design Goals

* Be compatible and testable with all known implementations (Synapse,
  Open Razer, uChroma)
* Reference is always a real device, in case of doubt: it should glitch and
  quirk in the same way.
* Use a configuration file to define the hardware device behaviour

## How can I help

Please supply me with `lsusb -v` and `usbhid-dump -m 1532:0282 -ea` dumps for
unknown devices. Send pull requests.

## TO DO

* Validate received commands
* Be able to interface back (send keypresses)
* Add support for other device types like mice and headsets
