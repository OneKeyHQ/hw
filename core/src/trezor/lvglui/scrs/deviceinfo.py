import binascii

from storage import device
from trezor import uart, utils


class DeviceInfoManager:
    _instance = None
    preloaded_info = {}

    def preload_device_info(self):
        model = device.get_model()
        version = device.get_firmware_version()
        onekey_firmware_build_id = utils.BUILD_ID[-7:].decode()

        onekey_firmware_hash = utils.onekey_firmware_hash()
        hex_hash = binascii.hexlify(onekey_firmware_hash).decode("ascii")
        short_hash = hex_hash[:7]
        version = f"{version} [{onekey_firmware_build_id}-{short_hash}]"

        serial = device.get_serial()
        ble_name = device.get_ble_name() or uart.get_ble_name()
        ble_version = uart.get_ble_version()
        ble_build_id = uart.get_ble_build_id()
        ble_hash = uart.get_ble_hash()
        hex_hash = binascii.hexlify(ble_hash).decode("ascii")
        short_hash = hex_hash[:7]
        ble_version = f"{ble_version} [{ble_build_id}-{short_hash}]"

        boot_version = utils.boot_version()
        onekey_boot_hash = utils.boot_hash()
        hex_hash = binascii.hexlify(onekey_boot_hash).decode("ascii")
        short_hash = hex_hash[:7]
        onekey_boot_build_id = utils.boot_build_id()
        boot_version = f"{boot_version} [{onekey_boot_build_id}-{short_hash}]"
        board_version = utils.board_version()

        self.preloaded_info = {
            "version": version,
            "ble_name": ble_name,
            "ble_version": ble_version,
            "boot_version": boot_version,
            "board_version": board_version,
            "serial": serial,
            "model": model,
        }

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.preload_device_info()
        return cls._instance

    def get_info(self):
        return self.preloaded_info
