"""Install crypto_probe_plugin.py AND the adjacent crypto_probe/ package into IDA plugins."""

import sys
from pathlib import Path
import idaapi

sys.path.insert(0, str(Path(__file__).resolve().parent))


class CryptoProbeMod(idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        from crypto_probe.ui import Controller

        self.controller = Controller()
        self.controller.install_actions()

    def run(self, arg):
        # Menu entry opens results; hotkeys/actions expose scan and debugger operations.
        self.controller.action("show")

    def __del__(self):
        try:
            self.controller.close()
        except Exception:
            pass


class CryptoProbePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    comment = "Offline crypto patterns, API argument provenance and debugger key/IV/nonce capture"
    help = "Ctrl+Alt+K scan all; Ctrl+Alt+J current function; Ctrl+Alt+R recursive; Ctrl+Alt+L suspended capture."
    wanted_name = "Crypto Probe (offline)"
    wanted_hotkey = ""

    def init(self):
        return CryptoProbeMod()


def PLUGIN_ENTRY():
    return CryptoProbePlugin()
