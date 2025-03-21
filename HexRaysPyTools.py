import logging

import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
import HexRaysPyTools.settings as settings
import idaapi
from HexRaysPyTools.callbacks import action_manager, hx_callback_manager
from HexRaysPyTools.core.struct_xrefs import XrefStorage
from HexRaysPyTools.core.temporary_structure import TemporaryStructureModel
from HexRaysPyTools.core.helper import init_hexrays
from HexRaysPyTools.forms import StructureBuilder


class HexRaysPyTools(idaapi.plugin_t):
    flags = 0
    comment = "Plugin for automatic classes reconstruction"
    help = "See https://github.com/igogo-x86/HexRaysPyTools/blob/master/readme.md"
    wanted_name = "HexRaysPyTools"
    wanted_hotkey = ""

    @staticmethod
    def init():
        if not init_hexrays():
            logging.error("Failed to initialize Hex-Rays SDK")
            return idaapi.PLUGIN_SKIP

        action_manager.initialize()
        hx_callback_manager.initialize()
        cache.temporary_structure = TemporaryStructureModel()
        const.init()
        XrefStorage().open()
        return idaapi.PLUGIN_KEEP

    @staticmethod
    def run(*args):
        tform = idaapi.find_widget("Structure Builder")
        if tform:
            idaapi.activate_widget(tform, True)
        else:
            StructureBuilder(cache.temporary_structure).Show()

    @staticmethod
    def term(*args):
        action_manager.finalize()
        hx_callback_manager.finalize()
        XrefStorage().close()
        idaapi.term_hexrays_plugin()


def PLUGIN_ENTRY():
    settings.load_settings()
    logging.basicConfig(format="[%(levelname)s] %(message)s\t(%(module)s:%(funcName)s)")
    logging.root.setLevel(settings.DEBUG_MESSAGE_LEVEL)
    idaapi.notify_when(idaapi.NW_OPENIDB, cache.initialize_cache)
    return HexRaysPyTools()
