import ida_frame
import ida_funcs
import ida_typeinf
import ida_hexrays
import idaapi, re
import idc
from ida_typeinf import udm_t
from idadex import ea_t

from . import callbacks

from HexRaysPyTools.log import Log
logger = Log.get_logger()

name_regex = re.compile(r"^a[\d]*[a]?$")

class VarRenameHooks(idaapi.IDB_Hooks):

    def frame_udm_renamed(self, func_ea: "ea_t", udm: "udm_t", oldname: "char const *"):
        logger.debug(f"Rename hook called. func_ea = {func_ea:#x}, udm = {udm}, oldname = {oldname}, newname = {udm.name}")
        if name_regex.match(udm.name):
            ida_func = ida_funcs.get_func(func_ea)
            if ida_func:
                if not ida_frame.is_funcarg_off(ida_func, udm.offset//8):
                    frame_tif = ida_typeinf.tinfo_t()
                    if ida_frame.get_func_frame(frame_tif, ida_func):
                        udm_idx = frame_tif.find_udm(udm.offset)
                        frame_tif.rename_udm(udm_idx, oldname)
        return 0

    def frame_udm_changed(self, func_ea: "ea_t", udm_tid: "tid_t", udmold: "udm_t", udmnew: "udm_t") -> "void":
        logger.debug(f"frame_udm_changed. func_ea = 0x{func_ea:#x}, udm_tid = 0x{udm_tid:#x}, udmold.name = {udmold.name}, udmnew.name = {udmnew.name}")
        return 0

class LvarHooks(ida_hexrays.Hexrays_Hooks):
    """Hex-Rays hooks for lvar change notifications."""

    # (vdui_t* vu, lvar_t* v, const char* name, bool is_user_name) -> int
    def lvar_name_changed(self, vu, v, name, is_user_name):
        print(
            f"[py_lvar] name_changed  vu={vu} v.name = {v.name}  name = {name}  user={is_user_name}"
        )
        return 0

    # (vdui_t* vu, lvar_t* v, const tinfo_t* tinfo) -> int

hx_hook = LvarHooks()


rename_hook = VarRenameHooks()
rename_hook.hook()

