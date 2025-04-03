import ida_frame
import ida_typeinf
import idaapi, re
import idc
from ida_typeinf import udm_t
from idadex import ea_t

from HexRaysPyTools.log import Log
logger = Log.get_logger()

name_regex = re.compile(r"^a[\d]*[a]?$")

class VarRenameHooks(idaapi.IDB_Hooks):

    def frame_udm_renamed(self, func_ea: "ea_t", udm: "udm_t", oldname: "char const *"):
        logger.debug(f"Rename hook called. func_ea = {func_ea:#x}, udm = {udm}, oldname = {oldname}")
        if name_regex.match(udm.name):
            ida_func = idaapi.get_func(func_ea)
            if ida_func:
                if not ida_frame.is_funcarg_off(ida_func, udm.offset//8):
                    frame_tif = ida_typeinf.tinfo_t(ida_func.frame)
                    udm_idx = frame_tif.find_udm(udm.offset)
                    frame_tif.rename_udm(udm_idx, oldname)
        return 0



rename_hook = VarRenameHooks()
rename_hook.hook()