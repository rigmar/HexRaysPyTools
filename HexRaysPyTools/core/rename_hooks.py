import idaapi, re
import idc
from HexRaysPyTools.log import Log
logger = Log.get_logger()

name_regex = re.compile(r"^a[\d]*[a]?$")


renamed_fields = {}

class VarRenameHooks(idaapi.IDB_Hooks):

    def renaming_struc_member(self, sptr, mptr, newname):
        if sptr.is_frame():
            if name_regex.match(newname):
                func_off = idaapi.get_func_by_frame(sptr.id)
                pfn = idaapi.get_func(func_off)
                if not idaapi.is_funcarg_off(pfn,mptr.soff):
                    global renamed_fields
                    logger.debug("My_IDB_Hooks: Frame of function at 0x%08X" % func_off)
                    logger.debug("My_IDB_Hooks: Frame member new name is %s" % newname)
                    old_name = idc.get_member_name(mptr.id,mptr.soff)
                    logger.debug("My_IDB_Hooks: Frame member old name is %s\n" % old_name)
                    if func_off not in renamed_fields:
                        renamed_fields[func_off] = {}
                    renamed_fields[func_off][mptr.soff] = old_name
        return 0

    def struc_member_renamed(self, sptr, mptr):
        if sptr.is_frame():
            func_off = idaapi.get_func_by_frame(sptr.id)
            pfn = idaapi.get_func(func_off)
            if not idaapi.is_funcarg_off(pfn, mptr.soff):
                new_name = idc.get_member_name(mptr.id,mptr.soff)
                if name_regex.match(new_name):
                    global renamed_fields
                    if func_off in renamed_fields:
                        if mptr.soff in renamed_fields[func_off]:
                            old_name = renamed_fields[func_off][mptr.soff]
                            idc.set_member_name(sptr.id ,mptr.soff,old_name)
                            del renamed_fields[func_off][mptr.soff]
                            if len(renamed_fields[func_off]) == 0:
                                del renamed_fields[func_off]
        return 0

rename_hook = VarRenameHooks()