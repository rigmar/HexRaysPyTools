from ida_typeinf import udm_t

from HexRaysPyTools.log import Log

import ida_idp, ida_nalt, ida_bytes
import ida_name
import ida_typeinf


import HexRaysPyTools.core.const as Const
import HexRaysPyTools.core.helper as helper
from HexRaysPyTools.settings import get_config

logger = Log.get_logger()






class VtMethodsRenameSync_hook(ida_idp.IDB_Hooks):

    def __init__(self):
        self.renaming = {'global':[], 'struct':[]}

        super().__init__()

    def rename_vt_struct_members(self, func_ea, new_name, exclude_type_ord=0):
        vt_list = helper.get_vt_from_node_by_addr(func_ea)
        if len(vt_list) > 0:
            global_class_name, new_meth_name = helper.global_get_class_name(new_name)
            for type_ord, meth_idx in vt_list:
                if type(type_ord) == int:
                    logger.debug("rename_vt_struct_members type_ord = %d, exclude_type_ord = %d " % (type_ord, exclude_type_ord))
                    if type(type_ord) == int and (exclude_type_ord == 0 or exclude_type_ord != type_ord):
                        tif = ida_typeinf.tinfo_t(ordinal=type_ord)
                        idx, udm = tif.get_udm(meth_idx)
                        if udm is not None:
                            # struct_class_name, old_meth_name = struct_get_class_name(sid, meth_member)
                            self.renaming['struct'].append((type_ord, udm.offset))
                            rc = tif.rename_udm(meth_idx, new_meth_name)
                            logger.debug(f"if.rename_udm return {rc}, meth_idx = {meth_idx}, new_name = {new_name}")
                            if rc != 0 and rc == -21:
                                l = 0
                                while rc == -21:
                                    rc = tif.rename_udm(meth_idx, new_name + "_%d"%l)
                                    l += 1
                                if rc != 0:
                                    logger.error(f"tif.rename_udm rc = {rc}, new_name = {new_name}, type_ord = {type_ord}, meth_idx = {meth_idx}")
                            elif rc != 0:
                                logger.error(f"if.rename_udm return {rc}, meth_idx = {meth_idx}, new_name = {new_name}")
                        else:
                            logger.error(f"tif.get_udm(meth_idx) error")

    def renamed(self, ea, new_name, local_name, old_name):
        logger.debug("Renamed at 0x%08X from '%s' to '%s', local = %s" % (ea, old_name, new_name, 'True' if local_name else "False"))
        if ida_bytes.is_mapped(ea) and ida_bytes.is_func(ida_bytes.get_flags_ex(ea, 0)):
            if ea in self.renaming['global']:
                logger.debug("Ignore 0x%08X" % ea)
                self.renaming['global'].remove(ea)
            else:
                self.rename_vt_struct_members(ea, new_name)
        return ida_idp.IDB_Hooks.renamed(self, ea, new_name, local_name, old_name)

    def lt_udm_renamed(self, udtname: "char const *", udm: "udm_t", oldname: "char const *"):
        logger.debug(f"lt_udm_renamed: udtname = {udtname}, udm = {udm}, oldname = {oldname}, newname = {udm.name}")
        type_ord = ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), udtname)
        if type_ord != 0:
            mem_offset = udm.offset
            if (type_ord, mem_offset) in self.renaming['struct']:
                logger.debug("Ignore type_ord = %d (%s), mptr.soff = 0x%02X" % (type_ord, ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(), type_ord), udm.offset//8))
                self.renaming['struct'].remove((type_ord, mem_offset))
            else:
                vt = helper.get_vt_from_node(type_ord)
                if vt:
                    meth_idx = udm.offset // Const.EA_SIZE // 8
                    meth_offset = vt[meth_idx]
                    class_name, meth_name = helper.struct_get_class_name(type_ord, udm)
                    global_class_name, global_meth_name = helper.global_get_class_name(ida_name.get_name(ida_nalt.get_imagebase() + meth_offset))
                    if global_class_name:
                        class_name = global_class_name
                    self.renaming['global'].append(ida_nalt.get_imagebase() + meth_offset)
                    e = ida_name.set_name(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name, ida_name.SN_NOWARN)
                    logger.debug(f"ida_name.set_name return {e}, class_name = {class_name}, meth_name = {meth_name} , meth_offset = {meth_offset:X}")
                    if e == 0:
                        l = 0
                        while e == 0:
                            e = ida_name.set_name(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name + "_%d" % l, ida_name.SN_NOWARN)
                            l += 1
                    self.rename_vt_struct_members(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name, type_ord)



if get_config().get_opt("Virtual table creation", "VT names/field names sync"):
    vt_rename_hooks = VtMethodsRenameSync_hook()
    vt_rename_hooks.hook()
