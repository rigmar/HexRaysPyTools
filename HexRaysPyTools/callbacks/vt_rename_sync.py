from ida_idaapi import BADADDR
from ida_typeinf import udm_t

from HexRaysPyTools.log import Log

import idaapi
import ida_idp, ida_nalt, ida_bytes
import ida_name
import ida_typeinf
import idc
import ida_funcs

from HexRaysPyTools.netnode import Netnode
import HexRaysPyTools.core.const as Const
import HexRaysPyTools.core.helper as helper
logger = Log.get_logger()

def get_vt_from_node(type_ord):
    n = Netnode("$ VTables")
    if type_ord in n:
        return n[type_ord]
    else:
        return None

def get_vt_from_node_by_addr(addr):
    offset = addr - ida_nalt.get_imagebase()
    n = Netnode("$ VTables")
    ret = []
    for type_ord in n.keys():
        vt = n[type_ord]
        if offset in vt:
            ret = ret + [(type_ord, i) for i, x in enumerate(vt) if x == offset]
    return ret

def global_get_class_name(full_name):
    if "::" in full_name:
        class_name, meth_name = full_name.rsplit("::", 1)
    else:
        # class_name = ida_typeinf.get_struc_name(sid).rsplit("_vtbl",1)[0]
        class_name = ""
        meth_name = full_name

    return class_name, meth_name

def struct_get_class_name(type_ord, udm):
    meth_full_name = udm.name
    if "::" in meth_full_name:
        class_name, meth_name = meth_full_name.rsplit("::", 1)
    else:
        class_name = ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(), type_ord).rsplit("_vtbl",1)[0]
        meth_name = meth_full_name

    return class_name, meth_name




class VtMethodsRenameSync_hook(ida_idp.IDB_Hooks):

    def __init__(self):
        self.renaming = {'global':[], 'struct':[]}

        super().__init__()

    def rename_vt_struct_members(self, func_ea, new_name, exclude_type_ord=0):
        vt_list = get_vt_from_node_by_addr(func_ea)
        if len(vt_list) > 0:
            global_class_name, new_meth_name = global_get_class_name(new_name)
            for type_ord, meth_idx in vt_list:
                if type(type_ord) == int:
                    logger.debug("rename_vt_struct_members type_ord = %d, exclude_type_ord = %d " % (type_ord, exclude_type_ord))
                    if type(type_ord) == int and (exclude_type_ord == 0 or exclude_type_ord != type_ord):
                        tif = ida_typeinf.tinfo_t(ordinal=type_ord)
                        udm = tif.get_udm(meth_idx)
                        # struct_class_name, old_meth_name = struct_get_class_name(sid, meth_member)
                        self.renaming['struct'].append((type_ord, udm.offset))
                        tif.rename_udm(meth_idx, new_meth_name)

    def renamed(self, ea, new_name, local_name, old_name):

        logger.debug("Renamed at 0x%08X from '%s' to '%s', local = %s" % (ea, old_name, new_name, 'True' if local_name else "False"))
        pass
        # if not idc.is_member_id(ea) and ida_typeinf.get_struc(ea) is None:
        #     logger.debug("Renamed at 0x%08X from '%s' to '%s', local = %s"%(ea, old_name, new_name, 'True' if local_name else "False"))
        #     if ea in self.renaming['global']:
        #         logger.debug("Ignore 0x%08X" % ea)
        #         self.renaming['global'].remove(ea)
        #     else:
        #         if ida_bytes.is_func(ida_bytes.get_full_flags(ea)):
        #             self.rename_vt_struct_members(ea, new_name)

    def lt_udm_renamed(self, udtname: "char const *", udm: "udm_t", oldname: "char const *"):
        logger.debug(f"lt_udm_renamed: udtname = {udtname}, udm = {udm}, oldname = {oldname}, newname = {udm.name}")
        type_ord = ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), udtname)
        if type_ord != 0:
            mem_offset = udm.offset
            if (type_ord, mem_offset) in self.renaming['struct']:
                logger.debug("Ignore type_ord = %d (%s), mptr.soff = 0x%02X" % (type_ord, ida_typeinf.get_numbered_type_name(ida_typeinf.get_idati(), type_ord), udm.offset//8))
                self.renaming['struct'].remove((type_ord, mem_offset))
            else:
                vt = get_vt_from_node(type_ord)
                if vt:
                    meth_idx = udm.offset // Const.EA_SIZE // 8
                    meth_offset = vt[meth_idx]
                    class_name, meth_name = struct_get_class_name(type_ord, udm)
                    e = ida_name.set_name(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name, ida_name.SN_NOWARN)
                    if e == 0:
                        l = 0
                        while e == 0:
                            e = ida_name.set_name(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name + "_%d" % l, ida_name.SN_NOWARN)
                            l += 1
                    self.rename_vt_struct_members(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name, type_ord)




vt_rename_hooks = VtMethodsRenameSync_hook()
vt_rename_hooks.hook()
