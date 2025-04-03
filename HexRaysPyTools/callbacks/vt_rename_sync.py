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

def get_vt_from_node(sid):
    n = Netnode("$ VTables")
    if sid in n:
        return n[sid]
    else:
        return None

def get_vt_from_node_by_addr(addr):
    offset = addr - ida_nalt.get_imagebase()
    n = Netnode("$ VTables")
    ret = []
    for sid in n.keys():
        vt = n[sid]
        if offset in vt:
            ret.append((sid, vt.index(offset)))
    return ret

def global_get_class_name(full_name):
    if "::" in full_name:
        class_name, meth_name = full_name.rsplit("::", 1)
    else:
        # class_name = ida_typeinf.get_struc_name(sid).rsplit("_vtbl",1)[0]
        class_name = ""
        meth_name = full_name

    return class_name, meth_name

def struct_get_class_name(sid, udm):
    meth_full_name = udm.name
    if "::" in meth_full_name:
        class_name, meth_name = meth_full_name.rsplit("::", 1)
    else:
        class_name = ida_typeinf.get_tid_name(sid).rsplit("_vtbl",1)[0]
        meth_name = meth_full_name

    return class_name, meth_name




class VtMethodsRenameSync_hook(ida_idp.IDB_Hooks):

    def __init__(self):
        self.renaming = {'global':[], 'struct':[]}

        super().__init__()

    def rename_vt_struct_members(self, func_ea, new_name, exclude_sid=None):
        vt_list = get_vt_from_node_by_addr(func_ea)
        if len(vt_list) > 0:
            global_class_name, new_meth_name = global_get_class_name(new_name)
            for sid, meth_idx in vt_list:
                if type(sid) == int:
                    logger.debug("rename_vt_struct_members sid = 0x%08X, exclude_sid = 0x%08X " % (sid, exclude_sid if exclude_sid is not None else 0xFFFFFFFF))
                    if type(sid) == int and (exclude_sid is None or exclude_sid != sid):
                        meth_member = helper.get_member(helper.get_struc(sid), Const.EA_SIZE * meth_idx)
                        # struct_class_name, old_meth_name = struct_get_class_name(sid, meth_member)
                        self.renaming['struct'].append((sid, helper.get_member_id_by_udm(sid, meth_member)))
                        idc.set_member_name(sid, meth_member.offset//8, new_meth_name)

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
        struct_id = idc.get_struc_id(udtname)
        if struct_id != BADADDR:
            mid = helper.get_member_id_by_udm(struct_id, udm)
            if (struct_id, mid) in self.renaming['struct']:
                logger.debug("Ignore sid = 0x%08X (%s), mptr.soff = 0x%02X" % (struct_id, ida_typeinf.get_tid_name(struct_id), udm.offset//8))
                self.renaming['struct'].remove((struct_id, mid))
            else:
                vt = get_vt_from_node(struct_id)
                if vt:
                    meth_idx = udm.offset // Const.EA_SIZE // 8
                    meth_offset = vt[meth_idx]
                    class_name, meth_name = struct_get_class_name(struct_id, udm)
                    e = ida_name.set_name(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name, ida_name.SN_NOWARN)
                    if e == 0:
                        l = 0
                        while e == 0:
                            e = ida_name.set_name(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name + "_%d" % l, ida_name.SN_NOWARN)
                            l += 1
                    self.rename_vt_struct_members(meth_offset + ida_nalt.get_imagebase(), class_name + "::" + meth_name, struct_id)




vt_rename_hooks = VtMethodsRenameSync_hook()
vt_rename_hooks.hook()
