import idaapi

import idc
import ida_hexrays
from . import callbacks
import HexRaysPyTools.core.helper as helper
from ..core import const
from ..netnode import Netnode
from ..settings import get_config
fDebug = False
if fDebug:
    import pydevd_pycharm

CALLED_FROM_COMMENT = "CALLED_FROM =>"

class MemberDoubleClick(callbacks.HexRaysEventHandler):
    def __init__(self):
        super(MemberDoubleClick, self).__init__()

    def _get_target_func_comment(self, func_ea, item):
        target_func = idaapi.decompile(func_ea)
        tl = ida_hexrays.treeloc_t()
        tl.ea = target_func.body.ea
        tl.itp = ida_hexrays.ITP_SEMI
        old_comment = target_func.get_user_cmt(tl, 0)
        jmp_src = item.e.ea
        src_as_string = "0x{:x}".format(jmp_src)
        if old_comment is None:
            old_comment = CALLED_FROM_COMMENT
        if src_as_string not in old_comment:
            return "{} | {}".format(old_comment, src_as_string)
        return old_comment

    def _update_func_comment_and_jump(self, func_ea, new_comment):
        target_func = idaapi.decompile(func_ea)
        tl = ida_hexrays.treeloc_t()
        tl.ea = target_func.body.ea
        tl.itp = ida_hexrays.ITP_SEMI
        target_func.set_user_cmt(tl, new_comment)
        target_func.save_user_cmts()
        idaapi.jumpto(func_ea)

    def _handle_member_pointer(self, item):
        if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
            return item.e.x.type.get_pointed_object(), item.e.m, item.e.x.x.x.type.get_pointed_object(), item.e.x.x.m
        elif item.e.x.op == idaapi.cot_memptr:
            vtable_tinfo = item.e.x.type
            if vtable_tinfo.is_ptr():
                vtable_tinfo = vtable_tinfo.get_pointed_object()
            return vtable_tinfo, item.e.m, item.e.x.x.type.get_pointed_object(), item.e.x.m

    def handle(self, event, *args):
        if fDebug:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=True)
        hx_view = args[0]
        item = hx_view.item
        vtable_tinfo = None
        method_offset = None
        class_tinfo = None
        vtable_offset = None
        if item.citype == idaapi.VDI_EXPR and item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
            if item.e.x.op in (idaapi.cot_memref, idaapi.cot_memptr):
                vtable_tinfo, method_offset, class_tinfo, vtable_offset = self._handle_member_pointer(item)
            else:
                if item.e.x is not None and item.e.x.op != idaapi.cot_empty:
                    vtable_tinfo = item.e.x.type
                    if vtable_tinfo:
                        while vtable_tinfo.is_ptr():
                            vtable_tinfo = vtable_tinfo.get_pointed_object()
                        method_offset = item.e.m
            if get_config().get_opt("Member double click", "JumpByNetnodeVT"):
                if method_offset is not None and vtable_tinfo:
                    n = Netnode("$ VTables")
                    vt_name = vtable_tinfo.get_type_name()
                    struct_id = idaapi.get_struc_id(vt_name)
                    if vt_name and vt_name in n:
                        l = n[vt_name]
                        if not const.EA64:
                            ptr_size = 4
                        else:
                            ptr_size = 8
                        if method_offset % ptr_size == 0 and method_offset // ptr_size < len(l) and l[method_offset // ptr_size] is not None:
                            idaapi.jumpto(l[method_offset // ptr_size] + idaapi.get_imagebase())
                            return 1
                    elif struct_id != idaapi.BADADDR and struct_id in n:
                        l = n[struct_id]
                        if not const.EA64:
                            ptr_size = 4
                        else:
                            ptr_size = 8
                        if method_offset % ptr_size == 0 and method_offset // ptr_size < len(l) and l[method_offset // ptr_size] is not None:
                            idaapi.jumpto(l[method_offset // ptr_size] + idaapi.get_imagebase())
                            return 1

                if get_config().get_opt("Member double click", "JumpByComment"):
                    func_name = helper.get_member_name(vtable_tinfo, method_offset)
                    func_ea = helper.choose_virtual_func_address(func_name, class_tinfo, vtable_offset)

                    if not func_ea:
                        func_ea = self._get_commented_address_from_vtable(vtable_tinfo, method_offset)

                    if func_ea:
                        new_comment = self._get_target_func_comment(func_ea, item)
                        self._update_func_comment_and_jump(func_ea, new_comment)
                        return 1

                if get_config().get_opt("Member double click", "JumpByFieldName"):
                    func_name = helper.get_member_name(vtable_tinfo, method_offset)
                    func_ea = helper.choose_virtual_func_address(func_name, class_tinfo, vtable_offset)
                    if func_ea is not None:
                        idaapi.jumpto(func_ea)
                        return 1
        return 0

    def _process_commented_address(self, struct_tinfo, func_offset, item):
        sid = idc.get_struc_id(struct_tinfo.dstr())
        if sid != idaapi.BADADDR:
            # sptr = helper.get_struc(sid)
            # mid = idaapi.get_member_id(sptr, func_offset)
            # comment = idaapi.get_member_cmt(mid, False)
            comment = idc.get_member_cmt(sid,func_offset)
            if comment:
                try:
                    commented_address = int(comment, 16)
                    new_comment = self._get_target_func_comment(commented_address, item)
                    self._update_func_comment_and_jump(commented_address, new_comment)
                except:
                    pass

    def _get_commented_address_from_vtable(self, vtable_tinfo, method_offset):
        sid = idc.get_struc_id(vtable_tinfo.get_type_name())
        if sid != idaapi.BADADDR:
            # sptr = helper.get_struc(sid)
            # mid = idaapi.get_member_id(sptr, method_offset)
            # comment = idaapi.get_member_cmt(mid, False)
            comment = idc.get_member_cmt(sid,method_offset)
            if comment:
                try:
                    return int(comment, 16)
                except:
                    return None
        return None

if get_config().get_opt("Member double click", "MemberDoubleClick"):
    callbacks.hx_callback_manager.register(idaapi.hxe_double_click, MemberDoubleClick())
