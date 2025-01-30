import idaapi
import ida_struct
import ida_funcs

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

    def handle(self, event, *args):
        if fDebug:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=True)
        hx_view = args[0]
        item = hx_view.item
        vtable_tinfo = None
        method_offset = None
        if item.citype == idaapi.VDI_EXPR and item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset
            if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                # class_tinfo = item.e.x.x.x.type.get_pointed_object()
                # vtable_offset = item.e.x.x.m
            elif item.e.x.op == idaapi.cot_memptr or item.e.x.op == idaapi.cot_var:
                vtable_tinfo = item.e.x.type
                if vtable_tinfo.is_ptr():
                    vtable_tinfo = vtable_tinfo.get_pointed_object()
                method_offset = item.e.m
                # class_tinfo = item.e.x.x.type.get_pointed_object()
                # vtable_offset = item.e.x.m
            else:
                if item.e.x is not None and item.e.x.op != idaapi.cot_empty:
                    vtable_tinfo = item.e.x.type
                    if vtable_tinfo:
                        while vtable_tinfo.is_ptr():
                            vtable_tinfo = vtable_tinfo.get_pointed_object()
                        method_offset = item.e.m

            if method_offset is not None and vtable_tinfo:
                n = Netnode("$ VTables")
                vt_name = vtable_tinfo.get_type_name()
                struct_id = idaapi.get_struc_id(vt_name)
                if vt_name and vt_name in n:
                    l = n[vt_name]
                    # print l
                    info = idaapi.get_inf_structure()
                    if not const.EA64:
                        ptr_size = 4
                    else:
                        ptr_size = 8
                    # else idc.__EA64__:
                    #     ptr_size = 8
                    # else:
                    #     ptr_size = 2
                    if method_offset % ptr_size == 0 and method_offset // ptr_size < len(l) and l[method_offset // ptr_size] is not None:
                        idaapi.jumpto(l[method_offset // ptr_size] + idaapi.get_imagebase())
                        return 1
                elif struct_id != idaapi.BADADDR and struct_id in n:
                    l = n[struct_id]
                    # print l
                    info = idaapi.get_inf_structure()
                    if not const.EA64:
                        ptr_size = 4
                    else:
                        ptr_size = 8
                    # else idc.__EA64__:
                    #     ptr_size = 8
                    # else:
                    #     ptr_size = 2
                    if method_offset % ptr_size == 0 and method_offset // ptr_size < len(l) and l[method_offset // ptr_size] is not None:
                        idaapi.jumpto(l[method_offset // ptr_size] + idaapi.get_imagebase())
                        return 1
                elif get_config().get_opt("Member double click", "JumpByFieldName"):
                    sptr = ida_struct.get_struc(struct_id)
                    mid = ida_struct.get_member_id(sptr, method_offset)
                    field_name = ida_struct.get_member_name(mid)
                    func_ea = helper.get_func_ea(field_name)
                    if func_ea is not None:
                        idaapi.jumpto(func_ea)
        return 0

if get_config().get_opt("Member double click", "MemberDoubleClick"):
    callbacks.hx_callback_manager.register(idaapi.hxe_double_click, MemberDoubleClick())
