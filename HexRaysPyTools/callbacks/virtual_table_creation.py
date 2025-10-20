import ida_bytes
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_name
import ida_typeinf
import idaapi
import idautils
import idc

import HexRaysPyTools.core.helper as helper
from . import actions
from HexRaysPyTools.core.temporary_structure import VirtualTable
import HexRaysPyTools.core.const as Const
from HexRaysPyTools.netnode import Netnode
from ..settings import get_config
from HexRaysPyTools.core.helper import GetXrefCnt
from HexRaysPyTools.log import Log

logger = Log.get_logger()

pure_names = ["___cxa_pure_virtual"]

class CreateVtable(actions.Action):
    description = "Create Virtual Table"
    hotkey = None

    def __init__(self):
        super(CreateVtable, self).__init__()

    @staticmethod
    def check(ea):
        return ea != idaapi.BADADDR and VirtualTable.check_address(ea)

    def activate(self, ctx):
        ea = ctx.cur_ea
        if self.check(ea):
            vtable = VirtualTable(0, ea)
            vtable.import_to_structures(True)

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            if self.check(ctx.cur_ea):
                idaapi.attach_action_to_popup(ctx.widget, None, self.name)
                return idaapi.AST_ENABLE_FOR_WIDGET
            idaapi.detach_action_from_popup(ctx.widget, self.name)
            return idaapi.AST_DISABLE
        return idaapi.AST_DISABLE_FOR_WIDGET

class DisassembleCreateVtable(actions.Action):
    description = "Create netnoded vtable"
    hotkey = None

    def __init__(self):
        super(DisassembleCreateVtable, self).__init__()

    @staticmethod
    def check(addr):
        if not Const.EA64:
            ptr_size = 4
            get_addr_val = ida_bytes.get_wide_dword
        else:
            ptr_size = 8
            get_addr_val = ida_bytes.get_qword
        i = 0
        if get_addr_val(addr) != 0 and idaapi.is_func(ida_bytes.get_full_flags(get_addr_val(addr))) and (GetXrefCnt(addr) == 0 or i == 0):
            return True
        return False

    def activate(self, ctx):
        addr = ctx.cur_ea
        name = create_vtable(addr)

    def update(self, ctx):  # type: (idaapi.action_ctx_base_t) -> None
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            if self.check(ctx.cur_ea):
                ida_kernwin.attach_action_to_popup(ctx.widget, None, self.name)
                return idaapi.AST_ENABLE_FOR_WIDGET
            ida_kernwin.detach_action_from_popup(ctx.widget, self.name)
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


def check_addr(addr, i, get_addr_val):
    ret = False
    if get_addr_val(addr) != 0:
        if ida_bytes.is_func(ida_bytes.get_full_flags(get_addr_val(addr))):
            if GetXrefCnt(addr) == 0 or i == 0:
                ret = True
        elif ida_bytes.has_name(ida_bytes.get_full_flags(get_addr_val(addr))):
            if ida_name.get_name(get_addr_val(addr)) in pure_names:
                if GetXrefCnt(addr) == 0 or i == 0:
                    ret = True
    return ret

class DecompileCreateVtable(actions.HexRaysPopupAction):
    description = "Create Vtable"
    hotkey = "shift+V"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def check(self, hx_view):
        if hx_view.item and hx_view.item.is_citem() and hx_view.item.it.is_expr():
            item = hx_view.item.e
            if item.opname == "obj" and idaapi.is_data(idaapi.get_full_flags(item.obj_ea)):
                return True
        return False

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

    def activate(self, ctx):
        # if fDebug:
        #     pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True)
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        vdui.get_current_item(idaapi.USE_KEYBOARD)
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            name = create_vtable(target_item.obj_ea)
            # if name is not None:
            #     cfunc = vdui.cfunc
            #     it_parent = cfunc.body.find_parent_of(target_item)
            #     while not it_parent is None or it_parent.op != idaapi.cit_block:
            #         if it_parent.is_expr() and it_parent.op == idaapi.cot_asg:
            #             operand = it_parent.cexpr.x
            #             if operand.op == idaapi.cot_memptr:
            #                 off = operand.cexpr.m
            #                 it_obj = operand.cexpr.x
            #                 obj_name = ("%s"%it_obj.cexpr.type).strip(" *")
            #                 sid = idc.GetStrucIdByName(obj_name)
            #                 if sid == idaapi.BADADDR:
            #                     break
            #                 sptr = helper.get_struc(sid)
            #                 mptr = idaapi.get_best_fit_member(sptr,off)
            #                 tif = idaapi.tinfo_t()
            #                 idaapi.parse_decl2(my_ti,name + " *;",tif,0)
            #                 idaapi.set_member_tinfo2(sptr,mptr,0,tif,0)
            #                 break
            #         it_parent = cfunc.body.find_parent_of(it_parent)
            vdui.refresh_view(True)

def create_vtable(addr, only_method=True):
    logger.debug("Enter: address = 0x%08X" % addr)
    name = ida_kernwin.ask_str("", 0, "Please enter the class name")
    if name is None:
        return

    vtbl_name = name + "_vtbl"
    type_ordinal = ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), vtbl_name)
    if type_ordinal != 0:
        vtbl_tif = helper.get_named_type_tif(vtbl_name)
        if vtbl_tif is not None:
            i = ida_kernwin.ask_yn(0, "A vtable structure for %s already exists. Are you sure you want to remake it?" % name)
            if i == idaapi.BADADDR:
                return
            if i == 1:
                udt = helper.get_type_udt(vtbl_tif)
                if udt is not None:
                    r = vtbl_tif.del_udms(0, len(udt))
                    if r != 0:
                        raise ValueError("Something wrong: %s" % ida_typeinf.tinfo_errstr(r))
                else:
                    logger.error("Cant obtain udt for type '%s'" % vtbl_name)
                    ida_kernwin.warning("Cant obtain udt for type '%s'" % vtbl_name)
                    return
        else:
            logger.error("Cant obtain tinfo for type '%s'"%vtbl_name)
            ida_kernwin.warning("Cant obtain tinfo for type '%s'"%vtbl_name)
            return
    else:
        type_ordinal = ida_typeinf.alloc_type_ordinal(ida_typeinf.get_idati())
        vtbl_tif = ida_typeinf.tinfo_t()
        if not vtbl_tif.create_udt():
            logger.error("Cant create udt tinfo for type '%s'"%vtbl_name)
            ida_kernwin.warning("Cant create udt tinfo for type '%s'"%vtbl_name)
            return

    i = 0
    n = Netnode("$ VTables")
    n[type_ordinal] = []
    if not Const.EA64:
        ptr_size = 4
        fSize = idaapi.FF_DWORD
        refinf = idaapi.refinfo_t()
        refinf.init(idaapi.REF_OFF32)
        ref_type = ida_nalt.REF_OFF32
        get_addr_val = ida_bytes.get_wide_dword
    else:
        ptr_size = 8
        fSize = idaapi.FF_QWORD
        refinf = idaapi.refinfo_t()
        refinf.init(idaapi.REF_OFF64)
        ref_type = ida_nalt.REF_OFF64
        get_addr_val = ida_bytes.get_qword
    # else:
    #     ptr_size = 2
    #     fSize = idaapi.FF_WORD
    #     refinf = idaapi.refinfo_t(idaapi.REF_OFF16)
    while check_addr(addr, i, get_addr_val) is True:
        meth_addr = get_addr_val(addr)
        methName = ""
        logger.debug("meth_addr = 0x%08X" % meth_addr)
        logger.debug("i = %d" % i)

        if meth_addr != 0:
            if ida_bytes.has_name(ida_bytes.get_full_flags(get_addr_val(meth_addr))) or ida_name.get_name(meth_addr) != "":
                methName = ida_name.get_name(meth_addr)
                if helper.isMangled(methName):
                    try:
                        demangled = ida_name.demangle_name(methName, 0)
                        if demangled:
                            methName = demangled[:demangled.find("(")]
                            if ' ' in methName:
                                methName = methName[methName.rfind(" "):].strip()
                            if only_method:
                                if "::" in methName:
                                    methName = methName.rsplit("::", 1)[1]
                                methName = methName.replace("~", "dtor_").replace("==", "_equal")
                            else:
                                if ('>' in methName or '<' in methName or
                                    len(methName) > 50 or
                                    methName.count("?") > 2):
                                    methName = "sub_%X" % meth_addr
                                else:
                                    methName = methName.replace("~", "dtor_").replace("==", "_equal")
                                if "::" in methName:
                                    methName = methName.replace("::", "__")
                        else:
                            methName = "sub_%X" % meth_addr
                    except:
                        methName = "sub_%X" % meth_addr
                else:
                    if "::" in methName:
                        if only_method:
                            methName = methName.rsplit("::", 1)[1]
                        else:
                            methName = methName.replace("::", "__")
                    methName = methName.replace("~", "dtor_").replace("==", "_equal")
            else:
                methName = "sub_%X" % meth_addr
        else:
            methName = "field_%02X" % (i * ptr_size)
        logger.debug("Name = %s"%methName)
        rc = helper.tif_add_member(vtbl_tif, methName, 'void*', i * ptr_size * 8)
        if rc != 0 and rc == -21:
            postfix_num = 0
            while rc != 0 and rc == -21:
                logger.debug("Member duplicated name. Trying add postfix number %d"%postfix_num)
                rc = helper.tif_add_member(vtbl_tif, methName+"_%d"%postfix_num, 'void*', i * ptr_size * 8)
                postfix_num = postfix_num + 1
        elif rc != 0:
            logger.error("Cant add member named '%s', rc = %d (%s)" % (methName, rc, ida_typeinf.tinfo_errstr(rc)))
            raise ValueError("Something wrong: %s" % ida_typeinf.tinfo_errstr(rc))
        l = n[type_ordinal]
        l.append((meth_addr - idaapi.get_imagebase()) if meth_addr else idaapi.BADADDR)
        n[type_ordinal] = l
        i = i + 1
        addr = addr + ptr_size
    rc = vtbl_tif.set_numbered_type(ida_typeinf.get_idati(), type_ordinal, ida_typeinf.NTF_TYPE|ida_typeinf.NTF_REPLACE, vtbl_name)
    if rc != 0:
        logger.error("Cant set_numbered_type named '%s', rc = %d (%s)" % (vtbl_name, rc, ida_typeinf.tinfo_errstr(rc)))
        ida_kernwin.warning("Cant set_numbered_type named '%s', rc = %d (%s)" % (vtbl_name, rc, ida_typeinf.tinfo_errstr(rc)))
    return vtbl_name




if get_config().get_opt("Virtual table creation", "CreateVtable"):
    actions.action_manager.register(CreateVtable())
if get_config().get_opt("Virtual table creation", "DecompileCreateVtable"):
    actions.action_manager.register(DecompileCreateVtable())
if get_config().get_opt("Virtual table creation", "DisassembleCreateVtable"):
    actions.action_manager.register(DisassembleCreateVtable())
