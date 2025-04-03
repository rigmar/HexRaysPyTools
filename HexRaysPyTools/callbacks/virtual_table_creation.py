import ida_bytes
import ida_kernwin
import ida_name
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
                return idaapi.AST_ENABLE
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
                return idaapi.AST_ENABLE
            ida_kernwin.detach_action_from_popup(ctx.widget, self.name)
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_DISABLE_FOR_WIDGET




class DecompileCreateVtable(actions.HexRaysPopupAction):
    description = "Create Vtable"
    hotkey = "shift+V"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def check(self, hx_view):
        if hx_view.item.is_citem() and hx_view.item.it.is_expr():
            item = hx_view.item.e
            if item.opname == "obj" and idaapi.is_data(idaapi.get_full_flags(item.obj_ea)):
                return True
        return False

    def activate(self, ctx):
        # if fDebug:
        #     pydevd.settrace('localhost', port=2255, stdoutToServer=True, stderrToServer=True)
        vdui = idaapi.get_widget_vdui(ctx.widget)
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

def create_vtable(addr):
    def get_function_signature(func_addr):
        tinfo = idaapi.tinfo_t()
        if idaapi.get_tinfo(tinfo, func_addr):
            func_type_data = idaapi.func_type_data_t()
            if tinfo.get_func_details(func_type_data):
                args = []
                for i, arg in enumerate(func_type_data):
                    if i == 0:  # The first argument is always the this pointer
                        continue  # Skipped because we will add it separately in the function signature
                    arg_name = arg.name if arg.name else f"a{i}"
                    args.append(f"{arg.type.dstr()} {arg_name}")

                args_str = ", ".join(args)
                ret_type = tinfo.get_rettype().dstr()

                # Get the original function name
                orig_name = ida_name.get_name(func_addr)
                demangled = ida_name.demangle_name(orig_name, 0) if orig_name else None
                func_name = demangled if demangled else orig_name

                # Build the full function signature, putting the function name inside the pointer declaration
                return f"{ret_type} (__thiscall *{func_name})(void *this{', ' + args_str if args_str else ''})"
        return None

    def isMangled(n):
        if n.startswith("_ZN")or n.startswith("?"): return True
        return False

    # print "addr = 0x%08X" % addr

    name = ida_kernwin.ask_str("", 0, "Please enter the class name")
    if name is None:
        return
    struct_id = idc.get_struc_id(name + "_vtbl")
    # print struct_id
    if struct_id != idaapi.BADADDR:
        i = ida_kernwin.ask_yn(0, "A vtable structure for %s already exists. Are you sure you want to remake it?" % name)
        if i == idaapi.BADADDR:
            return
        if i == 1:
            sptr = helper.get_struc(struct_id)
            if sptr:
                size = idc.get_struc_size(struct_id)
                offset = 0
                while offset < size:
                    member = idc.get_member_id(struct_id, offset)
                    if member != -1:
                        idc.del_struc_member(struct_id, offset)
                    offset += ida_bytes.get_item_size(member) if member != -1 else ida_bytes.get_item_size(offset)
    else:
        struct_id = idc.add_struc(idaapi.BADADDR, name + "_vtbl", 0)
    if struct_id == idaapi.BADADDR:
        Warning("Could not create the vtable structure!.\nPlease check the entered class name.")
        return

    # bNameMethods = AskYN(0,"Would you like to assign auto names to the virtual methods (%s_virtXX)?"%name)
    i = 0
    n = Netnode("$ VTables")
    n[struct_id] = []
    if not Const.EA64:
        ptr_size = 4
        fSize = idaapi.FF_DWORD
        refinf = idaapi.refinfo_t()
        refinf.init(idaapi.REF_OFF32)
        get_addr_val = ida_bytes.get_wide_dword
    else:
        ptr_size = 8
        fSize = idaapi.FF_QWORD
        refinf = idaapi.refinfo_t()
        refinf.init(idaapi.REF_OFF64)
        get_addr_val = ida_bytes.get_qword
    # else:
    #     ptr_size = 2
    #     fSize = idaapi.FF_WORD
    #     refinf = idaapi.refinfo_t(idaapi.REF_OFF16)

    while (get_addr_val(addr) != 0 and idaapi.is_func(ida_bytes.get_full_flags(get_addr_val(addr))) and (GetXrefCnt(addr) == 0 or i == 0)) is True:
        c = get_addr_val(addr)
        methName = ""
        logger.debug("c = 0x%08X" % c)
        logger.debug("i = %d" % i)

        # func_sig = get_function_signature(c) if c != 0 else None
        # Strange approach. Don't understand why func signature going to commnets.
        # It may do through creating special tinfo and apply to field.
        #todo need to think about auto apply func signatures
        if c != 0:
            if ida_bytes.has_name(ida_bytes.get_full_flags(get_addr_val(c))) or ida_name.get_name(c) != "":
                methName = ida_name.get_name(c)
                if isMangled(methName):
                    try:
                        demangled = ida_name.demangle_name(methName, 0)
                        if demangled:
                            methName = demangled[:demangled.find("(")]
                            if ' ' in methName:
                                methName = methName[methName.rfind(" "):].strip()
                            # ��麯�����Ƿ���������ַ������
                            if ('>' in methName or '<' in methName or
                                len(methName) > 50 or
                                methName.count("?") > 2):
                                methName = "sub_%X" % c
                            else:
                                methName = methName.replace("~", "dtor_").replace("==", "_equal")
                            # �������� "::" �����
                            if "::" in methName:
                                methName = methName.replace("::", "__")
                        else:
                            methName = "sub_%X" % c
                    except:
                        methName = "sub_%X" % c
                else:
                    if "::" in methName:
                        methName = methName.replace("::", "__")
            else:
                methName = "sub_%X" % c
        else:
            methName = "field_%02X" % (i * 4)
        logger.debug("Name = %s"%methName)
        sptr = helper.get_struc(struct_id)

        # if func_sig:
        #     comment = func_sig
        # else:
        #     comment = "-> %08X, args: 0x%X" % (c, idc.get_func_attr(c,idc.FUNCATTR_ARGSIZE))
        comment = "-> %08X, args: 0x%X" % (c, idc.get_func_attr(c,idc.FUNCATTR_ARGSIZE))
        e = idc.add_struc_member(struct_id, methName, i * ptr_size, idaapi.FF_0OFF | fSize | idaapi.FF_DATA, -1, ptr_size)
        logger.debug ("e = %d" % e)
        if e != 0:
            if e == -1:
                l = 0
                while e == -1:
                    e = idc.add_struc_member(sptr, (methName + "_%d"%l), i * ptr_size, idaapi.FF_0OFF | fSize | idaapi.FF_DATA,
                                                -1, ptr_size)
                    l = l + 1
                    if l > 50:
                        ida_kernwin.warning("Wrong function name!")
                        return
            elif e != -2 and e != idaapi.BADADDR:
                ida_kernwin.warning("Error adding a vtable entry!")
                return
            else:
                ida_kernwin.warning("Unknown error! Err = %d"%e)
                return
        idc.set_member_cmt(struct_id, i * ptr_size, comment, 1)
        # l = n[name + "_vtbl"]
        # l.append((c - idaapi.get_imagebase()) if c else idaapi.BADADDR)
        # n[name + "_vtbl"] = l
        l = n[struct_id]
        l.append((c - idaapi.get_imagebase()) if c else idaapi.BADADDR)
        n[struct_id] = l

        i = i + 1
        addr = addr + ptr_size
    return name + "_vtbl"


if get_config().get_opt("Virtual table creation", "CreateVtable"):
    actions.action_manager.register(CreateVtable())
if get_config().get_opt("Virtual table creation", "DecompileCreateVtable"):
    actions.action_manager.register(DecompileCreateVtable())
if get_config().get_opt("Virtual table creation", "DisassembleCreateVtable"):
    actions.action_manager.register(DisassembleCreateVtable())
