import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_struct
import idaapi

from HexRaysPyTools.callbacks import actions
from HexRaysPyTools.core.helper import convert_name, GetXrefCnt
from HexRaysPyTools.netnode import Netnode
import HexRaysPyTools.core.const as Const
from HexRaysPyTools.settings import get_config
from HexRaysPyTools.log import Log

logger = Log.get_logger()

vt_node_name = "$ VTables"

def edit_vtables_netnode():
    f = VtableRecordsUI()
    f.Go()


class VtableMembersUI(idaapi.Form):
    def __init__(self, vt_name):
        self.__n = 0
        self.vt_name = vt_name
        self.selected = None
        self.EChooser = VtableMembersChooser("Vtable %s members list" % vt_name, vt_name, self)
        idaapi.Form.__init__(self,
                             r"""
                             <Vtable %s members:{cEChooser}>   <##Add new:{iButtonAddNew}>
                             """ % vt_name.replace(":","\:"), {
                                 'cEChooser': idaapi.Form.EmbeddedChooserControl(self.EChooser),
                                 'iButtonAddNew': idaapi.Form.ButtonInput(self.add_new)
                             })

    def Go(self):
        self.Compile()
        ok = self.Execute()
        # print "Ok = %d"%ok
        if ok == 1:
            sel = self.EChooser.selected
            # print sel
            # print len(sel)
            if len(sel) > 0:
                return sel[0]
            else:
                return None
        return None

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetFocusedField(self.EChooser)

    def add_new(self, code=0):
        self.EChooser.OnInsertLine(None)


class VtableMembersChooser(idaapi.Choose):

    def __init__(self, title, vt_name, obj, flags=0):
        idaapi.Choose.__init__(self,
                               title,
                               [["Field offset", 10], ["Field name", 30], ["Func name", 30], ["Address", 30]],
                               embedded=True, width=50, height=10, flags=flags | idaapi.Choose.CH_CAN_REFRESH | idaapi.Choose.CH_CAN_DEL | idaapi.Choose.CH_CAN_INS)
        self.n = 0
        self.obj = obj
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.vt_name = vt_name
        if not idaapi.get_inf_structure().is_64bit():
            self.field_size = 4
        else:
            self.field_size = 8
        self.selected = []
        self.populate_items()

    def populate_items(self):
        self.items = []
        n = Netnode(vt_node_name)

        l = n[self.vt_name]
        sptr = ida_struct.get_struc(ida_struct.get_struc_id(self.vt_name))
        for i in range(len(l)):
            item = self.generate_item(i, sptr, l[i])
            self.items.append(item)

    def generate_item(self, i, sptr, func_offset):
        field_offset = i * self.field_size
        member_id = ida_struct.get_member_id(sptr, field_offset)
        if member_id == idaapi.BADADDR:
            field_name = "NONE"
        else:
            field_name = ida_struct.get_member_name(member_id)
        func_addr = func_offset
        if func_addr is not None:
            func_addr += ida_nalt.get_imagebase()
            func_name = ida_funcs.get_func_name(func_addr)
        else:
            func_name = "NONE"
        return ["0x%X" % field_offset, field_name, func_name, ("0x%X" % func_addr) if func_addr is not None else "NONE"]

    def OnClose(self):
        net = Netnode(vt_node_name)
        vt_sid = ida_struct.get_struc_id(self.vt_name)
        if vt_sid in net:
            net[vt_sid] = net[self.vt_name]

    # def Close(self):
    #     print ("Trying close")
    #     pass

    def OnGetLine(self, n):
        # print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        # print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        # print("del %d " % n)
        field_offset = int(self.items[n][0], 16)
        net = Netnode(vt_node_name)
        l = net[self.vt_name]
        i = field_offset // self.field_size
        if i < len(l) - 1:
            l[i] = None
            self.obj.RefreshField(self.obj.controls['cEChooser'])
        elif i == len(l) - 1:
            l.pop(-1)
            self.obj.RefreshField(self.obj.controls['cEChooser'])
        net[self.vt_name] = l
        return n

    def OnSelectLine(self, n):
        # print "Selected %d"%n
        # print self.items[n]
        self.selected = [n]
        field_offset = int(self.items[n][0], 16)
        i = field_offset // self.field_size
        l = Netnode(vt_node_name)[self.vt_name]
        if i < len(l):
            ida_kernwin.jumpto(l[i] + ida_nalt.get_imagebase())

    def OnEditLine(self, n):
        logger.debug("OnEditLine: n = ", n)
        func_addr = ida_kernwin.ask_addr(0, "Enter function addr")
        if func_addr is not None:
            if func_addr != 0:
                func_offset = func_addr - ida_nalt.get_imagebase()
            else:
                func_offset = None
            netnode = Netnode(vt_node_name)
            l = netnode[self.vt_name]
            l[n] = func_offset
            netnode[self.vt_name] = l
            sptr = ida_struct.get_struc(ida_struct.get_struc_id(self.vt_name))
            new_item = self.generate_item(n, sptr, func_offset)
            self.items[n] = new_item
            self.obj.RefreshField(self.obj.controls['cEChooser'])

    def OnInsertLine(self, n):
        print("insert line")
        sptr = ida_struct.get_struc(ida_struct.get_struc_id(self.vt_name))
        netnode = Netnode(vt_node_name)
        l = netnode[self.vt_name]
        if ida_struct.get_struc_size(sptr) // self.field_size > len(l):
            func_addr = ida_kernwin.ask_addr(0, "Enter function addr")
            if func_addr is not None:
                if func_addr != 0:
                    l.append(func_addr - ida_nalt.get_imagebase())
                else:
                    l.append(None)
                netnode[self.vt_name] = l
                self.obj.RefreshField(self.obj.controls['cEChooser'])
        else:
            ida_kernwin.warning("All fields of structrure %s has descriptions" % self.vt_name)

    def OnSelectionChange(self, sel_list):
        self.selected = []
        # print sel_list
        if type(sel_list) == int:
            self.selected.append(sel_list)
        else:
            for sel in sel_list:
                self.selected.append(sel)


class VtableChooser(idaapi.Choose):

    def __init__(self, title, obj, flags=0):
        idaapi.Choose.__init__(self,
                               title,
                               [["Name", 60]],
                               embedded=True, width=600, height=10, flags=flags | idaapi.Choose.CH_CAN_REFRESH | idaapi.Choose.CH_CAN_DEL | ida_kernwin.Choose.CH_CAN_INS)
        self.n = 0
        self.obj = obj
        # self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.items = []
        self.icon = 5
        self.selected = []
        self.populate_items()

    def populate_items(self):
        self.items = []
        n = Netnode(vt_node_name)
        for name in n.keys():
            if type(name) != str:
                name = "0x%08X" % name + " (%s)" % ida_struct.get_struc_name(name)
            self.items.append([name])

    def OnClose(self):
        pass

    def Close(self):
        logger.debug("Trying close")
        pass

    def OnGetLine(self, n):
        # print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        # print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        # print("del %d " % n)
        name = self.items[n][0]
        if name.startswith("0x"):
            name = int(name.split(' ')[0], 16)
        net = Netnode(vt_node_name)
        if name in net:
            del net[name]
            self.items.pop(n)
            self.obj.RefreshField(self.obj.controls['cEChooser'])
        return n

    def OnSelectLine(self, n):
        logger.debug("Selected %d" % n)
        # print self.items[n]
        self.selected = [n]
        vt_name = self.items[n][0]
        if vt_name.startswith("0x"):
            vt_sid = int(vt_name.split(' ')[0], 16)
            vt_name = ida_struct.get_struc_name(vt_sid)
        if vt_name:
            f = VtableMembersUI(vt_name)
            f.Go()

    def OnSelectionChange(self, sel_list):
        self.selected = []
        # print sel_list
        if type(sel_list) == int:
            self.selected.append(sel_list)
        else:
            for sel in sel_list:
                self.selected.append(sel)


class VtableRecordsUI(idaapi.Form):
    def __init__(self):
        self.__n = 0
        self.selected = None
        self.EChooser = VtableChooser("Vtable records list", self)
        idaapi.Form.__init__(self,
r"""STARTITEM {id:cEChooser}
BUTTON YES NONE
BUTTON CANCEL NONE
Saved vtables
<Vtable records:{cEChooser}>   <##Clear all:{iButtonClearAll}>
""",
                    {
                     'cEChooser': idaapi.Form.EmbeddedChooserControl(self.EChooser),
                     'iButtonClearAll': idaapi.Form.ButtonInput(self.clear_all)
                    })

    def Go(self):
        self.modal = False
        self.Compile()
        self.openform_flags = self.openform_flags | ida_kernwin.DP_SZHINT
        ok = self.Open()
        # print "Ok = %d"%ok
        # widget: PyQt5.QtWidgets.QWidget = ida_kernwin.get_current_widget()
        # widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(widget)
        # print(widget.windowTitle())
        # widget.resize(600, widget.height())
        if ok == 1:
            sel = self.EChooser.selected
            # print sel
            # print len(sel)
            if len(sel) > 0:
                return sel[0]
            else:
                return None
        return None

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetFocusedField(self.EChooser)

    def clear_all(self, code=0):
        net = Netnode(vt_node_name)
        net.kill()
        self.EChooser.populate_items()
        self.RefreshField(self.controls['cEChooser'])

class BoundVtable(actions.Action):
    description = "Bound vtable struct with func offsets"
    hotkey = None

    def __init__(self):
        super(BoundVtable, self).__init__()

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
        name = bound_vtable(addr)

    def update(self, ctx):  # type: (idaapi.action_ctx_base_t) -> None
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            if self.check(ctx.cur_ea):
                ida_kernwin.attach_action_to_popup(ctx.widget, None, self.name)
                return idaapi.AST_ENABLE
            ida_kernwin.detach_action_from_popup(ctx.widget, self.name)
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def bound_vtable(addr):

    def isMangled(n):
        if n.startswith("_ZN")or n.startswith("?"): return True
        return False

    # print "addr = 0x%08X" % addr
    vt_addr = addr
    name = ida_kernwin.ask_str("", 0, "Please enter the vtable struct name")
    if name is None:
        return
    struct_id = idaapi.get_struc_id(name)
    # print struct_id
    if struct_id != idaapi.BADADDR:

        i = 0
        if not Const.EA64:
            ptr_size = 4
            get_addr_val = ida_bytes.get_wide_dword
        else:
            ptr_size = 8
            get_addr_val = ida_bytes.get_qword
        # else:
        #     ptr_size = 2
        #     fSize = idaapi.FF_WORD
        #     refinf = idaapi.refinfo_t(idaapi.REF_OFF16)

        offsets = []
        while (get_addr_val(addr) != 0 and idaapi.is_func(ida_bytes.get_full_flags(get_addr_val(addr))) and (GetXrefCnt(addr) == 0 or i == 0)) is True:
            c = get_addr_val(addr)
            logger.debug("c = 0x%08X" % c)
            logger.debug("i = %d" % i)
            offsets.append(c - ida_nalt.get_imagebase())
            i = i + 1
            addr = addr + ptr_size
        sptr = ida_struct.get_struc(struct_id)
        if sptr.memqty == len(offsets):
            n = Netnode("$ VTables")
            n[name] = offsets
            n[struct_id] = offsets
        elif sptr.memqty > len(offsets):
            ida_kernwin.warning("Struct %s has more members than methods in vtbl at 0x%08X"%(name, vt_addr))
        elif sptr.memqty < len(offsets):
            ida_kernwin.warning("Vtbl at 0x%08X has more methods than members quantity in struct %s" % (vt_addr, name))
    else:
        ida_kernwin.warning("Type %s not founded" % name)
    return name

if get_config().get_opt("Virtual tables netnode", "BoundVtable"):
    actions.action_manager.register(BoundVtable())