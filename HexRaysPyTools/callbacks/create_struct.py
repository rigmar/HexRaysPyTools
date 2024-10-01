import ida_struct
import idaapi, ida_pro, idc, ida_kernwin
import struct

from . import actions
import HexRaysPyTools.core.const as Const
from HexRaysPyTools.settings import hex_pytools_config

class SimpleCreateStruct(actions.HexRaysPopupAction):
    name = "my:CreateStruct"
    description = "Create simple struct"
    hotkey = "Shift+C"
    ForPopup = True

    def __init__(self):
        super().__init__()

    def check(self, hx_view):
        return True

    def create_struct_type(self, struc_size, name, field_size=4, fAllign=True):
        my_ti = idaapi.get_idati()
        def make_field_str(field_num, fsize, pad=0):
            ret = b""
            # i = 0
            for i in range(0, field_num):
                ret += struct.pack(">B", len(b"field_%X" % (i * fsize)) + 1) + b"field_%X" % (i * fsize)
            k = 1
            i = field_num - 1
            while pad > 0:
                ret += struct.pack(">B", len(b"field_%X" % (i * fsize + k)) + 1) + b"field_%X" % (i * fsize + k)
                pad -= 1
                k += 1
            return ret

        def encode_size(num):
            enc = 0
            if num > 0xF:
                t, pad = divmod(num, 0x10)
                if t < 0x100:
                    enc = 0x8100 | (pad << 11) | t
                    return struct.pack(">BB", enc >> 8, enc & 0xFF)
                else:
                    t1, t2, t3 = (0, 0, 0)
                    t1, pad = divmod(num, 0x400)
                    t3 = pad
                    if pad > 7:
                        t2, t3 = divmod(pad, 8)
                    return b"\xFF\xFF" + struct.pack(">BBB", t1 | 0x80, t2 | 0x80, t3 << 3 | 0x40)
            else:
                return struct.pack(">B", num << 3 | 1)

        def make_type_string(field_num, fsize, pad=0):
            ret = b"\x0d" + encode_size(field_num + pad)
            if fsize == 1:
                t = b"\x32"
            elif fsize == 2:
                t = b"\x03"
            elif fsize == 8:
                t = b"\x05"
            else:
                t = b"\x07"
            ret += t * field_num
            if pad > 0:
                ret += b"\x32" * pad
            return ret

        struct_id = ida_struct.get_struc_id(name)
        type_ord = idaapi.get_type_ordinal(my_ti,name)
        if struct_id != idaapi.BADADDR or type_ord != 0:
            answer =  ida_kernwin.ask_yn(0, "A structure for %s already exists. Are you sure you want to remake it?" % name)
            if answer == 1:
                if struct_id != idaapi.BADADDR:
                    idc.del_struc(struct_id)
            else:
                return
        fields_num, pad = divmod(struc_size, field_size)
        if fAllign and pad:
            fields_num += 1
            pad = 0
        if type_ord != 0:
            idx = type_ord
        else:
            idx = idaapi.alloc_type_ordinal(my_ti)

        typ_type = make_type_string(fields_num, field_size, pad)
        typ_fields = make_field_str(fields_num, field_size, pad)
        ret = idaapi.set_numbered_type(my_ti,idx,0x5,name,typ_type, typ_fields, "", b"", 0)

        if (ida_pro.IDA_SDK_VERSION < 700 and ret != 0) or (ida_pro.IDA_SDK_VERSION >= 700 and ret != 1):
            idaapi.import_type(idaapi.cvar.idati,-1, name)
            sid = idaapi.get_struc_id(name)
            sptr = idaapi.get_struc(sid)
            align_shift = 0
            if fAllign:
                if field_size == 2:
                    align_shift = 1
                elif field_size == 4:
                    align_shift = 2
                elif field_size == 8:
                    align_shift = 3
            idaapi.set_struc_align(sptr, align_shift)
        else:
            Warning("set_numbered_type error")

    def activate(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        vdui.get_current_item(idaapi.USE_KEYBOARD)
        struc_size = 0
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            if target_item.opname == "num":
                struct_size = ida_kernwin.str2ea(idaapi.tag_remove(target_item.cexpr.print1(None)))
        class SimpleCreateStructForm(idaapi.Form):
            def __init__(self):
                idaapi.Form.__init__(self, r"""STARTITEM 0
               Create struct
               <Struct name:{cStrArg}><Struct size:{numSize}>
               <Field size :{numFieldSize}>                                        <Align:{ckAlign}>{gAlign}>
                """, {
                    'cStrArg': idaapi.Form.StringInput(),
                    'numSize': idaapi.Form.StringInput(swidth=10),
                    'numFieldSize': idaapi.Form.DropdownListControl(
                        items=["1", "2", "4", "8"],
                        readonly=False,
                        selval="8" if Const.EA64 else "4"),
                    'gAlign': idaapi.Form.ChkGroupControl(("ckAlign",)),
                })

            def Go(self, size=0):
                self.Compile()
                self.ckAlign.checked = True
                # f.numFieldSize.value = 4
                self.numSize.value = str(size)
                ok = self.Execute()
                # print "Ok = %d"%ok
                if ok == 1:
                    # print sel
                    # print len(sel)
                    # return (
                    # int(self.numSize.value, 16) if self.numSize.value.startswith("0x") else int(self.numSize.value, 10), self.cStrArg.value, int(self.numFieldSize.value),
                    # self.ckAlign.checked)
                    return (
                    ida_kernwin.str2ea(self.numSize.value), self.cStrArg.value, int(self.numFieldSize.value),
                    self.ckAlign.checked)
                return None

        ret = SimpleCreateStructForm().Go(struc_size)
        if ret is not None:
            self.create_struct_type(*ret)
        return 1

if hex_pytools_config.get_opt("Create struct", "SimpleCreateStruct"):
    actions.action_manager.register(SimpleCreateStruct())