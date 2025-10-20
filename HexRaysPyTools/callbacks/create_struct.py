import ida_typeinf
import idaapi, ida_pro, idc, ida_kernwin
import struct


from HexRaysPyTools.log import Log

logger = Log.get_logger()

from . import actions
import HexRaysPyTools.core.const as Const
from HexRaysPyTools.settings import hex_pytools_config
import HexRaysPyTools.core.helper as helper

class SimpleCreateStruct(actions.HexRaysPopupAction):
    name = "my:CreateStruct"
    description = "Create simple struct"
    hotkey = "Shift+C"
    ForPopup = True

    def __init__(self):
        super().__init__()

    def check(self, hx_view):
        return True

    def create_struct_type(self, struc_size, name, field_size=4, fAllign=True, fCPPObj=False, baseclass_name = ""):
        my_ti = ida_typeinf.get_idati()
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

        def encode_size(value: int, align: int = 0) -> bytes:
            """
            Build `overall = (value << 3) | (align & 7)` and encode:
              - short : 1 byte   -> overall fits in 7 bits      (0..0x7F)
              - medium: 2 bytes  -> overall fits in 15 bits     (0x80..0x7FFF)
              - long  : FF FF + 7-bit chunks (MSB=1) + terminator (0 1 lll fff),
                        where low 6 bits of terminator are overall[5:0] = (lll fff)
            """
            if not isinstance(value, int):
                raise TypeError("value must be int")
            if value < 0:
                raise ValueError("value must be non-negative")
            if not (0 <= align <= 7):
                raise ValueError("align must be in [0..7]")

            overall = (value << 3) | (align & 7)

            # short (1 byte): MSB must be 0
            if overall < 0x80:
                return bytes([overall])

            # medium (2 bytes): 7 low bits in b0 (with MSB=1), next 8 bits in b1
            if overall < 0x8000:
                b0 = 0x80 | (overall & 0x7F)
                b1 = (overall >> 7) & 0xFF
                return bytes([b0, b1])

            # long: prefix + big-endian 7-bit chunks of (overall >> 6), then terminator
            hi = overall >> 6  # everything above the last 6 bits
            tail6 = overall & 0x3F  # (lll fff)
            chunks = []
            while True:
                chunks.append(hi & 0x7F)
                hi >>= 7
                if hi == 0:
                    break
            chunks.reverse()
            out = bytearray(b"\xFF\xFF")
            for c in chunks:
                out.append(0x80 | c)  # continuation (MSB=1)
            out.append(0x40 | tail6)  # terminator: 0 1 lll fff  (low 6 bits = overall[5:0])
            return bytes(out)

        def make_type_string(field_num, fsize, pad=0):
            ret = b"\x0d" + encode_size(field_num + pad,1)
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

        struct_id = idc.get_struc_id(name)
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
        creating_tif = ida_typeinf.tinfo_t()
        ret = creating_tif.deserialize(my_ti, typ_type, typ_fields)
        # ret = idaapi.set_numbered_type(my_ti,idx,0x5,name,typ_type, typ_fields, "", b"", 0)
        if ret:
            if baseclass_name:
                baseclass_tif = ida_typeinf.tinfo_t()
                if baseclass_tif.get_named_type(ida_typeinf.get_idati(), baseclass_name):
                    logger.debug("baseclass found! Print = '%s'" % baseclass_tif._print())
                    ret = creating_tif.set_udm_type(0, baseclass_tif, ida_typeinf.ETF_MAY_DESTROY)
                    if ret == 0:
                        udt = ida_typeinf.udt_type_data_t()
                        creating_tif.get_udt_details(udt)
                        udm = udt[0]
                        udm.set_baseclass()
                        udt.taudt_bits = udt.taudt_bits | ida_typeinf.TAUDT_CPPOBJ
                        creating_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
                    else:
                        logger.error("Cant set baseclass '%s'" % baseclass_name)
                        Warning("Cant set baseclass '%s'" % baseclass_name)
                        return
                else:
                    logger.error("baseclass not found! Print = '%s'" % baseclass_tif._print())
                    Warning("baseclass not found! Print = '%s'" % baseclass_tif._print())
                    return
            elif fCPPObj:
                udt = ida_typeinf.udt_type_data_t()
                creating_tif.get_udt_details(udt)
                creating_tif.rename_udm(0, "__vftable")
                udt.taudt_bits = udt.taudt_bits | ida_typeinf.TAUDT_CPPOBJ
                creating_tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
            ret = creating_tif.set_numbered_type(ida_typeinf.get_idati(), idx, ida_typeinf.NTF_TYPE|ida_typeinf.NTF_REPLACE, name)
            if ret != 0:
                Warning("set_numbered_type error")
                logger.error("creating_tif.set_numbered_type error. ret = %d" % ret)
                return
        else:
            Warning("deserialize error")
            logger.error("creating_tif.deserialize error. ret = %d" % ret)
            return

    def activate(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        vdui.get_current_item(idaapi.USE_KEYBOARD)
        struc_size = 0
        size_str = "0"
        if vdui.item.is_citem() and vdui.item.it.is_expr():
            target_item = vdui.item.e
            if target_item.opname == "num":
                size_str = idaapi.tag_remove(target_item.cexpr.print1(None))
                # if size_str.is_numeric():
                #     struct_size = int(size_str, 10)
                # else:
                #     struct_size = ida_kernwin.str2ea(idaapi.tag_remove(target_item.cexpr.print1(None)))

        class SimpleCreateStructForm(ida_kernwin.Form):
            def __init__(self):
                ida_kernwin.Form.__init__(self, r"""STARTITEM 0
               Create struct
               <Struct name   :{cStrArg}><Struct size:{numSize}>
               <Baseclass name:{cStrArg2}><...:{iButton1}>                         <CPP obj:{ckCppObj}>
               <Field size :{numFieldSize}>                                        <Align:{ckAlign}>{gAlign}>
                """, {
                    'cStrArg': ida_kernwin.Form.StringInput(),
                    'numSize': ida_kernwin.Form.StringInput(swidth=10),
                    'numFieldSize': ida_kernwin.Form.DropdownListControl(
                        items=["1", "2", "4", "8"],
                        readonly=False,
                        selval="8" if Const.EA64 else "4"),
                    'gAlign': ida_kernwin.Form.ChkGroupControl(("ckAlign", "ckCppObj")),
                    'cStrArg2': ida_kernwin.Form.StringInput(),
                    'iButton1': ida_kernwin.Form.ButtonInput(self.onButton1),
                })

            def onButton1(self, code=0):
                baseclass_tif = ida_typeinf.tinfo_t()
                if ida_kernwin.choose_struct(baseclass_tif, 'Choose type for baseclass'):
                    self.SetControlValue(self.cStrArg2, baseclass_tif._print())
                    self.RefreshField(self.cStrArg2)

            def Go(self, size_str="0"):
                self.Compile()
                self.ckAlign.checked = True
                self.ckCppObj.checked = False
                # f.numFieldSize.value = 4
                self.numSize.value = size_str
                ok = self.Execute()
                # print "Ok = %d"%ok
                if ok == 1:
                    if self.numSize.value.isnumeric():
                        struct_size = int(self.numSize.value, 10)
                    else:
                        struct_size = ida_kernwin.atoea(self.numSize.value)
                        if struct_size is None:
                            struct_size = ida_kernwin.str2ea(self.numSize.value)
                    logger.debug("struct size = {0}".format(struct_size))
                    return (
                        struct_size, self.cStrArg.value, int(self.numFieldSize.value),
                        self.ckAlign.checked, self.ckCppObj.checked, self.cStrArg2.value)
                return None

        ret = SimpleCreateStructForm().Go(size_str)
        if ret is not None:
            self.create_struct_type(*ret)
        return 1

if hex_pytools_config.get_opt("Create struct", "SimpleCreateStruct"):
    actions.action_manager.register(SimpleCreateStruct())