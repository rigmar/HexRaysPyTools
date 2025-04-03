# no_compat_file
import collections

import ida_hexrays
import ida_idp
import ida_loader
from idc import BADADDR

from HexRaysPyTools.log import Log

import ida_bytes
import ida_funcs
import ida_typeinf
import idaapi
import idc
import idautils
import ida_ida
import ida_idaapi

import HexRaysPyTools.core.cache as cache
import HexRaysPyTools.core.const as const
import HexRaysPyTools.settings as settings
import HexRaysPyTools.forms as forms


logger = Log.get_logger()


def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexx64",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
        ida_idp.PLFM_RISCV: "hexrv",
        ida_idp.PLFM_ARC: "HEXARC",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

def GetXrefCnt(ea):
    i = 0
    for xref in idautils.XrefsTo(ea, 0):
        i += 1
    return i

def convert_name(vt_name):
    if vt_name.startswith("0x"):
        vt_sid = int(vt_name.split(' ')[0], 16)
        return ida_typeinf.get_tid_name(vt_sid)
    return vt_name

def is_imported_ea(ea):
    if idc.get_segm_name(ea) == ".plt":
        return True
    return ea + idaapi.get_imagebase() in cache.imported_ea


def is_code_ea(ea):
    if const.INF_PROCNAME == "ARM":
        # In case of ARM code in THUMB mode we sometimes get pointers with thumb bit set
        flags = idaapi.get_full_flags(ea & -2)  # flags_t
    else:
        flags = idaapi.get_full_flags(ea)
    return idaapi.is_code(flags)


def is_rw_ea(ea):
    seg = idaapi.getseg(ea)
    return seg.perm & idaapi.SEGPERM_WRITE and seg.perm & idaapi.SEGPERM_READ


def get_ptr(ea):
    """ Reads ptr at specified address. """
    if const.EA64:
        return idaapi.get_64bit(ea)
    ptr = idaapi.get_32bit(ea)
    if const.INF_PROCNAME == "ARM":
        ptr &= -2    # Clear thumb bit
    return ptr


def get_ordinal(tinfo):
    """ Returns non-zero ordinal of tinfo if it exist in database """
    ordinal = tinfo.get_ordinal()
    if ordinal == 0:
        t = idaapi.tinfo_t()
        struct_name = tinfo.dstr().split()[-1]        # Get rid of `struct` prefix or something else
        t.get_named_type(idaapi.cvar.idati, struct_name)
        ordinal = t.get_ordinal()
    return ordinal


def get_virtual_func_addresses(name, tinfo=None, offset=None):
    """
    Returns set of possible addresses of virtual function by its name.
    If there're symbols in binary and name is the name of an overloaded function, then returns list of all address of
    this overloaded function.
    TODO: After implementing inheritance return set of methods of all child classes

    :param name: method name, can be mangled
    :param tinfo: class tinfo to which this method belong
    :param offset: virtual table offset
    :return: list of possible addresses
    """

    address = idc.get_name_ea_simple(name)

    if address != idaapi.BADADDR:
        return [address]

    raw_addresses = cache.demangled_names.get(name)
    if raw_addresses:
        addresses = [ea + idaapi.get_imagebase() for ea in raw_addresses]
        return addresses

    if tinfo is None or offset is None:
        return []

    offset *= 8
    udt_member = idaapi.udt_member_t()
    while tinfo.is_struct():
        address = cache.demangled_names.get(tinfo.dstr() + '::' + name, idaapi.BADADDR)
        if address != idaapi.BADADDR:
            return [address + idaapi.get_imagebase()]
        udt_member.offset = offset
        tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
        tinfo = udt_member.type.copy() # copy to avoid interr 918
        offset = offset - udt_member.offset


def choose_virtual_func_address(name, tinfo=None, offset=None):
    addresses = get_virtual_func_addresses(name, tinfo, offset)
    if not addresses:
        return

    if len(addresses) == 1:
        return addresses[0]

    chooser = forms.MyChoose(
        [[to_hex(ea), idc.demangle_name(idc.get_name(ea), idc.INF_LONG_DN)] for ea in addresses],
        "Select Function",
        [["Address", 10], ["Full name", 50]]
    )
    idx = chooser.Show(modal=True)
    if idx != -1:
        return addresses[idx]


def get_func_argument_info(function, expression):
    """
    Function is cexpr with opname == 'cot_call', expression is any son. Returns index of argument and it's type

    :param function: idaapi.cexpr_t
    :param expression: idaapi.cexpr_t
    :return: (int, idaapi.tinfo_t)
    """
    for idx, argument in enumerate(function.a):
        if expression == argument.cexpr:
            func_tinfo = function.x.type
            if idx < func_tinfo.get_nargs():
                return idx, func_tinfo.get_nth_arg(idx).copy() # copy to avoid interr 918
            return idx, None
    print("[ERROR] Wrong usage of 'Helper.get_func_argument_info()'")


def set_func_argument(func_tinfo, index, arg_tinfo):
    func_data = idaapi.func_type_data_t()
    func_tinfo.get_func_details(func_data)
    func_data[index].type = arg_tinfo
    func_tinfo.create_func(func_data)


def get_func_arg_name(func_tinfo, arg_idx):
    # type: (idaapi.tinfo_t, int) -> str

    func_data = idaapi.func_type_data_t()
    func_tinfo.get_func_details(func_data)
    if arg_idx < func_tinfo.get_nargs():
        return func_data[arg_idx].name


def set_func_arg_name(func_tinfo, arg_idx, name):
    # type: (idaapi.tinfo_t, int, str) -> None

    func_data = idaapi.func_type_data_t()
    func_tinfo.get_func_details(func_data)
    func_data[arg_idx].name = name
    func_tinfo.create_func(func_data)


def set_funcptr_argument(funcptr_tinfo, index, arg_tinfo):
    func_tinfo = funcptr_tinfo.get_pointed_object()
    set_func_argument(func_tinfo, index, arg_tinfo)
    funcptr_tinfo.create_ptr(func_tinfo)


def set_func_return(func_tinfo, return_tinfo):
    func_data = idaapi.func_type_data_t()
    func_tinfo.get_func_details(func_data)
    func_data.rettype = return_tinfo
    func_tinfo.create_func(func_data)


def get_nice_pointed_object(tinfo):
    """
    Returns nice pointer name (if exist) or None.
    For example if tinfo is PKSPIN_LOCK which is typedef of unsigned int *, then if in local types exist KSPIN_LOCK with
    type unsigned int, this function returns KSPIN_LOCK
    """
    try:
        name = tinfo.dstr()
        if name[0] == 'P':
            pointed_tinfo = idaapi.tinfo_t()
            if pointed_tinfo.get_named_type(idaapi.get_idati(), name[1:]):
                if tinfo.get_pointed_object().equals_to(pointed_tinfo):
                    return pointed_tinfo
    except TypeError:
        pass


def get_fields_at_offset(tinfo, offset):
    """
    Given tinfo and offset of the structure or union, returns list of all tinfo at that offset.
    This function helps to find appropriate structures by type of the offset
    """
    result = []
    if offset == 0:
        result.append(tinfo)
    udt_data = idaapi.udt_type_data_t()
    tinfo.get_udt_details(udt_data)
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    idx = tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
    if idx != -1:
        while idx < tinfo.get_udt_nmembers() and udt_data[idx].offset <= offset * 8:
            udt_member = udt_data[idx]
            if udt_member.offset == offset * 8:
                if udt_member.type.is_ptr():
                    result.append(idaapi.get_unk_type(const.EA_SIZE))
                    result.append(udt_member.type)
                    result.append(idaapi.dummy_ptrtype(const.EA_SIZE, False))
                elif not udt_member.type.is_udt():
                    result.append(udt_member.type)
            if udt_member.type.is_array():
                if (offset - udt_member.offset // 8) % udt_member.type.get_array_element().get_size() == 0:
                    result.append(udt_member.type.get_array_element())
            elif udt_member.type.is_udt():
                result.extend(get_fields_at_offset(udt_member.type, offset - udt_member.offset // 8))
            idx += 1
    result = [t.copy() for t in result]
    return result

def is_legal_type(tinfo: idaapi.tinfo_t):
    tinfo.clr_const()
    if tinfo.is_ptr() and tinfo.get_pointed_object().is_forward_decl():
        is_bad_size = tinfo.get_pointed_object().get_size() == idaapi.BADSIZE
        print(f"[DEBUG] Type {tinfo.dstr()} is forward declaration: {is_bad_size}")
        return is_bad_size
    if tinfo.is_unknown():
        print(f"[DEBUG] Type {tinfo.dstr()} is unknown")
        return False
    return True

# This function after 9.0 nearly always returns False
# def is_legal_type(tinfo: idaapi.tinfo_t):
#     tinfo.clr_const()

#     if tinfo.is_ptr() and tinfo.get_pointed_object().is_forward_decl():
#         is_bad_size = tinfo.get_pointed_object().get_size() == idaapi.BADSIZE
#         print(f"[DEBUG] Type {tinfo.dstr()} is forward declaration: {is_bad_size}")
#         return is_bad_size
#     legal_type = settings.SCAN_ANY_TYPE or bool([x for x in const.LEGAL_TYPES if x.equals_to(tinfo)])
#     legal_type = tinfo.is_ptr()
#     print(f"[DEBUG] Type {tinfo.dstr()} is legal: {legal_type}")
#     return legal_type


def search_duplicate_fields(udt_data):
    # Returns list of lists with duplicate fields

    default_dict = collections.defaultdict(list)
    for idx, udt_member in enumerate(udt_data):
        default_dict[udt_member.name].append(idx)
    return [indices for indices in list(default_dict.values()) if len(indices) > 1]


def get_member_name(tinfo, offset):
    udt_member = idaapi.udt_member_t()
    udt_member.offset = offset * 8
    tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
    return udt_member.name


def change_member_name(struct_name, offset, name):
    return idc.set_member_name(idc.get_struc_id(struct_name), offset, name)


def import_structure(name, tinfo):
    cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                       tinfo, name, None)
    if idc.parse_decl(cdecl_typedef, idaapi.PT_TYP) is None:
        return 0

    previous_ordinal = idaapi.get_type_ordinal(idaapi.get_idati(), name)
    if previous_ordinal:
        idaapi.del_numbered_type(idaapi.get_idati(), previous_ordinal)
        ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
    else:
        ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)
    return ordinal


def get_funcs_calling_address(ea):
    """ Returns all addresses of functions which make call to a function at `ea`"""
    xref_ea = idaapi.get_first_cref_to(ea)
    xrefs = set()
    while xref_ea != idaapi.BADADDR:
        xref_func_ea = idc.get_func_attr(xref_ea, idc.FUNCATTR_START)
        if xref_func_ea != idaapi.BADADDR:
            xrefs.add(xref_func_ea)
        else:
            print("[Warning] Function not found at 0x{0:08X}".format(xref_ea))
        xref_ea = idaapi.get_next_cref_to(ea, xref_ea)
    return xrefs


class FunctionTouchVisitor(idaapi.ctree_parentee_t):
    def __init__(self, cfunc):
        super(FunctionTouchVisitor, self).__init__()
        self.functions = set()
        self.cfunc = cfunc

    def visit_expr(self, expression):
        if expression.op == idaapi.cot_call:
            self.functions.add(expression.x.obj_ea)
        return 0

    def touch_all(self):
        diff = self.functions.difference(cache.touched_functions)
        for address in diff:
            if is_imported_ea(address):
                continue
            try:
                cfunc = idaapi.decompile(address)
                if cfunc:
                    FunctionTouchVisitor(cfunc).process()
            except idaapi.DecompilationFailure:
                logger.warning("IDA failed to decompile function at {}".format(to_hex(address)))
                cache.touched_functions.add(address)
        idaapi.decompile(self.cfunc.entry_ea)

    def process(self):
        if self.cfunc.entry_ea not in cache.touched_functions:
            cache.touched_functions.add(self.cfunc.entry_ea)
            self.apply_to(self.cfunc.body, None)
            self.touch_all()
            return True
        return False


def to_hex(ea):
    """ Formats address so it could be double clicked at console """
    if const.EA64:
        return "0x{:016X}".format(ea)
    return "0x{:08X}".format(ea)


def to_nice_str(ea):
    """ Shows address as function name + offset """
    func_start_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    func_name = idc.get_name(func_start_ea)
    offset = ea - func_start_ea
    return "{}+0x{:X}".format(func_name, offset)


def save_long_str_to_idb(array_name, value):
    """ Overwrites old array completely in process """
    id = idc.get_array_id(array_name)
    if id != -1:
        idc.delete_array(id)
    id = idc.create_array(array_name)
    r = []
    for idx in range(len(value) // 1024 + 1):
        s = value[idx * 1024: (idx + 1) * 1024]
        r.append(s)
        idc.set_array_string(id, idx, s)


def load_long_str_from_idb(array_name):
    id = idc.get_array_id(array_name)
    if id == -1:
        return None
    max_idx = idc.get_last_index(idc.AR_STR, id)
    result = []
    for idx in range(max_idx + 1):
        e = idc.get_array_element(idc.AR_STR, id, idx)
        if type(e) == int:
            e = e.to_bytes((e.bit_length() + 7) // 8, 'little')
        result.append(e)
    return b"".join(result).decode("utf-8")

def create_padding_udt_member(offset, size):
    # type: (long, long) -> idaapi.udt_member_t
    """ Creates internal IDA structure with name gap_XXX and appropriate size and offset """

    udt_member = idaapi.udt_member_t()
    udt_member.name = "gap_{0:X}".format(offset)
    udt_member.offset = offset
    udt_member.size = size

    if size == 1:
        udt_member.type = const.BYTE_TINFO
    else:
        if size < 1 or size > 0xffffffff:
            print("HexRaysPyTools::core::helper::create_padding_udt_member: size is out of uint32 range (offset:{} size:{})".format(offset, size))
        array_data = idaapi.array_type_data_t()
        array_data.base = 0
        array_data.elem_type = const.BYTE_TINFO
        array_data.nelems = size
        tmp_tinfo = idaapi.tinfo_t()
        tmp_tinfo.create_array(array_data)
        udt_member.type = tmp_tinfo
    return udt_member


def decompile_function(address):
    try:
        cfunc = idaapi.decompile(address)
        if cfunc:
            return cfunc
    except idaapi.DecompilationFailure:
        pass
    logger.warning("IDA failed to decompile function at 0x{address:08X}".format(address=address))


def find_asm_address(cexpr, parents):
    """ Returns most close virtual address corresponding to cexpr """

    ea = cexpr.ea
    if ea != idaapi.BADADDR:
        return ea

    for p in reversed(parents):
        if p.ea != idaapi.BADADDR:
            return p.ea


def my_cexpr_t(*args, **kwargs):
    """ Replacement of bugged cexpr_t() function """

    if len(args) == 0:
        return idaapi.cexpr_t()

    if len(args) != 1:
        raise NotImplementedError

    cexpr = idaapi.cexpr_t()
    cexpr.thisown = False
    if type(args[0]) == idaapi.cexpr_t:
        cexpr.assign(args[0])
    else:
        op = args[0]
        cexpr._set_op(op)

        if 'x' in kwargs:
            cexpr._set_x(kwargs['x'])
        if 'y' in kwargs:
            cexpr._set_y(kwargs['y'])
        if 'z' in kwargs:
            cexpr._set_z(kwargs['z'])
    return cexpr

def import_type(type_name):
    t = idaapi.tinfo_t()
    if not t.get_named_type(idaapi.cvar.idati, type_name):
        return idaapi.BADADDR
    return t.force_tid()

def get_func_ea(name):
    for ea in idautils.Functions():
        n = ida_funcs.get_func_name(ea)
        if n == name:
            return ea
    return None

def struct_get_struc_name(id):
    if hasattr(idc, "get_struc_name"): # ida 9.0
        return idc.get_struc_name(id)
    else:
        import ida_struct
        return ida_struct.get_struc_name(id)

# def struct_get_member_name(id):
#     if hasattr(idc, "get_member_name"): # ida 9.0
#         return idc.get_member_name(id)
#     else:
#         import ida_struct
#         return ida_struct.get_member_name(id)

def _import_type(type_name, ti=idaapi.cvar.idati):
    t = idaapi.tinfo_t()
    if not t.get_named_type(ti, type_name):
        return idaapi.BADADDR
    return t.force_tid()

def _get_member_cmt(tif, off):
    # if hasattr(idc, "get_struc_id"):
    _typename = tif.get_type_name()
    name_sid = idc.get_struc_id(_typename)
    cmt = idc.get_member_cmt(name_sid, off, 0)
    return cmt

def get_ordinal_qty(ti: "til_t"=None) -> "uint32":
    if hasattr(idaapi, 'get_ordinal_limit'):
        return idaapi.get_ordinal_limit(ti)
    else:
        return ida_typeinf.get_ordinal_limit(ti)

def get_ordinal_limit(ti: "til_t"=None) -> "uint32":
    return get_ordinal_qty(ti)

def __get_tinfo(name):
    idati = idaapi.get_idati()
    ti = idaapi.tinfo_t()

    for ordinal in range(1, get_ordinal_qty(idati) + 1):
        if ti.get_numbered_type(idati, ordinal) and ti.dstr() == name:
            return ti
    return None

def choose_tinfo(title):
    if hasattr(idaapi, 'choose_struct'):
        tinfo = idaapi.tinfo_t()
        ret = idaapi.choose_struct(tinfo, title)
        if ret:
            return tinfo
        else:
            return None
    else:
        struct = idaapi.choose_struc(title)  # no_compat
        if struct is None:
            return None
        sid = struct.id
        name = idaapi.get_struc_name(sid)  # no_compat

        tif = __get_tinfo(name)
        return tif

def get_struc(struct_tid):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(struct_tid):
        if tif.is_struct():
            return tif
    return ida_idaapi.BADADDR


def get_member(tif, offset):
    if not tif.is_struct():
        return None

    udm = ida_typeinf.udm_t()
    udm.offset = offset * 8
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
    if idx != -1:
        return udm

    return None

def del_struc_member(tif: ida_typeinf.tinfo_t, offset):

    if not tif.is_struct():
        return ida_typeinf.TERR_SAVE_ERROR

    udm = ida_typeinf.udm_t()
    udm.offset = offset * 8
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
    if idx != -1:
        return tif.del_udm(idx)
    return ida_typeinf.TERR_NOT_FOUND

def set_member_type(tif: ida_typeinf.tinfo_t, offset, new_type: ida_typeinf.tinfo_t, flags = 0):
    if not tif.is_struct():
        return ida_typeinf.TERR_SAVE_ERROR

    udm = ida_typeinf.udm_t()
    udm.offset = offset * 8
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
    if idx != -1:
        return tif.set_udm_type(idx, new_type, flags)
    return ida_typeinf.TERR_NOT_FOUND


def get_member_by_fullname(fullname):
    udm = ida_typeinf.udm_t()
    idx = ida_typeinf.get_udm_by_fullname(udm, fullname)
    if  idx == -1:
        return None
    else:
        return udm

def get_member_struc(fullname):
    udm = ida_typeinf.udm_t()
    idx = ida_typeinf.get_udm_by_fullname(udm, fullname)
    if idx != -1:
        if udm.type.is_struct():
            return ida_typeinf.tinfo_t(udm.type)
    return None

def get_member_tinfo(tif, udm):
    if tif and udm:
        ida_typeinf.copy_tinfo_t(tif, udm.type)
        return True
    return False


def get_member_by_name(tif, name):
    if not tif.is_struct():
        return None

    udm = ida_typeinf.udm_t()
    udm.name = name
    idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
    if idx != -1:
        return udm
    return None

def get_struc_idx(id):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(id):
        if tif.is_struct():
            return tif.get_ordinal()
    return -1

def get_struc_qty():
    count = 0
    limit = ida_typeinf.get_ordinal_limit()
    for i in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(i, ida_typeinf.BTF_STRUCT):
            continue
        else:
            count += 1
    return count

def is_varmember(udm):
    return udm.is_varmember()

# def is_special_member(member_id):
#     tif = ida_typeing.tinfo_t()
#     udm = ida_typeinf.udm_t()
#     if tif.get_udm_by_tid(udm, member_id) != -1:
#         return udm.is_special_member()
#     return False
#
# def is_varstr(str_id):
#     tif = ida_typeinf.tinfo_t()
#     if tif.get_type_by_tid(str_id):
#         return tif.is_varstruct()
#     return False

def get_sptr(udm):
    tif = udm.type
    if tif.is_udt() and tif.is_struct():
        return tif
    else:
        return None

def set_struc_listed(tif, is_listed):
    if tif.is_struct():
        ida_typeinf.set_type_choosable(None, tif.get_ordinal(), is_listed)

def get_member_id_by_udm(sid, udm):
    tif = ida_typeinf.tinfo_t(sid)
    udm_idx = tif.find_udm(udm)
    if udm_idx != -1:
        mid = tif.get_udm_tid(udm_idx)
        return mid
    return BADADDR