import idaapi

EA64 = None
EA_SIZE = None

INF_IS_64BIT = None
INF_IS_32BIT = None
INF_IS_BE = None
INF_PROCNAME = None

COT_ARITHMETIC = (idaapi.cot_num, idaapi.cot_fnum, idaapi.cot_add, idaapi.cot_fadd, idaapi.cot_sub, idaapi.cot_fsub,
                  idaapi.cot_mul, idaapi.cot_fmul, idaapi.cot_fdiv)

VOID_TINFO = None
PVOID_TINFO = idaapi.tinfo_t()
CONST_VOID_TINFO = None
CONST_PVOID_TINFO = idaapi.tinfo_t()
CHAR_TINFO = None
PCHAR_TINFO = idaapi.tinfo_t()
CONST_PCHAR_TINFO = idaapi.tinfo_t()
BYTE_TINFO = None
PBYTE_TINFO = None

WORD_TINFO = None
PWORD_TINFO = idaapi.tinfo_t()

X_WORD_TINFO = None                 # DWORD for x32 and QWORD for x64
PX_WORD_TINFO = None

DUMMY_FUNC = None

LEGAL_TYPES = []


def init():
    """ All tinfo should be reinitialized between session. Otherwise they could have wrong type """
    global VOID_TINFO, PVOID_TINFO, CONST_PVOID_TINFO, BYTE_TINFO, PBYTE_TINFO, LEGAL_TYPES, X_WORD_TINFO, \
        PX_WORD_TINFO, DUMMY_FUNC, CONST_PCHAR_TINFO, CHAR_TINFO, PCHAR_TINFO, CONST_VOID_TINFO, \
        WORD_TINFO, PWORD_TINFO, EA64, EA_SIZE

    if hasattr(idaapi, 'get_inf_structure'):
        info = idaapi.get_inf_structure()
        try:
            cpuname = info.procname.lower()
        except:
            cpuname = info.procName.lower()
        try:
            # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
            is_be = idaapi.cvar.inf.is_be()
        except:
            # older IDA versions
            is_be = idaapi.cvar.inf.mf
        is_64bit = info.is_64bit()
        is_32bit = info.is_32bit()
    elif hasattr(idaapi, 'get_idp_name'):
        cpuname = idaapi.get_idp_name().lower()
        is_64bit = idaapi.inf_is_64bit()
        is_32bit = idaapi.inf_is_32bit_exactly()
        is_be = idaapi.inf_is_be()
    else:
        assert False, "Unexpected IDAPython API"
    INF_PROCNAME = cpuname
    INF_IS_BE = is_be
    
    if is_64bit:
        INF_IS_64BIT = True
        INF_IS_32BIT = False
        EA64 = True
        EA_SIZE = 8
    elif is_32bit:
        INF_IS_64BIT = False
        INF_IS_32BIT = True
        EA64 = False
        EA_SIZE = 4
    else:
        INF_IS_64BIT = False
        INF_IS_32BIT = False
        EA64 = False
        EA_SIZE = 2

    VOID_TINFO = idaapi.tinfo_t(idaapi.BT_VOID)
    PVOID_TINFO.create_ptr(VOID_TINFO)
    CONST_VOID_TINFO = idaapi.tinfo_t(idaapi.BT_VOID | idaapi.BTM_CONST)
    CONST_PVOID_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID | idaapi.BTM_CONST))
    CONST_PCHAR_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BTF_CHAR | idaapi.BTM_CONST))
    CHAR_TINFO = idaapi.tinfo_t(idaapi.BTF_CHAR)
    PCHAR_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BTF_CHAR))
    BYTE_TINFO = idaapi.tinfo_t(idaapi.BTF_BYTE)
    PBYTE_TINFO = idaapi.dummy_ptrtype(1, False)
    X_WORD_TINFO = idaapi.get_unk_type(EA_SIZE)
    PX_WORD_TINFO = idaapi.dummy_ptrtype(EA_SIZE, False)

    WORD_TINFO = idaapi.tinfo_t(idaapi.BT_UNK_WORD)
    PWORD_TINFO.create_ptr(idaapi.tinfo_t(idaapi.BT_UNK_WORD))

    func_data = idaapi.func_type_data_t()
    func_data.rettype = PVOID_TINFO
    func_data.cc = idaapi.CM_CC_UNKNOWN
    DUMMY_FUNC = idaapi.tinfo_t()
    DUMMY_FUNC.create_func(func_data, idaapi.BT_FUNC)

    LEGAL_TYPES = [PVOID_TINFO, PX_WORD_TINFO, PWORD_TINFO, PBYTE_TINFO, X_WORD_TINFO]
