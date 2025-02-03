import ctypes
import sys

import idaapi
import idc

from . import const
from idaapi import til_t
import HexRaysPyTools.forms as forms
from HexRaysPyTools.core import helper


class til_t(ctypes.Structure):
    pass


til_t._fields_ = [
    ("name", ctypes.c_char_p),
    ("desc", ctypes.c_char_p),
    ("nbases", ctypes.c_int),
    ("base", ctypes.POINTER(ctypes.POINTER(til_t)))
]


def _enable_library_ordinals(library_num):
    idaname = "ida64" if const.EA64 else "ida"
    if sys.platform == "win32":
        dll = ctypes.windll[idaname + ".dll"]
    elif sys.platform == "linux2":
        dll = ctypes.cdll["lib" + idaname + ".so"]
    elif sys.platform == "darwin":
        dll = ctypes.cdll["lib" + idaname + ".dylib"]
    else:
        print("[ERROR] Failed to enable ordinals")
        return

    print("HexRaysPyTools DLL: {}".format(dll))

    dll.get_idati.restype = ctypes.POINTER(til_t)
    idati = dll.get_idati()
    dll.enable_numbered_types(idati.contents.base[library_num], True)


def choose_til():
    # type: () -> (idaapi.til_t, int, bool)
    """ Creates a list of loaded libraries, asks user to take one of them and returns it with
    information about max ordinal and whether it's local or imported library """
    idati = idaapi.get_idati()
    list_type_library = [(idati, idati.name, idati.desc)]
    for idx in range(idati.nbases):
        type_library = idati.base(idx)          # type: idaapi.til_t
        list_type_library.append((type_library, type_library.name, type_library.desc))

    library_chooser = forms.MyChoose(
        list([[x[1], x[2]] for x in list_type_library]),
        "Select Library",
        [["Library", 10 | idaapi.Choose.CHCOL_PLAIN], ["Description", 30 | idaapi.Choose.CHCOL_PLAIN]],
        69
    )
    library_num = library_chooser.Show(True)
    if library_num != -1:
        selected_library = list_type_library[library_num][0]    # type: idaapi.til_t
        max_ordinal = helper.get_ordinal_limit(selected_library)
        if max_ordinal == idaapi.BADORD:
            _enable_library_ordinals(library_num - 1)
            max_ordinal = helper.get_ordinal_limit(selected_library)
        print("[DEBUG] Maximal ordinal of lib {0} = {1}".format(selected_library.name, max_ordinal))
        return selected_library, max_ordinal, library_num == 0

def create_type(name: str, declaration: str) -> bool:
    """
    创建新类型
    :param name: 类型名称
    :param declaration: 类型声明
    :return: bool
    """

    # 检查类型是否已存在
    ordinal = idaapi.get_type_ordinal(idaapi.get_idati(), name)
    if ordinal:
        # 删除已存在的类型
        idaapi.del_numbered_type(idaapi.get_idati(), ordinal)

    # 创建新类型
    if idc.set_local_type(-1, declaration, 0) != 0:
        print(f"[Info] Successfully created type '{name}'")
        return True

    print(f"[ERROR] Failed to create type '{name}'")
    return False

def import_type(library, name):
    if library.name != idaapi.cvar.idati.name:
        last_ordinal = helper.get_ordinal_limit(idaapi.cvar.idati)
        type_id = helper._import_type(name, library)
        if type_id != idaapi.BADORD:
            return last_ordinal

def check_type_exists(type_name):
    """
    检查类型是否存在于本地类型库中
    :param type_name: 类型名称
    :return: bool
    """
    return idaapi.get_named_type(idaapi.get_idati(), type_name, 0) is not None

def delete_type(type_name):
    """
    从本地类型库中删除类型
    :param type_name: 类型名称
    :return: bool
    """
    ordinal = idaapi.get_type_ordinal(idaapi.get_idati(), type_name)
    if ordinal:
        return idaapi.del_numbered_type(idaapi.get_idati(), ordinal)
    return False

