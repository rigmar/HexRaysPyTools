# Based on Rolf Rolles TemplatedTypes script
# https://www.msreverseengineering.com/blog/2021/9/21/automation-in-reverse-engineering-c-template-code

import os
import toml
import HexRaysPyTools.settings as settings

# fDebug = True
# if fDebug:
#     import pydevd_pycharm
#
# if fDebug == True:
#     pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
#

class TemplatedTypes:

    def __init__(self):

        self.toml_path = ""
        self._types_dict = {}
        self.keys = []
        print(settings.TEMPLATED_TYPES_FILE)
        self.set_file_path(settings.TEMPLATED_TYPES_FILE)

    def get_decl_str(self, key: str, args):
        # ensure type is in our dictionary
        if key in self._types_dict:
            type_count = len(self._types_dict[key]["types"])
            # ensure that the number of types is what we expect for format string
            if type_count * 2 == len(args):
                type_struct = self._types_dict[key]["struct"]
                type_name = self._types_dict[key]["base_name"]
                # apply formatting to struct string
                type_struct = type_struct.format(*args)
                type_name = type_name.format(*args)
                # return tuple
                return type_name, type_struct
            else:
                print("[ERROR] arg count does not match type")
                return None
        else:
            print(f"[ERROR] type is not in type dictionary: {key}")
            return None

    def get_types(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["types"]
        else:
            print("[ERROR] type is not in type dictionary")
            return None

    def get_struct(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["struct"]
        else:
            print("[ERROR] struct is not in type dictionary")
            return None

    def get_base_name(self, key):
        if key in self._types_dict:
            return self._types_dict[key]["base_name"]
        else:
            print("[ERROR] struct is not in type dictionary")
            return None

    def set_file_path(self, path):
        self.toml_path = path
        self.reload_types()

    def reload_types(self):
        with open(self.toml_path, "r") as f:
            types_dict = toml.loads(f.read())

        self._types_dict = types_dict
        self.keys = list(types_dict.keys())
