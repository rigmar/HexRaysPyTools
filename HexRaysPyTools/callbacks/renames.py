﻿import re
from HexRaysPyTools.log import Log

import idaapi
import idc

from . import actions
import HexRaysPyTools.api as api
import HexRaysPyTools.core.helper as helper
import HexRaysPyTools.settings as settings
from ..settings import get_config

fDebug = False
if fDebug:
    import pydevd_pycharm

logger = Log.get_logger()


def _should_be_renamed(old_name, new_name):
    # type: (str, str) -> bool
    """ Checks if there's a point to rename a variable or argument """

    # There's no point to rename into default name
    if _is_default_name(new_name):
        return False

    # Strip prefixes and check if names are the same
    return old_name.lstrip('_') != new_name.lstrip('_')


def _is_default_name(string):
    return re.match(r"[av]\d+$", string) is not None or \
           re.match(r"[qd]?word|field_|off_", string) is not None


class RenameOther(actions.HexRaysPopupAction):
    description = "Take other name"
    hotkey = "Ctrl+N"

    def __init__(self):
        super(RenameOther, self).__init__()

    def check(self, hx_view):
        return self.__extract_rename_info(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.__extract_rename_info(hx_view.cfunc, hx_view.item)

        if result:
            lvar, name = result
            while not hx_view.rename_lvar(lvar, name, True):
                name = '_' + name

    @staticmethod
    def __extract_rename_info(cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> (idaapi.lvar_t, str)

        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_var:
            return

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_asg:
            return

        other = parent.theother(expression)
        if other.op != idaapi.cot_var:
            return

        this_lvar = ctree_item.get_lvar()
        other_lvar = cfunc.get_lvars()[other.v.idx]

        if _should_be_renamed(this_lvar.name, other_lvar.name):
            return this_lvar, other_lvar.name.lstrip('_')


class RenameInside(actions.HexRaysPopupAction):
    description = "Rename inside argument"
    hotkey = "Shift+N"

    def __init__(self):
        super(RenameInside, self).__init__()

    def check(self, hx_view):
        return self.__extract_rename_info(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.__extract_rename_info(hx_view.cfunc, hx_view.item)

        if result:
            func_tinfo, address, arg_index, name = result
            helper.set_func_arg_name(func_tinfo, arg_index, name)
            idaapi.apply_tinfo(address, func_tinfo, idaapi.TINFO_DEFINITE)
            hx_view.refresh_view(True)

    @staticmethod
    def __extract_rename_info(cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> (idaapi.tinfo_t, long, int, str)

        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_var:
            return

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_call or parent.x.obj_ea == idaapi.BADADDR:
            return

        lvar = ctree_item.get_lvar()
        arg_index, _ = helper.get_func_argument_info(parent, expression)
        func_tinfo = parent.x.type.get_pointed_object()
        arg_name = helper.get_func_arg_name(func_tinfo, arg_index)
        if _should_be_renamed(arg_name, lvar.name):
            return func_tinfo, parent.x.obj_ea, arg_index, lvar.name.lstrip('_')


class RenameOutside(actions.HexRaysPopupAction):
    description = "Take argument name"
    hotkey = "Ctrl+Shift+N"

    def __init__(self):
        super(RenameOutside, self).__init__()

    def check(self, hx_view):
        return self.__extract_rename_info(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.__extract_rename_info(hx_view.cfunc, hx_view.item)

        if result:
            lvar, name = result
            while not hx_view.rename_lvar(lvar, name, True):
                name = '_' + name

    @staticmethod
    def __extract_rename_info(cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> (idaapi.lvar_t, str)

        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_var:
            return

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_call or parent.x.obj_ea == idaapi.BADADDR:
            return

        lvar = ctree_item.get_lvar()
        arg_index, _ = helper.get_func_argument_info(parent, expression)
        func_tinfo = parent.x.type.get_pointed_object()
        arg_name = helper.get_func_arg_name(func_tinfo, arg_index)
        if arg_name and _should_be_renamed(lvar.name, arg_name):
            return lvar, arg_name.lstrip("_")

class RenameMemberFromFunctionName(actions.HexRaysPopupAction):
    description = "Take name from function"
    hotkey = "Ctrl+Alt+N"

    def __init__(self):
        super(RenameMemberFromFunctionName, self).__init__()

    def check(self, hx_view):
        return self.__extract_rename_info(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        info = self.__extract_rename_info(hx_view.cfunc, hx_view.item)

        if info:
            mname = info.name;
            sname = re.sub('struct ', '', info.struct_name);

            if not re.search("_vtbl$", sname):
                mname = re.sub('^(get|set)*', 'm', mname, flags=re.IGNORECASE)

            if not helper.change_member_name(sname, info.offset, mname):
                mname = mname + '_' + hex(info.offset)[2:]
                helper.change_member_name(sname, info.offset, mname)

            hx_view.refresh_view(True)

    @staticmethod
    def __extract_rename_info(cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> api.StructRefObject

        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expr = ctree_item.it.to_specific_type
        if expr.op == idaapi.cot_memptr:
            t = expr.x.type.get_pointed_object()
        elif expr.op == idaapi.cot_memref:
            t = expr.x.type
        else:
            return

        # Get name string
        result = api.StructRefObject(t.dstr(), expr.m)
        result.name = idaapi.get_name(cfunc.entry_ea)
        if idaapi.is_valid_typename(result.name):
            return result

        result.name = idc.demangle_name(result.name, idc.get_inf_attr(3)) # Get only main name
        if result.name is None:
            return

        result.name = re.sub('^.*:', '', result.name)
        if result.name is None:
            return

        return result

class _RenameUsingAssertVisitor(idaapi.ctree_parentee_t):

    def __init__(self, cfunc, func_addr, arg_idx):
        idaapi.ctree_parentee_t.__init__(self)
        self.__cfunc = cfunc
        self.__func_addr = func_addr
        self.__arg_idx = arg_idx
        self.__possible_names = set()

    def visit_expr(self, expr):
        if expr.op == idaapi.cot_call and expr.x.op == idaapi.cot_obj and expr.x.obj_ea == self.__func_addr:
            arg_expr = expr.a[self.__arg_idx]
            if arg_expr.op != idaapi.cot_obj:
                cexpr_ea = helper.find_asm_address(expr, self.parents)
                logger.error("Argument is a not string at {}".format(helper.to_hex(cexpr_ea)))
                return 1
            self.__add_func_name(arg_expr)
        return 0

    def process(self):
        self.apply_to(self.__cfunc.body, None)
        if len(self.__possible_names) == 1:
            # Only one potential name was found, rename function using it
            new_name = self.__possible_names.pop()
            logger.info("Renaming function at {} to `{}`".format(helper.to_hex(self.__cfunc.entry_ea), new_name))
            idc.set_name(self.__cfunc.entry_ea, new_name)
        elif len(self.__possible_names) > 1:
            logger.error("Function at {} has more than one candidate for renaming: {}".format(
                helper.to_hex(self.__cfunc.entry_ea), ", ".join(self.__possible_names)))

    def __add_func_name(self, arg_expr):
        new_name = idc.get_strlit_contents(arg_expr.obj_ea)
        if type(new_name) is not str:
            # convert bytes to str (python 3)
            new_name = new_name.decode('ascii')
        if not idaapi.is_valid_typename(new_name):
            logger.warning("Argument has a weird name `{}` at {}".format(
                new_name, helper.to_hex(helper.find_asm_address(arg_expr, self.parents))))
            return

        self.__possible_names.add(new_name)


class RenameUsingAssert(actions.HexRaysPopupAction):
    description = "Rename as assert argument"
    hotkey = None

    def __init__(self):
        super(RenameUsingAssert, self).__init__()

    @staticmethod
    def __can_be_part_of_assert(cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> bool
        """
        Returns true if expression we clicked is an argument passed to a function
        and this argument is a string that can be a valid function name
        """

        if ctree_item.citype != idaapi.VDI_EXPR:
            return False

        expression = ctree_item.it.to_specific_type
        if expression.op != idaapi.cot_obj:
            return False

        parent = cfunc.body.find_parent_of(expression).to_specific_type
        if parent.op != idaapi.cot_call or parent.x.op != idaapi.cot_obj:
            return False

        obj_ea = expression.obj_ea
        if not helper.is_code_ea(obj_ea) and idc.get_str_type(obj_ea) == idc.STRTYPE_C:
            str_potential_name = idc.get_strlit_contents(obj_ea)
            if type(str_potential_name) is not str:
                # convert bytes to str (python 3)
                str_potential_name = str_potential_name.decode('ascii')
            return idaapi.is_valid_typename(str_potential_name)
        return False

    def check(self, hx_view):
        return self.__can_be_part_of_assert(hx_view.cfunc, hx_view.item)

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        if not self.__can_be_part_of_assert(hx_view.cfunc, hx_view.item):
            return

        # So we clicked on function an func argument that is a string. Now we extract
        # argument index and address of assert function
        expr_arg = hx_view.item.it.to_specific_type
        expr_call = hx_view.cfunc.body.find_parent_of(expr_arg).to_specific_type
        arg_idx, _ = helper.get_func_argument_info(expr_call, expr_arg)
        assert_func_ea = expr_call.x.obj_ea

        # Iterate through all places where assert function and rename using helper class
        all_callers = helper.get_funcs_calling_address(assert_func_ea)
        for caller_ea in all_callers:
            cfunc = helper.decompile_function(caller_ea)
            if cfunc:
                _RenameUsingAssertVisitor(cfunc, assert_func_ea, arg_idx).process()

        hx_view.refresh_view(True)


class _NamePropagator(api.RecursiveObjectDownwardsVisitor):
        def __init__(self, hx_view, cfunc, obj):
            super(_NamePropagator, self).__init__(cfunc, obj, skip_until_object=True)
            self.__hx_view = hx_view
            self.__propagated_name = obj.name

        def _start_iteration(self):
            self.__hx_view.switch_to(self._cfunc, False)

        def _manipulate(self, cexpr, obj):
            if self.crippled:
                logger.debug("Skipping crippled function at {}".format(helper.to_hex(self._cfunc.entry_ea)))
                return

            if obj.id == api.SO_GLOBAL_OBJECT:
                old_name = idaapi.get_short_name(cexpr.obj_ea)
                if settings.PROPAGATE_THROUGH_ALL_NAMES or _is_default_name(old_name):
                    new_name = self.__rename_with_prefix(
                        lambda x: idaapi.set_name(cexpr.obj_ea, x),
                        self.__propagated_name)
                    logger.debug("Renamed global variable from {} to {}".format(old_name, new_name))
            elif obj.id == api.SO_LOCAL_VARIABLE:
                lvar = self._cfunc.get_lvars()[cexpr.v.idx]
                old_name = lvar.name
                if settings.PROPAGATE_THROUGH_ALL_NAMES or _is_default_name(old_name):
                    new_name = self.__rename_with_prefix(
                        lambda x: self.__hx_view.rename_lvar(lvar, x, True),
                        self.__propagated_name)
                    logger.debug("Renamed local variable from {} to {}".format(old_name, new_name))
            elif obj.id in (api.SO_STRUCT_POINTER, api.SO_STRUCT_REFERENCE):
                struct_tinfo = cexpr.x.type
                offset = cexpr.m
                struct_tinfo.remove_ptr_or_array()
                old_name = helper.get_member_name(struct_tinfo, offset)
                if settings.PROPAGATE_THROUGH_ALL_NAMES or _is_default_name(old_name):
                    new_name = self.__rename_with_prefix(
                        lambda x: helper.change_member_name(struct_tinfo.dstr(), offset, x),
                        self.__propagated_name)
                    logger.debug("Renamed struct member from {} to {}".format(old_name, new_name))

        def _finish(self):
            self.__hx_view.switch_to(self._cfunc, True)

        @staticmethod
        def __rename_with_prefix(rename_func, name):
            while not rename_func(name):
                name = "_" + name
            return name


class PropagateName(actions.HexRaysPopupAction):
    description = "Propagate name"
    hotkey = "P"

    def __init__(self):
        super(PropagateName, self).__init__()

    @staticmethod
    def __extract_propagate_info(cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        obj = api.ScanObject.create(cfunc, ctree_item)
        if obj and not _is_default_name(obj.name):
            return obj

    def check(self, hx_view):
        return self.__extract_propagate_info(hx_view.cfunc, hx_view.item) is not None

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        obj = self.__extract_propagate_info(hx_view.cfunc, hx_view.item)
        if obj:
            cfunc = hx_view.cfunc
            visitor = _NamePropagator(hx_view, cfunc, obj)
            visitor.process()
            hx_view.refresh_view(True)


class TakeTypeAsName(actions.HexRaysPopupAction):

    name = "my:TakeTypeAsName"
    description = "Take Type As Name"
    hotkey = ""
    ForPopup = True

    def __init__(self):
        super().__init__()

    def check(self,hx_view):
        if fDebug:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        cfunc = hx_view.cfunc
        ctree_item = hx_view.item
        if ctree_item.citype == idaapi.VDI_EXPR:
            if ctree_item.it.op in (idaapi.cot_memptr, idaapi.cot_memref):
                tp_name = idaapi.remove_pointer(ctree_item.e.type).dstr()
                struct_name = idaapi.remove_pointer(ctree_item.e.x.type).dstr()
                if idaapi.get_type_ordinal(idaapi.get_idati(), struct_name) and idaapi.get_type_ordinal(idaapi.get_idati(), tp_name):
                    sid = idc.get_struc_id(struct_name)
                    if sid != idaapi.BADADDR:
                        field_name = idc.get_member_name(sid, ctree_item.e.m)
                        if tp_name not in field_name:
                            return True

            elif ctree_item.it.op == idaapi.cot_var:
                lv = cfunc.get_lvars()[ctree_item.e.v.idx]
                lv_type_name = idaapi.remove_pointer(lv.tif).dstr()
                if idaapi.get_type_ordinal(idaapi.get_idati(),lv_type_name) and lv_type_name not in lv.name:
                    return True

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        item = hx_view.item.e
        if item.op in (idaapi.cot_memptr, idaapi.cot_memref):
            offset = item.m
            tp_name = "p" if item.type.is_ptr() else "o_"
            tp_name = tp_name + idaapi.remove_pointer(item.type).dstr()
            struct_name = idaapi.remove_pointer(item.x.type).dstr()
            sid = idc.get_struc_id(struct_name)
            idc.set_member_name(sid,offset,tp_name)

            hx_view.refresh_view(True)
        elif item.op == idaapi.cot_var:
            lv = hx_view.cfunc.get_lvars()[item.v.idx]
            tp_name = "p" if lv.tif.is_ptr() else "o_"
            tp_name = tp_name + idaapi.remove_pointer(lv.tif).dstr()
            hx_view.rename_lvar(lv,tp_name,True)
            hx_view.refresh_view(True)

if get_config().get_opt("Renames", "RenameOther"):
    actions.action_manager.register(RenameOther())
if get_config().get_opt("Renames", "RenameInside"):
    actions.action_manager.register(RenameInside())
if get_config().get_opt("Renames", "RenameOutside"):
    actions.action_manager.register(RenameOutside())
if get_config().get_opt("Renames", "RenameUsingAssert"):
    actions.action_manager.register(RenameUsingAssert())
if get_config().get_opt("Renames", "PropagateName"):
    actions.action_manager.register(PropagateName())
if get_config().get_opt("Renames", "TakeTypeAsName"):
    actions.action_manager.register(TakeTypeAsName())
if get_config().get_opt("Renames", "RenameMemberFromFunctionName"):
    actions.action_manager.register(RenameMemberFromFunctionName())
