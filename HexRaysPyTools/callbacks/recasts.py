from collections import namedtuple
from HexRaysPyTools.log import Log

import ida_typeinf
import idaapi
import idc

from . import actions
import HexRaysPyTools.core.helper as helper
from ..settings import get_config

fDebug = False
if fDebug:
    import pydevd_pycharm

logger = Log.get_logger()

RecastLocalVariable = namedtuple('RecastLocalVariable', ['recast_tinfo', 'local_variable'])
RecastGlobalVariable = namedtuple('RecastGlobalVariable', ['recast_tinfo', 'global_variable_ea'])
RecastArgument = namedtuple('RecastArgument', ['recast_tinfo', 'arg_idx', 'func_ea', 'func_tinfo'])
RecastReturn = namedtuple('RecastReturn', ['recast_tinfo', 'func_ea'])
RecastStructure = namedtuple('RecastStructure', ['recast_tinfo', 'structure_name', 'field_offset'])


class RecastItemLeft(actions.HexRaysPopupAction):

    description = "Recast Item"
    hotkey = "Shift+L"

    def __init__(self):
        super(RecastItemLeft, self).__init__()

    def extract_recast_info(self, cfunc, ctree_item):
        # type: (idaapi.cfunc_t, idaapi.ctree_item_t) -> namedtuple
        # Returns one of the Recast... namedtuple or None if nothing was found

        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it.to_specific_type
        child = None

        # Look through parents until we found Return, Assignment or Call
        while expression and expression.op not in (idaapi.cot_asg, idaapi.cit_return, idaapi.cot_call):
            child = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type
        if expression.op == idaapi.cot_asg:

            if expression.x.opname not in ('var', 'obj', 'memptr', 'memref'):
                return

            right_expr = expression.y
            right_tinfo = right_expr.x.type if right_expr.op == idaapi.cot_cast else right_expr.type

            # Check if both left and right parts of expression are of the same types.
            # If not then we can recast then.
            if right_tinfo.dstr() == expression.x.type.dstr():
                return

            if expression.x.op == idaapi.cot_var:
                # var = (TYPE ) ...;
                variable = cfunc.get_lvars()[expression.x.v.idx]
                return RecastLocalVariable(right_tinfo, variable)

            elif expression.x.op == idaapi.cot_obj:
                # g_var = (TYPE ) ...;
                return RecastGlobalVariable(right_tinfo, expression.x.obj_ea)

            # elif expression.x.op == idaapi.cot_memptr:
            #     # struct->member = (TYPE ) ...;
            #     struct_name = expression.x.x.type.get_pointed_object().dstr()
            #     struct_offset = expression.x.m
            #     return RecastStructure(right_tinfo, struct_name, struct_offset)
            #
            # elif expression.x.op == idaapi.cot_memref:
            #     # struct.member = (TYPE ) ...;
            #     struct_name = expression.x.x.type.dstr()
            #     struct_offset = expression.x.m
            #     return RecastStructure(right_tinfo, struct_name, struct_offset)

        elif expression.op == idaapi.cit_return:
            child = child or expression.creturn.expr
            if child.op == idaapi.cot_cast:
                # return (TYPE) ...;
                return RecastReturn(child.x.type, cfunc.entry_ea)

            func_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(func_tinfo)
            rettype = func_tinfo.get_rettype()
            if rettype.dstr() != child.type.dstr():
                # return ...;
                # This's possible when returned type and value are both pointers to different types
                return RecastReturn(child.type, cfunc.entry_ea)

        elif expression.op == idaapi.cot_call:
            if expression.x == child or expression.x.op == idaapi.cot_helper:
                return
            func_ea = expression.x.obj_ea
            arg_index, param_tinfo = helper.get_func_argument_info(expression, child)
            if expression.x.op == idaapi.cot_memptr:
                if child.op == idaapi.cot_cast:
                    # struct_ptr->func(..., (TYPE) var, ...);
                    arg_tinfo = child.x.type
                else:
                    # struct_ptr->func(..., var, ...); When `var` and `arg` are different pointers
                    if param_tinfo.equals_to(child.type):
                        return
                    arg_tinfo = child.type

                struct_tinfo = expression.x.x.type.get_pointed_object()
                funcptr_tinfo = expression.x.type
                helper.set_funcptr_argument(funcptr_tinfo, arg_index, arg_tinfo)
                return RecastStructure(funcptr_tinfo, struct_tinfo.dstr(), expression.x.m)

            if child.op == idaapi.cot_ref:
                if child.x.op == idaapi.cot_memref and child.x.m == 0:
                    # func(..., &struct.field_0, ...)
                    arg_tinfo = idaapi.tinfo_t()
                    arg_tinfo.create_ptr(child.x.x.type)
                elif child.x.op == idaapi.cot_memptr and child.x.m == 0:
                    # func(..., &struct->field_0, ...)
                    arg_tinfo = child.x.x.type
                else:
                    # func(..., &var, ...)
                    arg_tinfo = child.type
            elif child.op == idaapi.cot_cast:
                arg_tinfo = child.x.type
            else:
                arg_tinfo = child.type

            func_tinfo = expression.x.type.get_pointed_object()
            return RecastArgument(arg_tinfo, arg_index, func_ea, func_tinfo)

    def set_label(self, label):
        idaapi.update_action_label(self.name, label)

    def check(self, hx_view):
        cfunc, ctree_item = hx_view.cfunc, hx_view.item

        ri = self.extract_recast_info(cfunc, ctree_item)
        if not ri:
            return False

        if isinstance(ri, RecastLocalVariable):
            self.set_label('Recast Variable "{0}" to {1}'.format(ri.local_variable.name, ri.recast_tinfo.dstr()))
        elif isinstance(ri, RecastGlobalVariable):
            gvar_name = idaapi.get_name(ri.global_variable_ea)
            self.set_label('Recast Global Variable "{0}" to {1}'.format(gvar_name, ri.recast_tinfo.dstr()))
        elif isinstance(ri, RecastArgument):
            self.set_label("Recast Argument")
        elif isinstance(ri, RecastStructure):
            self.set_label("Recast Field of {0} structure".format(ri.structure_name))
        elif isinstance(ri, RecastReturn):
            self.set_label("Recast Return to ".format(ri.recast_tinfo.dstr()))
        else:
            raise NotImplementedError
        return True

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        ri = self.extract_recast_info(hx_view.cfunc, hx_view.item)
        if not ri:
            return 0

        if isinstance(ri, RecastLocalVariable):
            hx_view.set_lvar_type(ri.local_variable, ri.recast_tinfo)

        elif isinstance(ri, RecastGlobalVariable):
            idaapi.apply_tinfo(ri.global_variable_ea, ri.recast_tinfo, idaapi.TINFO_DEFINITE)
        #TODO: remove arguments name in tinfo
        elif isinstance(ri, RecastArgument):
            if ri.recast_tinfo.is_array():
                ri.recast_tinfo.convert_array_to_ptr()
            helper.set_func_argument(ri.func_tinfo, ri.arg_idx, ri.recast_tinfo)
            idaapi.apply_tinfo(ri.func_ea, ri.func_tinfo, idaapi.TINFO_DEFINITE)

        elif isinstance(ri, RecastReturn):
            cfunc = helper.decompile_function(ri.func_ea)
            if not cfunc:
                return 0

            func_tinfo = idaapi.tinfo_t()
            cfunc.get_func_type(func_tinfo)
            helper.set_func_return(func_tinfo, ri.recast_tinfo)
            idaapi.apply_tinfo(cfunc.entry_ea, func_tinfo, idaapi.TINFO_DEFINITE)

        elif isinstance(ri, RecastStructure):
            tinfo = idaapi.tinfo_t()
            tinfo.get_named_type(idaapi.get_idati(), ri.structure_name)
            ordinal = idaapi.get_type_ordinal(idaapi.get_idati(), ri.structure_name)
            if ordinal == 0:
                return 0

            udt_member = idaapi.udt_member_t()
            udt_member.offset = ri.field_offset * 8
            idx = tinfo.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)
            if udt_member.offset != ri.field_offset * 8:
                print("[Info] Can't handle with arrays yet")
            elif udt_member.type.get_size() != ri.recast_tinfo.get_size():
                print("[Info] Can't recast different sizes yet")
            else:
                udt_data = idaapi.udt_type_data_t()
                tinfo.get_udt_details(udt_data)
                udt_data[idx].type = ri.recast_tinfo
                tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)
                tinfo.set_numbered_type(idaapi.get_idati(), ordinal, idaapi.NTF_REPLACE, ri.structure_name)
        else:
            raise NotImplementedError

        hx_view.refresh_view(True)
        return 0


class RecastItemRight(RecastItemLeft):

    name = "my:RecastItemRight"
    description = "Recast Item"
    hotkey = "Shift+R"

    def __init__(self):
        super(RecastItemRight, self).__init__()

    def extract_recast_info(self, cfunc, ctree_item):
        if ctree_item.citype != idaapi.VDI_EXPR:
            return

        expression = ctree_item.it
        result = RecastItemRight._check_potential_array(cfunc, expression)
        if result:
            return result

        # Look through parents until we found Cast
        while expression and expression.op != idaapi.cot_cast:
            expression = expression.to_specific_type
            expression = cfunc.body.find_parent_of(expression)
        if not expression:
            return

        expression = expression.to_specific_type

        # Find `(TYPE) something;` or `(TYPE *) &something;` and calculate appropriate type for recast
        if expression.x.op == idaapi.cot_ref:
            tinfo = expression.type.get_pointed_object()
            expression = expression.x
        else:
            tinfo = expression.type

        if expression.x.op == idaapi.cot_var:
            # (TYPE) var;
            variable = cfunc.get_lvars()[expression.x.v.idx]
            return RecastLocalVariable(tinfo, variable)

        elif expression.x.op == idaapi.cot_obj:
            # (TYPE) g_var;
            if helper.is_code_ea(expression.x.obj_ea) and tinfo.is_funcptr():
                # (TYPE) sub_XXXXXX;
                tinfo = tinfo.get_pointed_object()
            gvar_ea = expression.x.obj_ea
            return RecastGlobalVariable(tinfo, gvar_ea)

        elif expression.x.op == idaapi.cot_call:
            # (TYPE) call();
            idaapi.update_action_label(RecastItemRight.name, "Recast Return")
            func_ea = expression.x.x.obj_ea
            return RecastReturn(tinfo, func_ea)

        # elif expression.x.op == idaapi.cot_memptr:
        #     # (TYPE) var->member;
        #     idaapi.update_action_label(RecastItemRight.name, "Recast Field")
        #     struct_name = expression.x.x.type.get_pointed_object().dstr()
        #     struct_offset = expression.x.m
        #     return RecastStructure(tinfo, struct_name, struct_offset)

    @staticmethod
    def _check_potential_array(cfunc, expr):
        """ Checks `call(..., &buffer, ..., number)` and returns information for recasting """
        if expr.op != idaapi.cot_var:
            return

        var_expr = expr.to_specific_type
        parent = cfunc.body.find_parent_of(expr)
        if parent.op != idaapi.cot_ref:
            return

        parent = cfunc.body.find_parent_of(parent)
        if parent.op != idaapi.cot_call:
            return

        call_expr = parent.to_specific_type
        for arg_expr in call_expr.a:
            if arg_expr.op == idaapi.cot_num:
                number = arg_expr.numval()
                if number:
                    variable = cfunc.lvars[var_expr.v.idx]
                    char_array_tinfo = idaapi.tinfo_t()
                    char_array_tinfo.create_array(idaapi.tinfo_t(idaapi.BTF_CHAR), number)
                    idaapi.update_action_label(RecastItemRight.name, 'Recast Variable "{}" to "{}"'.format(
                        variable.name, char_array_tinfo.dstr()
                    ))
                    return RecastLocalVariable(char_array_tinfo, variable)

def get_branch(cfunc,item):
    if type(item) is idaapi.ctree_item_t:
        item = item.it
    rc = [item.cexpr]
    while True:
        parent = cfunc.body.find_parent_of(item)
        if not parent or not parent.is_expr():
            break
        rc.append(parent.cexpr)
        item = parent
    rc.reverse()
    return rc

def is_gap(structure_name,field_offset):
    sid = idc.get_struc_id(structure_name)
    if sid != idaapi.BADADDR:
        sptr = helper.get_struc(sid)
        mptr = idaapi.get_member(sptr, field_offset)
        if mptr:
            return False
        else:
            return True

def get_struct_member_type(structure_name, field_offset):
    sid = idc.get_struc_id(structure_name)
    if sid != idaapi.BADADDR:
        sptr = helper.get_struc(sid)
        mptr = idaapi.get_member(sptr, field_offset)
        if mptr:
            tif = idaapi.tinfo_t()
            idaapi.get_member_tinfo(tif ,mptr)
            return tif
        return None


def get_struct_member_type_new(structure_name, field_offset):
    if ida_typeinf.get_type_ordinal(ida_typeinf.get_idati(), structure_name) != 0:
        pass

RECAST_HELPER = 1
RECAST_STRUCTURE = 4

class RecastStructMember(actions.HexRaysPopupAction):

    name = "my:RecastStructMember"
    description = "Recast Struct Member"
    hotkey = "Shift+M"
    ForPopup = True

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @staticmethod
    def check(hx_view):
        if fDebug:
            pydevd_pycharm.settrace('127.0.0.1', port=31337, stdoutToServer=True, stderrToServer=True, suspend=False)
        cfunc = hx_view.cfunc
        ctree_item = hx_view.item
        if ctree_item.citype == idaapi.VDI_EXPR and ctree_item.it.op in (idaapi.cot_memptr, idaapi.cot_memref):
            parent = cfunc.body.find_parent_of(ctree_item.it)
            if parent and parent.op == idaapi.cot_call and parent.cexpr.x.op == idaapi.cot_helper:
                cast_helper = parent.to_specific_type.x.helper
                helpers = ["HIBYTE", "LOBYTE", "BYTE", "HIWORD", "LOWORD"]
                for h in helpers:
                    if cast_helper.startswith(h):
                        return RECAST_HELPER, idaapi.remove_pointer(ctree_item.e.x.type).dstr(), ctree_item.e.m, cast_helper

            rc = get_branch(cfunc,ctree_item)
            branch_idx = 0
            off_delta = 0
            fDoDeref = False
            if rc:
                return RecastStructMember.process_branch(rc)
        return None

    @staticmethod
    def process_call_branch(nodes,idx = 0):
        target = nodes[-1]
        new_type = None
        fDoDeref = False
        off_delta = 0
        while nodes[idx] != target:
            item = nodes[idx]
            if item.op == idaapi.cot_cast:
                if new_type is None:
                    new_type = item.cexpr.type
            elif item.op == idaapi.cot_ref:
                fDoDeref = True
            elif item.op in (idaapi.cot_add, idaapi.cot_idx):
                if new_type is None and item.op == idaapi.cot_add:
                    new_type = item.cexpr.type
                num = item.cexpr.y.n._value if item.cexpr.x.index == nodes[idx + 1].index else item.to_specific_type.x.n._value
                off_delta += (num * idaapi.remove_pointer(item.cexpr.type).get_size())
            idx += 1
        if new_type:
            struct_name = target.cexpr.x.type.get_pointed_object().dstr() if target.op == idaapi.cot_memptr else \
                target.cexpr.x.type.dstr()
            if fDoDeref or (target.cexpr.type.is_array() and not target.cexpr.type.get_array_element().is_ptr()):
                new_type = idaapi.remove_pointer(new_type)
            return RECAST_STRUCTURE, struct_name, target.cexpr.m + off_delta, new_type

    @staticmethod
    def resolve_references(tp, ref_cnt, ptr_cnt):
        delta = ref_cnt - ptr_cnt
        if delta > 0:
            while delta:
                tp = idaapi.remove_pointer(tp)
                delta -= 1
        elif delta < 0:
            delta = abs(delta)
            while delta:
                tif = idaapi.tinfo_t()
                tif.create_ptr(tp)
                tp = tif
                delta -= 1
        return tp

    @staticmethod
    def process_asg_second_branch(nodes):
        top = nodes[0]
        target = nodes[-1]
        next_node = top.x if top.y.index == nodes[1].index else top.y
        ref_cnt = 0
        ptr_cnt = 0
        new_type = None
        while next_node and next_node.op not in (idaapi.cot_var, idaapi.cot_memptr, idaapi.cot_memref, idaapi.cot_call, idaapi.cot_num):
            if next_node.op == idaapi.cot_ref:
                ref_cnt += 1
            elif next_node.op == idaapi.cot_ptr:
                ptr_cnt += 1
            if next_node.x:
                next_node = next_node.x.cexpr
            else:
                break
        return RecastStructMember.resolve_references(next_node.type, ref_cnt, ptr_cnt)


    @staticmethod
    def process_asg_branch(nodes, idx = 0):
        second_branch_node = nodes[idx].cexpr.x if nodes[idx+1].index == nodes[idx].cexpr.y.index else nodes[idx].cexpr.y
        target = nodes[-1]
        new_type = None
        fDoDeref = False
        ref_cnt = 0
        ptr_cnt = 0
        off_delta = 0
        new_type_second = None
        while second_branch_node and second_branch_node.op not in (idaapi.cot_var,):
            second_branch_node = second_branch_node.cexpr.x
        if second_branch_node:
            new_type_second = second_branch_node.cexpr.type
        while nodes[idx] != target:
            item = nodes[idx]
            if item.op == idaapi.cot_cast:
                if new_type is None:
                    new_type = item.cexpr.type
            elif item.op == idaapi.cot_ref:
                ref_cnt += 1
            elif item.op == idaapi.cot_ptr:
                ptr_cnt += 1
            elif item.op in (idaapi.cot_add, idaapi.cot_idx):
                if new_type is None and item.op == idaapi.cot_add:
                    new_type = item.cexpr.type
                num = item.cexpr.y.n._value if item.cexpr.x.index == nodes[idx + 1].index else item.to_specific_type.x.n._value
                off_delta += (num * idaapi.remove_pointer(item.cexpr.type).get_size())
            idx += 1
        if new_type or (new_type_second and target.cexpr.type.dstr() != new_type_second.dstr()):
            struct_name = target.cexpr.x.type.get_pointed_object().dstr() if target.op == idaapi.cot_memptr else \
                target.cexpr.x.type.dstr()
            new_type = RecastStructMember.resolve_references(new_type,ref_cnt,ptr_cnt)
            if target.cexpr.type.is_array() and not target.cexpr.type.get_array_element().is_ptr():
                new_type = idaapi.remove_pointer(new_type)
            return RECAST_STRUCTURE, struct_name, target.cexpr.m + off_delta, new_type

    @staticmethod
    def process_branch(nodes, idx = 0):
        target = nodes[-1]
        # types = collections.OrderedDict()
        opcodes = []
        new_type = None
        asg_type = None
        ref_cnt = 0
        ptr_cnt = 0
        off_delta = 0
        while nodes[idx] != target:
            item = nodes[idx]
            opcodes.append(item.op)
            if item.op == idaapi.cot_cast:
                # types[item] = item.cexpr.type
                if new_type is None:
                    new_type = item.cexpr.type
            elif item.op == idaapi.cot_asg:
                # asg_type = item.cexpr.type
                second_type = RecastStructMember.process_asg_second_branch(nodes[idx:])
                if target.type != second_type:
                    # types[item] = item.cexpr.type
                    asg_type = second_type
            elif item.op == idaapi.cot_ref:
                ref_cnt += 1
            elif item.op == idaapi.cot_ptr:
                # types[item] = item.cexpr.type
                if new_type is None:
                    new_type = item.cexpr.type
                ptr_cnt += 1
            elif item.op in (idaapi.cot_add, idaapi.cot_idx):
                # types[item] = item.cexpr.type
                if item.x.op == idaapi.cot_num or item.y.op == idaapi.cot_num:
                    if new_type is None and item.op == idaapi.cot_add:
                        new_type = item.cexpr.type
                    num = item.cexpr.y.n._value if item.cexpr.x.index == nodes[idx + 1].index else item.cexpr.x.n._value
                    off_delta += (num * idaapi.remove_pointer(item.cexpr.type).get_size())
                else:
                    return None
            idx += 1
        if asg_type is not None and new_type is None:
            new_type = asg_type
        if new_type is not None:
            #cool 8.4. Two similar cases for struct->field. In one x node have type struct*, in another - just struct without pointer. Briliant.
            if target.op == idaapi.cot_memptr:
                if target.cexpr.x.type.is_ptr():
                    struct_name = target.cexpr.x.type.get_pointed_object()._print()
                else:
                    struct_name = target.cexpr.x.type._print()
            else:
                struct_name = target.cexpr.x.type._print()
            logger.debug("[process_branch] struct_name = %s"%struct_name)
            new_type = RecastStructMember.resolve_references(new_type,ref_cnt,ptr_cnt)
            struct_member_type = get_struct_member_type(struct_name, target.cexpr.m + off_delta)
            if new_type.is_ptr() and idaapi.cot_idx not in opcodes and (is_gap(struct_name,target.cexpr.m + off_delta) or (struct_member_type!=None and struct_member_type.is_array())):
                new_type = new_type.get_pointed_object()
            return RECAST_STRUCTURE, struct_name, target.cexpr.m + off_delta, new_type

    def activate(self, ctx):
        hx_view = idaapi.get_widget_vdui(ctx.widget)
        result = self.check(hx_view)
        if result:
            if result[0] == RECAST_HELPER:
                struct_name, member_offset, cast_helper = result[1:]
                sid = idc.get_struc_id(struct_name)
                if sid != idaapi.BADADDR:
                    sptr = helper.get_struc(sid)
                    mptr = idaapi.get_member(sptr,member_offset)
                    member_name = idc.get_member_name(mptr.id,member_offset)
                    member_size = idaapi.get_member_size(mptr)
                    if cast_helper.startswith("BYTE") or cast_helper in ("HIBYTE", "LOBYTE"):
                        idaapi.del_struc_member(sptr, member_offset)
                        for i in range(member_size):
                            idc.add_struc_member(sptr.id,member_name if i == 0 else "field_%X"%(member_offset + i), member_offset+i, idaapi.FF_DATA|idaapi.FF_BYTE,idaapi.BADADDR, 1)
                    if cast_helper in ("LOWORD","HIWORD"):
                        idaapi.del_struc_member(sptr, member_offset)
                        for i in range(0,member_size,2):
                            idc.add_struc_member(sptr.id,member_name if i == 0 else "field_%X"%(member_offset + i), member_offset+i, idaapi.FF_DATA|idaapi.FF_WORD,idaapi.BADADDR, 2)
                    hx_view.refresh_view(True)

            elif result[0] == RECAST_STRUCTURE:
                structure_name, field_offset, new_type = result[1:]
                sid = idc.get_struc_id(structure_name)
                if sid != idaapi.BADADDR:
                    sptr = helper.get_struc(sid)
                    mptr = idaapi.get_member(sptr, field_offset)
                    if mptr is None:
                        if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                                   idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                            print ("Error on add_struc_member!")
                        mptr = idaapi.get_member(sptr, field_offset)
                    elif mptr.soff != field_offset:
                        if not idaapi.del_struc_member(sptr, mptr.soff):
                            print ("Error on del_struc_member!")
                        if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                                   idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                            print ("Error on add_struc_member!")
                        mptr = idaapi.get_member(sptr, field_offset)
                    else:
                        tif = idaapi.tinfo_t()
                        idaapi.get_member_tinfo(tif,mptr)
                        if tif.is_array():
                            if not idaapi.del_struc_member(sptr, mptr.soff):
                                print ("Error on del_struc_member!")
                            if idaapi.add_struc_member(sptr, "field_%X" % field_offset, field_offset,
                                                       idaapi.FF_DATA | idaapi.FF_BYTE, None, 1) != 0:
                                print ("Error on add_struc_member!")
                            mptr = idaapi.get_member(sptr, field_offset)
                    rc = idaapi.set_member_tinfo(sptr, mptr, field_offset, new_type,
                                                  idaapi.SET_MEMTI_MAY_DESTROY)
                    if rc != 1:
                        print ("set_member_tinfo2 rc = %d" % rc)
                    hx_view.refresh_view(True)


if get_config().get_opt("Recasts", "RecastItemLeft"):
    actions.action_manager.register(RecastItemLeft())
if get_config().get_opt("Recasts", "RecastItemRight"):
    actions.action_manager.register(RecastItemRight())
if get_config().get_opt("Recasts", "RecastStructMember"):
    actions.action_manager.register(RecastStructMember())
