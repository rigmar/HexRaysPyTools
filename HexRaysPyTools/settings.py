import os
import logging

import ida_diskio
import ida_kernwin
import idc
import configparser
from HexRaysPyTools.log import Log

logger = Log.get_logger()

hex_pytools_config = None

def get_config():
    global hex_pytools_config
    if hex_pytools_config is None:
        hex_pytools_config = Config()
    return hex_pytools_config

class ConfigFeaturesChooser(ida_kernwin.Choose):

    def __init__(self, config, parent):

        self.config = config
        self.parent = parent

        super(ConfigFeaturesChooser, self).__init__("Features", [["Feature section", 40], ["Feature name", 40], ["Status", 10]], embedded=True)

        self.n = 0
        self.items = []

        self.make_items()

    def make_items(self):
        for section in self.config.FeaturesListDef:
            for opt in self.config.FeaturesListDef[section]:
                self.items.append([section, opt, "Enabled" if self.config.get_opt(section, opt) else "Disabled"])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnSelectLine(self, n):
        section, opt, status = self.items[n]
        if status == "Disabled":
            self.items[n][-1] = "Enabled"
        else:
            self.items[n][-1] = "Disabled"
        self.parent.RefreshField(self.parent.ceChooser)

    def GetItems(self):
        ret = {}
        for section, opt, status in self.items:
            if section not in ret:
                ret[section] = {}
            ret[section][opt] = True if status == "Enabled" else False
        return ret

class ConfigFeatures(ida_kernwin.Form):
    form_template = """HexRaysPyTools features config
Double click for switch feature.
Need restart Ida Pro for settings applying!

<Features: {ceChooser}>
"""

    def __init__(self, config):
        self.config = config
        self.eChooser = ConfigFeaturesChooser(self.config, self)

        super(ConfigFeatures, self).__init__(self.form_template, {"ceChooser": ida_kernwin.Form.EmbeddedChooserControl(self.eChooser)})

    def Do(self):
        self.Compile()
        ok = self.Execute()
        logger.debug("self.Execute = ", ok)
        if ok == 1:
            self.config.update(self.eChooser.GetItems())


CONFIG_FILE_PATH = os.path.join(ida_diskio.idadir(""),"cfg", "HexRaysPyTools.cfg")
CONFIG_DIRECTORY = os.path.join(ida_diskio.idadir(""),"cfg")

try:
    f = open(CONFIG_FILE_PATH, "ab")
    f.close()
except:
    logger.error("Cannot open config file.")
    CONFIG_FILE_PATH = os.path.join(ida_diskio.get_user_idadir(), "cfg", "HexRaysPyTools.cfg")
    CONFIG_DIRECTORY = os.path.join(ida_diskio.get_user_idadir(), 'cfg')
    if not os.path.exists(os.path.join(ida_diskio.get_user_idadir(), "cfg")):
        os.makedirs(os.path.join(ida_diskio.get_user_idadir(), "cfg"))
    f = open(CONFIG_FILE_PATH, "ab")
    f.close()

DEBUG_MESSAGE_LEVEL = logging.INFO
# Whether propagate names (Propagate name feature) through all names or only defaults like v11, a3, this, field_4
PROPAGATE_THROUGH_ALL_NAMES = False
# Store Xref information in database. I don't know how much size it consumes yet
STORE_XREFS = True
# There're some types that can be pointers to structures like int, PVOID etc and by default plugin scans only them
# Full list can be found in `Const.LEGAL_TYPES`.
# But if set this option to True than variable of every type could be possible to scan
SCAN_ANY_TYPE = False

TEMPLATED_TYPES_FILE = os.path.join(
                os.path.dirname(__file__), 'types', 'templated_types.toml')



def add_default_settings(config):
    updated = False
    if not config.has_option("DEFAULT", "DEBUG_MESSAGE_LEVEL"):
        config.set(None, 'DEBUG_MESSAGE_LEVEL', str(DEBUG_MESSAGE_LEVEL))
        updated = True
    if not config.has_option("DEFAULT", "PROPAGATE_THROUGH_ALL_NAMES"):
        config.set(None, 'PROPAGATE_THROUGH_ALL_NAMES', str(PROPAGATE_THROUGH_ALL_NAMES))
        updated = True
    if not config.has_option("DEFAULT", "STORE_XREFS"):
        config.set(None, 'STORE_XREFS', str(STORE_XREFS))
        updated = True
    if not config.has_option("DEFAULT", "SCAN_ANY_TYPE"):
        config.set(None, 'SCAN_ANY_TYPE', str(SCAN_ANY_TYPE))
        updated = True
    if not config.has_option("DEFAULT", "TEMPLATED_TYPES_FILE"):
        config.set(None, 'TEMPLATED_TYPES_FILE', str(TEMPLATED_TYPES_FILE))
        updated = True

    if updated:
        try:
            if not os.path.exists(CONFIG_DIRECTORY):
                os.makedirs(CONFIG_DIRECTORY)
            with open(CONFIG_FILE_PATH, "w") as f:
                config.write(f)
        except IOError:
            logger.error("[ERROR] Failed to write or update config file at {}. Default settings will be used instead.\n" \
                  "Consider running IDA Pro under administrator once".format(CONFIG_FILE_PATH))
            ida_kernwin.error("[ERROR] Failed to write or update config file at {}. Default settings will be used instead.\n" \
                  "Consider running IDA Pro under administrator once".format(CONFIG_FILE_PATH))


def load_settings():
    global                           \
        DEBUG_MESSAGE_LEVEL,         \
        PROPAGATE_THROUGH_ALL_NAMES, \
        STORE_XREFS,                 \
        SCAN_ANY_TYPE,               \
        TEMPLATED_TYPES_FILE, \
        hex_pytools_config

    config = configparser.ConfigParser()
    config.optionxform = str
    if os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)

    add_default_settings(config)

    DEBUG_MESSAGE_LEVEL = config.getint("DEFAULT", 'DEBUG_MESSAGE_LEVEL')
    PROPAGATE_THROUGH_ALL_NAMES = config.getboolean("DEFAULT", 'PROPAGATE_THROUGH_ALL_NAMES')
    STORE_XREFS = config.getboolean("DEFAULT", 'STORE_XREFS')
    SCAN_ANY_TYPE = config.getboolean("DEFAULT", 'SCAN_ANY_TYPE')
    TEMPLATED_TYPES_FILE = config.get("DEFAULT", 'TEMPLATED_TYPES_FILE')


class Config(object):

    FeaturesListDef = { "Create struct":{"SimpleCreateStruct":True},
                        "Main plugins UI forms":{"ShowGraph":True, "ShowStructureBuilder":True},
                        "Function signature modifiers":{"ConvertToUsercall":True, "AddRemoveReturn":True,"RemoveArgument":True},
                        "Guess allocation":{"GuessAllocation":True},
                        "Member double click":{"MemberDoubleClick":True, "JumpByFieldName":True, "JumpByComment":False, "JumpByNetnodeVT":True},
                        "Negative offsets":{"SelectContainingStructure":True},
                        "New field creation":{"CreateNewField":True},
                        "Recasts":{"RecastItemLeft":True,"RecastItemRight":True,"RecastStructMember":True},
                        "Renames":{"RenameOther":True,"RenameInside":True,"RenameOutside":True,"RenameUsingAssert":True,"PropagateName":True,"TakeTypeAsName":True, "RenameMemberFromFunctionName":False},
                        "Scanners":{"ShallowScanVariable":True,"DeepScanVariable":True,"RecognizeShape":True,"DeepScanReturn":True,"DeepScanFunctions":True},
                        "Struct xref collector":{"StructXrefCollector":True},
                        "Struct xref representation":{"FindFieldXrefs":False},
                        "Structs by size":{"GetStructureBySize":True},
                        "Swap if":{"SilentIfSwapper":True, "SwapThenElse":True},
                        "Virtual table creation":{"CreateVtable":True,"DecompileCreateVtable":True,"DisassembleCreateVtable":True},
                        "Virtual tables netnode":{"BoundVtable":True},
                       }

    def __init__(self):
        # global hex_pytools_config
        self.section = "HexRaysPyTools features"
        self.file_path = CONFIG_FILE_PATH
        self.reader = configparser.ConfigParser()
        self.reader.optionxform = str
        # self.config_dict = {}
        # hex_pytools_config = self
        # try:
        #     f = open(self.file_path, "ab")
        #     f.close()
        # except:
        #     logger.error("Cannot open config file.")
        #     self.file_path = os.path.join(os.environ["APPDATA"],"IDA Pro","cfg", "HexRaysPyTools.cfg")
        #     if not os.path.exists(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg")):
        #         os.makedirs(os.path.join(os.environ["APPDATA"], "IDA Pro", "cfg"))
        #     f = open(self.file_path, "ab")
        #     f.close()

        f = open(self.file_path, "r")
        self.reader.read_file(f)
        f.close()
        fRewrite = False
        for section in Config.FeaturesListDef:
            if not self.reader.has_section(section):
                self.reader.add_section(section)
                fRewrite = True
                for opt in Config.FeaturesListDef[section]:
                    self.reader.set(section,opt,str(Config.FeaturesListDef[section][opt]))
            else:
                for opt in Config.FeaturesListDef[section]:
                    if not self.reader.has_option(section,opt):
                        self.reader.set(section,opt,str(Config.FeaturesListDef[section][opt]))
                        fRewrite = True
        if fRewrite:
            self.write_config()

    def update(self, feature_list, fWrite=True):
        for section in feature_list:
            if not self.reader.has_section(section):
                self.reader.add_section(section)
            for opt in feature_list[section]:
                self.reader.set(section,opt,str(feature_list[section][opt]))
        if fWrite:
            self.write_config()


    def get_opt(self, section, option):
        return self.reader.getboolean(section,option)

    def write_config(self):
        f = open(self.file_path, "w")
        self.reader.write(f)
        f.close()

    def modify(self):
        f = ConfigFeatures(self)
        f.Do()
        f.Free()
