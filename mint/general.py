MINT_ENABLED_MODIFY_MODE = False
MINT_ENABLED_REPLAY_MODE = False
MINT_ENABLED_GENERATED_MODE = False

MINT_ENABLED_CHECK_SESSION = False

MINT_PCAP_INPUT_FILES_PATH = []
MINT_PCAP_OUTPUT_FILES_PATH = []

MINT_SMAC_REPLACE_LIST = {}
MINT_DMAC_REPLACE_LIST = {}

MINT_ENABLED_RAND_SOUI = False
MINT_RAND_SOUI_TARGET_MAC = None
MINT_ENABLED_RAND_DOUI = False
MINT_RAND_DOUI_TARGET_MAC = None

MINT_ENABLED_RAND_SOUI_SIP_SYNC = False
MINT_RAND_SOUI_SIP_SYNC = None
MINT_ENABLED_RAND_DOUI_DIP_SYNC = False
MINT_RAND_DOUI_DIP_SYNC = None

MINT_RAND_GENERATE_COUNT = 0

MINT_SIP_REPLACE_LIST = {}
MINT_DIP_REPLACE_LIST = {}

MINT_OUI_DICT = {}

MINT_SPECIFIED_INTERFACE = None
MINT_SAVE_TO_PCAPNG_FILE = False

MINT_DISABLE_CALC_IP_CHECKSUM = False

MINT_PARAM_OPT = None
MINT_PARAM_DESC = None
MINT_PARAM_FUNC = None

MINT_SLIENT_MODE = False

MINT_EXPORT_TO_REPORT = False

MINT_DEFINE_OUT_FILEPATH = './resources/oui.txt'


class PacketModifyReport:
    def __init__(self):
        self.filepath = ""
        self.modified_filepath = ""

        self._generated_idx = 0

        self.packet_cnt = 0
        self.modified_smac = 0
        self.modified_dmac = 0
        self.modified_sip = 0
        self.modified_dip = 0

        self.origin_predict_dmac = None
        self.origin_predict_smac = None

        self.modified_predict_dmac = None
        self.modified_predict_smac = None
    
        self.origin_predict_dip = None
        self.origin_predict_sip = None

        self.modified_predict_dip = None
        self.modified_predict_sip = None

        self.origin_packet_list = []
        self.modified_packet_list = []
    
    def apply_result(self):
        if not self.origin_predict_dmac:
            self.origin_predict_dmac = "No Selected"

        if not self.origin_predict_smac:
            self.origin_predict_smac = "No Selected"

        if not self.origin_predict_dip:
            self.origin_predict_dip = "No Selected"

        if not self.origin_predict_sip:
            self.origin_predict_sip = "No Selected"

        if not self.modified_predict_dmac:
            self.modified_predict_dmac = "-"

        if not self.modified_predict_smac:
            self.modified_predict_smac = "-"

        if not self.modified_predict_sip:
            self.modified_predict_sip = "-"

        if not self.modified_predict_dip:
            self.modified_predict_dip = "-"


def load_oui_info(filepath = None):
    if filepath is None:
        filepath = MINT_DEFINE_OUT_FILEPATH

    try:
        oui_file = open(filepath, 'r')
        for line in oui_file:
            if "(hex)" in line:
                split_str = line.split("(hex)")
                if len(split_str) >= 2:
                    mac_hexstring = split_str[0].strip().replace("-", ":")
                    mac_hexstring += ":00:00:00"
                    oui_name = split_str[1].strip()
                    MINT_OUI_DICT[mac_hexstring] = oui_name
        oui_file.close()
        return MINT_OUI_DICT
    except FileNotFoundError:
        print("!== OUI file not found!! {}".format(filepath))
        return None