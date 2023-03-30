import glob
import socket
import sys
import os

import mint.general as GLOBAL

def config_execute_opt():
    opt = []
    desc = []
    func = []

    opt.append(("h", "help"))
    desc.append("Output the guide")
    func.append(_dissect_help)

    opt.append(("m:", "mode="))
    desc.append("Set the execute mode [1: modify(default), 2: replay, 3: make&replay, 4: generate packet (rule-based)]")
    func.append(_dissect_mode)

    opt.append(("o:", "output="))
    desc.append("Output modified PCAP file to specific path (modify-mode only)")
    func.append(_dissect_output)

    opt.append((None, "pcapng-enabled"))
    desc.append("Save to the PCAPNG format when save the file (modify-mode only)")
    func.append(_dissect_use_pcapng)

    opt.append((None, "check-session"))
    desc.append("When changing the MAC or IP, change them together if the session is exchanging (modify-mode only)")
    func.append(_dissect_use_check_session)

    opt.append(("e:", "eth="))
    desc.append("Select the interface name for sending modified packet (replay-mode only)")
    func.append(_dissect_eth)

    opt.append((None, "smac="))
    desc.append("Change the specified source MAC [example: 00:11:22:33:44:55/aa:bb:cc:dd:ee:ff,00:19:38:2a:69:44/aa:bb:cc:dd:ee:ff]")
    func.append(_dissect_smac)

    opt.append((None, "dmac="))
    desc.append("Change the specified destination MAC [example: 00:11:22:33:44:55/aa:bb:cc:dd:ee:ff,00:19:38:2a:69:44/aa:bb:cc:dd:ee:ff]")
    func.append(_dissect_dmac)

    opt.append((None, "sip="))
    desc.append("Change the specified source IP [example: 192.168.0.1/192.168.0.2]")
    func.append(_dissect_sip)

    opt.append((None, "dip="))
    desc.append("Change the specified destination IP [example: 192.168.0.1/192.168.0.2]")
    func.append(_dissect_dip)

    opt.append((None, "random-soui="))
    desc.append("Change the source MAC to random with OUI")
    func.append(_dissect_rand_soui)

    opt.append((None, "random-doui="))
    desc.append("Change the destination MAC to random with OUI")
    func.append(_dissect_rand_doui)

    opt.append((None, "disable-ip-checksum"))
    desc.append("Disable re-calculate a checksum value of the IP Layer when changed")
    func.append(_dissect_disable_ip_checksum)

    opt.append((None, "generate-count="))
    desc.append("Define the generate count when modified the PCAP with OUI (Need to enable --random-doui or soui)")
    func.append(_dissect_generate_count)

    opt.append((None, "sync-sip="))
    desc.append("Sync the specific Source IP when SMAC address is changed with OUI")
    func.append(_dissect_sync_sip)

    opt.append((None, "sync-dip="))
    desc.append("Sync the specific Destination IP when DMAC address is changed with OUI")
    func.append(_dissect_sync_dip)

    opt.append((None, "slient"))
    desc.append("Disable the system output")
    func.append(_dissect_slient)

    opt.append((None, "export"))
    desc.append("Export to CSV file of report")
    func.append(_dissect_export)

    # insert the input param
    opt.append((None, None))
    desc.append("Input the file or directory path [Example: /path/to/file.pcap or /path/to ...]")
    func.append(_dissect_input)

    GLOBAL.MINT_PARAM_OPT = opt
    GLOBAL.MINT_PARAM_DESC = desc
    GLOBAL.MINT_PARAM_FUNC = func
    return [opt, desc, func]


def _dissect_help(_):
    execute_help(GLOBAL.MINT_PARAM_OPT, GLOBAL.MINT_PARAM_DESC)
    sys.exit(-1)


def _dissect_mode(value):
    if int(value) & 0x01:
        GLOBAL.MINT_ENABLED_MODIFY_MODE = True
    if int(value) & 0x02:
        GLOBAL.MINT_ENABLED_REPLAY_MODE = True
    if int(value) & 0x04:
        GLOBAL.MINT_ENABLED_GENERATED_MODE = True
    
    if not (GLOBAL.MINT_ENABLED_MODIFY_MODE or GLOBAL.MINT_ENABLED_REPLAY_MODE or GLOBAL.MINT_ENABLED_GENERATED_MODE):
        GLOBAL.MINT_ENABLED_MODIFY_MODE = True
        print("?== Unknown Mode, Use default mode (Modify)")
    
    return True



def _dissect_smac(value):
    GLOBAL.MINT_SMAC_REPLACE_LIST = _dissect_mac(value)
    if GLOBAL.MINT_SMAC_REPLACE_LIST == None:
        return False
    return True



def _dissect_dmac(value):
    GLOBAL.MINT_DMAC_REPLACE_LIST = _dissect_mac(value)
    if GLOBAL.MINT_DMAC_REPLACE_LIST == None:
        return False
    return True



def _dissect_use_pcapng(_):
    GLOBAL.MINT_SAVE_TO_PCAPNG_FILE = True
    return True



def _dissect_use_check_session(_):
    GLOBAL.MINT_ENABLED_CHECK_SESSION = True
    return True



def _dissect_disable_ip_checksum(_):
    GLOBAL.MINT_DISABLE_CALC_IP_CHECKSUM = True
    return True



def _dissect_slient(_):
    GLOBAL.MINT_SLIENT_MODE = True
    return True



def _dissect_export(_):
    GLOBAL.MINT_EXPORT_TO_REPORT = True
    return True



def _dissect_rand_soui(value):
    if "," in value:
        mac_value = value.split(',')
        macs = []
        if len(mac_value) >= 1:
            for mac in mac_value:
                mac_addr = _get_mac_address(mac)
                if mac_addr is None:
                    print("?== invaild random OUI mac -> {}, skipping".format(mac))
                    continue
                macs.append(mac_addr)
            GLOBAL.MINT_ENABLED_RAND_SOUI = True
            GLOBAL.MINT_RAND_SOUI_TARGET_MAC = macs
        else:
            print("!== invaild random OUI mac!")
        return True
    else:
        mac_addr = _get_mac_address(value)
        if mac_addr is None:
            return False
        GLOBAL.MINT_ENABLED_RAND_SOUI = True
        GLOBAL.MINT_RAND_SOUI_TARGET_MAC = [mac_addr]
        return True



def _dissect_rand_doui(value):
    if "," in value:
        mac_value = value.split(',')
        macs = []
        if len(mac_value) >= 1:
            for mac in mac_value:
                mac_addr = _get_mac_address(mac)
                if mac_addr is None:
                    print("?== invaild random OUI mac -> {}, skipping".format(mac))
                    continue
                macs.append(mac_addr)
            GLOBAL.MINT_ENABLED_RAND_DOUI = True
            GLOBAL.MINT_RAND_DOUI_TARGET_MAC = macs
        else:
            print("!== invaild random OUI mac!")
        return True
    else:
        mac_addr = _get_mac_address(value)
        if mac_addr is None:
            return False
        GLOBAL.MINT_ENABLED_RAND_DOUI = True
        GLOBAL.MINT_RAND_DOUI_TARGET_MAC = [mac_addr]
        return True



def _dissect_sip(value):
    GLOBAL.MINT_SIP_REPLACE_LIST = _dissect_ip_dict(value)
    if GLOBAL.MINT_SIP_REPLACE_LIST == None:
        return False
    return True
    


def _dissect_dip(value):
    GLOBAL.MINT_DIP_REPLACE_LIST = _dissect_ip_dict(value)
    if GLOBAL.MINT_DIP_REPLACE_LIST == None:
        return False
    return True



def _dissect_generate_count(value):
    if int(value) < 0 or int(value) >= 254:
        print("!-- Invaild generate count! use default ==> 1")
        GLOBAL.MINT_RAND_GENERATE_COUNT = 1
    else:
        GLOBAL.MINT_RAND_GENERATE_COUNT = int(value)
    return True



def _dissect_ip_dict(value):
    ipv4_dict = {}
    ipv4_addr_info = value.split(",")

    if len(ipv4_addr_info) <= 1:
        splited_ip = value.split("/")

        ipv4_value = _get_ipv4_addr(splited_ip[0])
        if ipv4_value is None:
            print("!== Invaild ipv4 address ==> {}".format(splited_ip[0]))
            return None

        ipv4_value2 = _get_ipv4_addr(splited_ip[1])
        if ipv4_value2 is None:
            print("!== Invaild ipv4 address ==> {}".format(splited_ip[1]))
            return None

        ipv4_dict[ipv4_value] = ipv4_value2

    else:
        for ipv4_addr_value in splited_ip:
            splited_ip = ipv4_addr_value.split("/")

            ipv4_value = _get_ipv4_addr(splited_ip[0])
            if ipv4_value is None:
                print("?== Invaild ipv4 address ==> {}, skipping".format(splited_ip[0]))
                continue

            ipv4_value2 = _get_ipv4_addr(splited_ip[1])
            if ipv4_value2 is None:
                print("?== Invaild ipv4 address ==> {}, skipping".format(splited_ip[0]))
                continue

            ipv4_dict[ipv4_value] = ipv4_value2

    return ipv4_dict



def _get_ipv4_addr(ipv4_string : str):
    ip_classes = ipv4_string.split(".")
    if len(ip_classes) == 4:
        for ipc in ip_classes:
            if int(ipc) >= 0 and int(ipc) <= 255:
                continue
            else:
                return None
        return ipv4_string
    else:
        return None



def _dissect_sync_sip(value):
    GLOBAL.MINT_RAND_DOUI_SIP_SYNC = _dissect_ip_list(value)
    if GLOBAL.MINT_RAND_DOUI_SIP_SYNC == None:
        return False
    GLOBAL.MINT_ENABLED_RAND_SOUI_SIP_SYNC = True
    return True



def _dissect_sync_dip(value):
    GLOBAL.MINT_RAND_DOUI_DIP_SYNC = _dissect_ip_list(value)
    if GLOBAL.MINT_RAND_DOUI_DIP_SYNC == None:
        return False
    GLOBAL.MINT_ENABLED_RAND_DOUI_DIP_SYNC = True
    return True



def _dissect_ip_list(value):
    li = []
    ipv4_addr_info = value.split(",")
    
    if len(ipv4_addr_info) <= 1:
        ipv4_value = _get_ipv4_addr(ipv4_addr_info[0])
        if ipv4_value is None:
            print("!== Invaild IPv4 address ==> {}".format(ipv4_value))
            return None
        li.append(ipv4_value)
    else:
        for ipv4_val in ipv4_addr_info:
            ipv4_value = _get_ipv4_addr(ipv4_val)
            if ipv4_value is None:
                print("?== Invaild IPv4 address ==> {}, skipping".format(ipv4_value))
                continue
            li.append(ipv4_value)
    return li
        


def _dissect_mac(value):
    mac_dict = {}
    mac_addr_info = value.split(",")

    if len(mac_addr_info) <= 1:
        splited_mac = value.split("/")

        mac = _get_mac_address(splited_mac[0])
        if mac is None:
            print("!== Invaild mac address ==> {}".format(splited_mac[0]))
            return None

        mac2 = _get_mac_address(splited_mac[1])
        if mac2 is None:
            print("!== Invaild mac address ==> {}".format(splited_mac[1]))
            return None
        mac_dict[mac] = mac2
    else:
        for mac_addr_value in mac_addr_info:
            splited_mac = mac_addr_value.split("/")
            mac = _get_mac_address(splited_mac[0])
            if mac is None:
                print("?== Invaild mac address ==> {}, skipping".format(splited_mac[0]))
                continue
            mac2 = _get_mac_address(splited_mac[1])
            if mac2 is None:
                print("?== Invaild mac address ==> {}, skipping".format(splited_mac[1]))
                continue
            mac_dict[mac] = mac2
    return mac_dict



def _get_mac_address(value):
    if isinstance(value, str):
        if len(value) == 12 and (not ":" in value):
            return "{}:{}:{}:{}:{}:{}".format(value[:2], value[2:4], value[4:6], \
                value[6:8], value[8:10], value[10:12])
        elif len(value) == 17 and (":" in value):
            return value
        else:
            return None
    else:
        return None



def _dissect_input(value):
    def _dissect_child_path(v):
        if os.path.isdir(v):
            for filename in glob.glob(v + "/" + "*.cap"):
                GLOBAL.MINT_PCAP_INPUT_FILES_PATH.append(filename)

            for filename in glob.glob(v + "/" + "*.pcap"):
                GLOBAL.MINT_PCAP_INPUT_FILES_PATH.append(filename)
            
            for filename in glob.glob(v + "/" + "*.pcapng"):
                GLOBAL.MINT_PCAP_INPUT_FILES_PATH.append(filename)

            for filename in glob.glob(v + "/" + "*.txt"):
                GLOBAL.MINT_PCAP_INPUT_FILES_PATH.append(filename)
        else:
            GLOBAL.MINT_PCAP_INPUT_FILES_PATH.append(v)

    if isinstance(value, list):
        for val in value:
            _dissect_child_path(val)
    else:
        _dissect_child_path(value)
    
    return True



def _dissect_output(value):
    try:
        # let that is directory
        os.makedirs(os.path.dirname(value), exist_ok=True)
        GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH.append(value)
    except FileNotFoundError:
        # let that is file
        f = open(value, "w")
        f.write("")
        f.close()
        GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH.append(value)
    return True



def _dissect_eth(value):
    for _, if_name in socket.if_nameindex():
        if if_name.find(value) != -1:
            GLOBAL.MINT_SPECIFIED_INTERFACE = if_name
            break
    if GLOBAL.MINT_SPECIFIED_INTERFACE is None:
        print("!== '{}' is undefined network interface your system".format(value))
        return False
    return True



def execute_help(opts, desc):
    print("""
        MINT (MAC, IP is Now you wanTed)

        M)mm mmm I)iiiiN)n   nnT)tttttt 
        M)  mm  mm  I)  N)nn  nn   T)    
        M)  mm  mm  I)  N) nn nn   T)    
        M)  mm  mm  I)  N)  nnnn   T)    
        M)      mm  I)  N)   nnn   T)    
        M)      mmI)iiiiN)    nn   T) 
    """)

    print("Usuge: {}".format(sys.argv[0]), end='')

    default_param = "Path or specific file ..."
    dist_string_list = []

    for shortcut, long_param in opts:
        if shortcut is not None:
            dist_string = "-" + shortcut.replace(":", "")

            dist_string_list.append([dist_string, "--" + long_param.replace("=", "")])
        else:
            if long_param is None:
                # default param
                dist_string_list.append([None, None])
            else:
                dist_string_list.append([None, "--" + long_param.replace("=", "")])

    # output summary param info
    for dist in dist_string_list:
        output_args = "["
        if dist[0] is not None:
            output_args += dist[0]
            output_args += "|"
            output_args += dist[1]
            output_args += "]"
        else:
            # it is default param
            if dist[1] is None:
                output_args += "{}]".format(default_param)
            else:
                output_args += dist[1]
                output_args += "]"
    
        print(" {}".format(output_args), end="")
    print("\n")

    # output param description
    for idx, dist in enumerate(dist_string_list):
        output_args = "["
        if dist[0] is not None:
            output_args += dist[0]
            output_args += " or "
            output_args += dist[1]
            output_args += "]"
        else:
            if dist[1] is None:
                output_args += default_param + ']'
            else:
                output_args += dist[1]
                output_args += "]"
        print("{}".format(output_args), end="")
        print(" : {}".format(desc[idx]))
    print()