#!/usr/bin/env python

"""
 M)mm mmm I)iiiiN)n   nnT)tttttt 
M)  mm  mm  I)  N)nn  nn   T)    
M)  mm  mm  I)  N) nn nn   T)    
M)  mm  mm  I)  N)  nnnn   T)    
M)      mm  I)  N)   nnn   T)    
M)      mmI)iiiiN)    nn   T) 


The MIT License (MIT)

MINT (MAC, IP is Now you wanTed)

Copyright (c) 2023 ruskonert@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the 
Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE 
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
"""
import os
import getopt
import sys
import pandas as pd

import mint.general as GLOBAL

from mint.param import config_execute_opt, execute_help
from mint.execute_func import execute_make_pkt, execute_generate, execute_replay
from mint.exception import MintExecuteParamError
from mint.general import load_oui_info, PacketModifyReport
from mint.utils import mint_print

def main():
    opt_rslt = config_execute_opt()
    if len(opt_rslt) == 3:
        _check_arguments(opt_rslt[0], opt_rslt[1], opt_rslt[2])
    else:
        raise MintExecuteParamError("Your typed option argments that was not support!", '')
    
    for idx, args in enumerate(sys.argv):
        mint_print("*== ARGS[{}] = {}".format(idx, args))

    mint_print("\n*== Check the execute arguments ...")

    """
    Check the execute mode
    """
    if GLOBAL.MINT_ENABLED_MODIFY_MODE:
        mint_print("      [*] Modify mode Enabled")

    if GLOBAL.MINT_ENABLED_REPLAY_MODE:
        mint_print("      [*] Replay mode Enabled")

    if GLOBAL.MINT_ENABLED_GENERATED_MODE:
        # does
        if GLOBAL.MINT_ENABLED_MODIFY_MODE:
            mint_print("      [!] Please select only one mode (Modify or Generated)")
            sys.exit(-1)

        mint_print("      [*] Generated mode Enabled")

    if not (GLOBAL.MINT_ENABLED_MODIFY_MODE or GLOBAL.MINT_ENABLED_REPLAY_MODE or GLOBAL.MINT_ENABLED_GENERATED_MODE):
        GLOBAL.MINT_ENABLED_MODIFY_MODE = True
        mint_print("      [!] Unknown Mode, Use default mode (Modify)")

    if GLOBAL.MINT_SAVE_TO_PCAPNG_FILE:
        mint_print("      [*] Enabled the PCAPNG Format")

    if len(GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH) == 0:
        # using default path
        GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH.append("output/")
        mint_print("      [!] Use the default output path")
        os.makedirs(GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH[0], exist_ok=True)

    if GLOBAL.MINT_ENABLED_MODIFY_MODE:
        if len(GLOBAL.MINT_SMAC_REPLACE_LIST) == 0 and len(GLOBAL.MINT_DMAC_REPLACE_LIST) == 0:
            mint_print("      [?] Enabled modify mode but nothing targetted")

    """
    Check the typed Source MAC
    """
    if len(GLOBAL.MINT_SMAC_REPLACE_LIST) > 0:
        mint_print("      [*] Loading the Source MAC Address ...")
        for origin_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
            mint_print("         - Target MAC [{} --> {}]".format(origin_mac, GLOBAL.MINT_SMAC_REPLACE_LIST[origin_mac]))

    """
    Check the typed Destination MAC
    """
    if len(GLOBAL.MINT_DMAC_REPLACE_LIST) > 0:
        mint_print("      [*] Loading the Destination MAC Address ...")
        for origin_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
            mint_print("         - Destination MAC [{} --> {}]".format(origin_mac, GLOBAL.MINT_SMAC_REPLACE_LIST[origin_mac]))

    if GLOBAL.MINT_ENABLED_CHECK_SESSION:
        mint_print("      [*] Session check mode Enabled")

    if GLOBAL.MINT_DISABLE_CALC_IP_CHECKSUM:
        mint_print("      [*] IP Checksum vaildation is Disabled")

    if GLOBAL.MINT_ENABLED_RAND_DOUI or GLOBAL.MINT_ENABLED_RAND_SOUI:
        mint_print("      [*] Random MAC with OUI is Enabled")

        if GLOBAL.MINT_ENABLED_RAND_DOUI:
            if len(GLOBAL.MINT_DMAC_REPLACE_LIST) > 0:
                mint_print("      [?] Random Destination MAC with OUI is Enabled, But You selected DMAC => ignored")
                GLOBAL.MINT_DMAC_REPLACE_LIST.clear()
        
        if GLOBAL.MINT_ENABLED_RAND_SOUI:
            if len(GLOBAL.MINT_SMAC_REPLACE_LIST) > 0:
                mint_print("      [?] Random Source MAC with OUI is Enabled, But You selected SMAC => ignored")
                GLOBAL.MINT_SMAC_REPLACE_LIST.clear()

        oui_dir = load_oui_info()
        if oui_dir is None:
            mint_print("      [!] Failed to OUI List! Please check the resource file: oui.txt")
            sys.exit(-1)
        mint_print("      [*] OUI list loaded was successfully: oui={}".format(len(oui_dir)))


    if GLOBAL.MINT_ENABLED_RAND_DOUI_DIP_SYNC or GLOBAL.MINT_ENABLED_RAND_SOUI_SIP_SYNC:
        mint_print("      [*] Sync IP when change to random MAC with OUI is Enabled")
        if len(GLOBAL.MINT_SIP_REPLACE_LIST) > 0:
            mint_print("      [?] Sync Source IP when modified to OUI is Enabled, But You selected SIP => ignored")
            GLOBAL.MINT_SIP_REPLACE_LIST.clear()
        
        if len(GLOBAL.MINT_DIP_REPLACE_LIST) > 0:
            mint_print("      [?] Sync Destination IP when modified to OUI is Enabled, But You selected DIP => ignored")
            GLOBAL.MINT_DIP_REPLACE_LIST.clear()

    if GLOBAL.MINT_RAND_GENERATE_COUNT > 0:
        if not (GLOBAL.MINT_ENABLED_RAND_SOUI or GLOBAL.MINT_ENABLED_RAND_DOUI):
            mint_print("      [!] Need to enable Random S/DOUI when use generate count!")
            sys.exit(-1)
    mint_print()
    
    packet_report : list[PacketModifyReport] = None

    # Execute the modify function
    if GLOBAL.MINT_ENABLED_MODIFY_MODE:
        mint_print("*== Execute the function: Modify the PCAP")
        packet_report = execute_make_pkt()

        # check the report
        str_check_session = "No"
        if GLOBAL.MINT_ENABLED_CHECK_SESSION:
            str_check_session = "Yes"

        if len(packet_report) > 0:
            for report in packet_report:
                report.apply_result()
                mint_print()
                mint_print("    ----- Filepath [%s] -----" % report.filepath)
                mint_print("        Packet(s): %d" % report.packet_cnt)
                mint_print("        Detected Source MAC: [%s]" % report.origin_predict_smac)
                mint_print("        Detected Destination MAC: [%s]" % report.origin_predict_dmac)
                mint_print("        Modifed Source MAC: [%s]" % report.modified_predict_smac)
                mint_print("        Modifed Destination MAC: [%s]" % report.modified_predict_dmac)
                mint_print()
                mint_print("        Detected Source IP: [%s]" % report.origin_predict_sip)
                mint_print("        Detected Destination IP: [%s]" % report.origin_predict_dip)
                mint_print("        Modifed Source IP: [%s]" % report.modified_predict_sip)
                mint_print("        Modifed Destination IP: [%s]" % report.modified_predict_dip)
                mint_print()
                mint_print("        Changed Source MAC: %d" % report.modified_smac)
                mint_print("        Changed Destination MAC: %d" % report.modified_dmac)
                mint_print("        Changed Source IP: %d" % report.modified_sip)
                mint_print("        Changed Destination IP: %d" % report.modified_dip)
                mint_print()
                mint_print("        Cross-checked (Session)? %s" % str_check_session)
                mint_print("        Modified file to: [%s]" % report.modified_filepath)
                mint_print("    " + "-" * len(report.filepath) + "-" * 23)
                mint_print()

            if GLOBAL.MINT_EXPORT_TO_REPORT:
                dummy = PacketModifyReport()
                field_values = dummy.__dict__
                del field_values['_generated_idx']
                del field_values["filepath"]
                del field_values["origin_packet_list"]
                del field_values["modified_packet_list"]

                col = field_values.keys()

                df = pd.DataFrame(columns=col)

                for report in packet_report:
                    v = report.__dict__
                    del v['_generated_idx']
                    del v["filepath"]
                    del v["origin_packet_list"]
                    del v["modified_packet_list"]
                    df.loc[-1] = v.values()
                    df.index = df.index + 1
                    df = df.sort_index()
                    
                df.to_csv("./report.csv")
                mint_print("*== Export to CSV file! [report.csv]")


    if GLOBAL.MINT_ENABLED_REPLAY_MODE:
        mint_print("*== Execute the function: Replay the PCAP")
        execute_replay(packet_info)

    if GLOBAL.MINT_ENABLED_GENERATED_MODE:
        mint_print("*== Execute the function: PCAP Generate")
        execute_generate()
    


def _check_arguments(opts, desc, instance_func):
    if len(sys.argv) <= 1:
        execute_help(opts, desc)
        sys.exit(-1)

    s_opt_string = ""
    dist_string_list = []
    opt_list = []

    # make opt string
    for shortcut, long_param in opts:
        if shortcut is not None:
            s_opt_string += shortcut
            dist_string = "-" + shortcut.replace(":", "")
            dist_string_list.append([dist_string, "--" + long_param.replace("=", "")])
            if long_param is not None:
                opt_list.append(long_param)
        else:
            if long_param is None:
                # it is default param, skipping
                continue
            opt_list.append(long_param)
            dist_string_list.append(["--" + long_param.replace("=", "")])

    success = False
    args = None
    try:
        opt, args = getopt.getopt(sys.argv[1:], s_opt_string, opt_list)
        for option, arg in opt:
            for func_idx, disg_list in enumerate(dist_string_list):
                if option in disg_list:
                    # call the param dissector 
                    success = instance_func[func_idx](arg)
                    if not success:
                        mint_print("!!! Failed to dissect the specific param")
                        mint_print("===> param: {}".format(disg_list))
                        sys.exit(-1)

    except getopt.GetoptError:
        raise MintExecuteParamError("Please check the argments")

    # call the dissect default dissector 
    success = instance_func[-1](args)
    if not success:
        execute_help(opts, desc)
        sys.exit(-1)



if __name__ == "__main__":
    main()