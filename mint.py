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
import mint.general as GLOBAL

from mint.param import config_execute_opt, execute_help
from mint.execute_func import execute_make_pkt, execute_generate, execute_replay
from mint.exception import MintExecuteParamError


def main():
    for idx, args in enumerate(sys.argv):
        print("*== ARGS[{}] = {}".format(idx, args))
    opt_rslt = config_execute_opt()
    if len(opt_rslt) == 3:
        _check_arguments(opt_rslt[0], opt_rslt[1], opt_rslt[2])
    else:
        raise MintExecuteParamError("Your typed option argments that was not support!", '')

    print("\n*== Check the execute arguments ...")

    """
    Check the execute mode
    """
    if GLOBAL.MINT_ENABLED_MODIFY_MODE:
        print("      [*] Modify mode Enabled")

    if GLOBAL.MINT_ENABLED_REPLAY_MODE:
        print("      [*] Replay mode Enabled")

    if GLOBAL.MINT_ENABLED_GENERATED_MODE:
        # does
        if GLOBAL.MINT_ENABLED_MODIFY_MODE:
            print("      [!] Please select only one mode (Modify or Generated)")
            sys.exit(-1)

        print("      [*] Generated mode Enabled")

    if not (GLOBAL.MINT_ENABLED_MODIFY_MODE or GLOBAL.MINT_ENABLED_REPLAY_MODE or GLOBAL.MINT_ENABLED_GENERATED_MODE):
        GLOBAL.MINT_ENABLED_MODIFY_MODE = True
        print("      [!] Unknown Mode, Use default mode (Modify)")

    if GLOBAL.MINT_SAVE_TO_PCAPNG_FILE:
        print("      [*] Enabled the PCAPNG Format")

    if len(GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH) == 0:
        # using default path
        GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH.append("output/")
        print("      [!] Use the default output path")
        os.makedirs(GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH[0], exist_ok=True)

    if GLOBAL.MINT_ENABLED_MODIFY_MODE:
        if len(GLOBAL.MINT_SMAC_REPLACE_LIST) == 0 and len(GLOBAL.MINT_DMAC_REPLACE_LIST) == 0:
            print("      [?] Enabled modify mode but nothing targetted")

    """
    Check the typed Source MAC
    """
    if len(GLOBAL.MINT_SMAC_REPLACE_LIST) > 0:
        print("      [*] Loading the Source MAC Address ...")
        for origin_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
            print("         - Target MAC [{} --> {}]".format(origin_mac, GLOBAL.MINT_SMAC_REPLACE_LIST[origin_mac]))

    """
    Check the typed Destination MAC
    """
    if len(GLOBAL.MINT_DMAC_REPLACE_LIST) > 0:
        print("      [*] Loading the Destination MAC Address ...")
        for origin_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
            print("         - Destination MAC [{} --> {}]".format(origin_mac, GLOBAL.MINT_SMAC_REPLACE_LIST[origin_mac]))


    if GLOBAL.MINT_ENABLED_CHECK_SESSION:
        print("      [*] Session check mode Enabled")


    print()
    
    packet_info = None
    if GLOBAL.MINT_ENABLED_MODIFY_MODE:
        print("*== Execute the function: Modify the PCAP")
        packet_info = execute_make_pkt()

    if GLOBAL.MINT_ENABLED_REPLAY_MODE:
        print("*== Execute the function: Replay the PCAP")
        execute_replay(packet_info)

    if GLOBAL.MINT_ENABLED_GENERATED_MODE:
        print("*== Execute the function: PCAP Generate")
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
                        print("!!! Failed to dissect the specific param")
                        print("===> param: {}".format(disg_list))
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