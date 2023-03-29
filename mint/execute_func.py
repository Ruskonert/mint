from scapy.all import *

import mint.general as GLOBAL
import sys
import os

def execute_replay(packet_info):
    if packet_info is None:
        pass
    return


def execute_generate():
    pass

def execute_make_pkt():
    if len(GLOBAL.MINT_PCAP_INPUT_FILES_PATH) == 0:
        print("!== Input file is empty!")
        sys.exit(-1)

    entire_packet_data = []

    for filepath in GLOBAL.MINT_PCAP_INPUT_FILES_PATH:
        packets = None
        # load the PCAP file
        try:
            packets = rdpcap(filepath)
        except:
            print("?== filepath: {}, it is not PCAP file or exist".format(filepath))
            continue

        for packet in packets:
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                for target_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
                    if src_mac == target_mac:
                        packet[Ether].src = GLOBAL.MINT_SMAC_REPLACE_LIST[target_mac]
                        break
                
                # if session check is enabled
                if GLOBAL.MINT_ENABLED_CHECK_SESSION:
                    for target_mac in GLOBAL.MINT_DMAC_REPLACE_LIST.keys():
                        if src_mac == target_mac:
                            packet[Ether].src = GLOBAL.MINT_DMAC_REPLACE_LIST[target_mac]
                            break

                dst_mac = packet[Ether].dst
                for target_mac in GLOBAL.MINT_DMAC_REPLACE_LIST.keys():
                    if dst_mac == target_mac:
                        packet[Ether].dst = GLOBAL.MINT_DMAC_REPLACE_LIST[target_mac]
                        break
                    
                # if session check is enabled
                if GLOBAL.MINT_ENABLED_CHECK_SESSION:
                    for target_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
                        if dst_mac == target_mac:
                            packet[Ether].dst = GLOBAL.MINT_SMAC_REPLACE_LIST[target_mac]
                            break


        # it is only the one file
        if len(GLOBAL.MINT_PCAP_INPUT_FILES_PATH) == 1:
            final_filename = None
            output_path = GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH[0]    

            if os.path.isdir(output_path):
                # make the dir if not exist
                os.makedirs(output_path, exist_ok=True)
                final_filename = output_path + "/" + filepath
            else:
                try:
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                except FileNotFoundError:
                    f = open(output_path, "a")
                    f.write(">")
                    f.close()
                final_filename = output_path

            if GLOBAL.MINT_SAVE_TO_PCAPNG_FILE:
                wrpcapng(final_filename, packets)
                print("*== Completed & save the modified with PCAPNG! ... [{}]".format(final_filename))
            else:
                wrpcap(final_filename, packets)
                print("*== Completed & save the modified PCAP! ... [{}]".format(final_filename))

        # more than one file...
        else:
            final_filename = None
            output_path = GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH[0]    

            if os.path.isdir(output_path):
                # make the dir if not exist
                os.makedirs(output_path, exist_ok=True)
                final_filename = output_path + "/" + filepath
            else:
                print("!== output path should be directory format, not filename when use the multiple input file!")
                sys.exit(-1)

            if GLOBAL.MINT_SAVE_TO_PCAPNG_FILE:
                wrpcapng(final_filename, packets)
                print("*== Completed & save the modified with PCAPNG! ... [{}]".format(final_filename))
            else:
                wrpcap(final_filename, packets)
                print("*== Completed & save the modified PCAP! ... [{}]".format(final_filename))

        entire_packet_data.append((filepath, packets))

    return entire_packet_data