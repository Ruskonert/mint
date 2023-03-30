from scapy.all import *

import random
import mint.general as GLOBAL
import sys
import os
import copy

from mint.general import PacketModifyReport
from mint.utils import *

def execute_replay(packet_info):
    if packet_info is None:
        pass
    return



def execute_generate():
    pass



def execute_make_pkt() -> PacketModifyReport:
    if len(GLOBAL.MINT_PCAP_INPUT_FILES_PATH) == 0:
        mint_print("!== Input file is empty!")
        sys.exit(-1)

    pmr_list = []

    smac_list_len = len(GLOBAL.MINT_SMAC_REPLACE_LIST)
    dmac_list_len = len(GLOBAL.MINT_DMAC_REPLACE_LIST)
    mac_elements_exist = smac_list_len > 0 or dmac_list_len > 0

    sip_list_len = len(GLOBAL.MINT_SIP_REPLACE_LIST)
    dip_list_len = len(GLOBAL.MINT_DIP_REPLACE_LIST)
    ipv4_elements_exist = sip_list_len > 0 or dip_list_len > 0
    
    # Select OUI value
    oui_list = None
    if GLOBAL.MINT_ENABLED_RAND_SOUI or GLOBAL.MINT_ENABLED_RAND_DOUI:
        oui_list = random.sample(GLOBAL.MINT_OUI_DICT.keys(), len(GLOBAL.MINT_PCAP_INPUT_FILES_PATH))


    for filepath_idx, filepath in enumerate(GLOBAL.MINT_PCAP_INPUT_FILES_PATH):
        if GLOBAL.MINT_RAND_GENERATE_COUNT == 0:
            GLOBAL.MINT_RAND_GENERATE_COUNT = 1
    

        for i in range(0, GLOBAL.MINT_RAND_GENERATE_COUNT):
            pmr = PacketModifyReport()
            packets = None

            # load the PCAP file
            try:
                packets = rdpcap(filepath)
                pmr.origin_packet_list = copy.deepcopy(packets)
                pmr.filepath = filepath
                pmr._generated_idx = i + 1
                pmr.packet_cnt = len(pmr.origin_packet_list)
            except:
                mint_print("?== filepath: {}, it is not PCAP file or exist".format(filepath))
                continue
            packet_modify_mac_ip(packets, mac_elements_exist, ipv4_elements_exist, pmr, oui_list, filepath_idx, None, None)
            pmr.modified_packet_list = packets

            ### save process

            # it is only the one file.
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

                if GLOBAL.MINT_ENABLED_RAND_DOUI or GLOBAL.MINT_ENABLED_RAND_SOUI:
                    final_filename = remove_pcap_file_extension(final_filename)
                    final_filename += "_{}.pcap".format(i+1)

                if GLOBAL.MINT_SAVE_TO_PCAPNG_FILE:
                    wrpcapng(final_filename, packets)
                    mint_print("*== Completed & save the modified with PCAPNG! ... [{}]".format(final_filename))
                else:
                    wrpcap(final_filename, packets)
                    mint_print("*== Completed & save the modified PCAP! ... [{}]".format(final_filename))
                pmr.modified_filepath = final_filename

            # more than one file...
            # It needs to saperate directory path.
            else:
                final_filename = None
                output_path = GLOBAL.MINT_PCAP_OUTPUT_FILES_PATH[0]    

                if os.path.isdir(output_path):
                    # make the dir if not exist
                    os.makedirs(output_path, exist_ok=True)
                    final_filename = output_path + "/" + filepath
                else:
                    mint_print("!== output path should be directory format, not filename when use the multiple input file!")
                    sys.exit(-1)

                if GLOBAL.MINT_ENABLED_RAND_DOUI or GLOBAL.MINT_ENABLED_RAND_SOUI:
                    final_filename = remove_pcap_file_extension(final_filename)
                    final_filename += "_{}.pcap".format(i+1)

                if GLOBAL.MINT_SAVE_TO_PCAPNG_FILE:
                    wrpcapng(final_filename, packets)
                    mint_print("*== Completed & save the modified with PCAPNG! ... [{}]".format(final_filename))
                else:
                    wrpcap(final_filename, packets)
                    mint_print("*== Completed & save the modified PCAP! ... [{}]".format(final_filename))
                pmr.modified_filepath = final_filename
            # report the result
            pmr_list.append(pmr)
    
    return pmr_list



def packet_modify_rand_oui_mac(packet : Packet, pmr : PacketModifyReport, oui_list, oui_idx, to_addr_mac):
    sync_mac = None
    if GLOBAL.MINT_ENABLED_RAND_SOUI or GLOBAL.MINT_ENABLED_RAND_DOUI:
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

            if GLOBAL.MINT_ENABLED_RAND_SOUI:
                for source_target_mac in GLOBAL.MINT_RAND_SOUI_TARGET_MAC:
                    if src_mac == source_target_mac:
                        if pmr.origin_predict_smac is None:
                            pmr.origin_predict_smac = source_target_mac

                        if sync_mac is None:
                            if to_addr_mac is not None:
                                sync_mac = to_addr_mac
                            else:
                                sync_mac = increase_mac_addr(oui_list[oui_idx], pmr._generated_idx)
                        packet[Ether].src = sync_mac
                        pmr.modified_smac += 1
                        if pmr.modified_predict_smac is None:
                            pmr.modified_predict_smac = sync_mac
                        break
                    elif GLOBAL.MINT_ENABLED_CHECK_SESSION:
                        if dst_mac == source_target_mac:
                            if sync_mac is None:
                                if to_addr_mac is not None:
                                    sync_mac = to_addr_mac
                                else:
                                    sync_mac = increase_mac_addr(oui_list[oui_idx], pmr._generated_idx)
                            packet[Ether].dst = sync_mac
                            pmr.modified_dmac += 1
                            break

            if GLOBAL.MINT_ENABLED_RAND_DOUI:
                for dest_target_mac in GLOBAL.MINT_RAND_DOUI_TARGET_MAC:
                    if dst_mac == dest_target_mac:
                        if pmr.origin_predict_dmac is None:
                            pmr.origin_predict_dmac = dest_target_mac

                        if sync_mac is None:
                            if to_addr_mac is not None:
                                sync_mac = to_addr_mac
                            else:
                                sync_mac = increase_mac_addr(oui_list[oui_idx], pmr._generated_idx)
                        packet[Ether].dst = sync_mac
                        pmr.modified_dmac += 1
                        if pmr.modified_predict_dmac is None:
                            pmr.modified_predict_dmac = sync_mac
                        break

                    elif GLOBAL.MINT_ENABLED_CHECK_SESSION:
                        if src_mac == dest_target_mac:
                            if sync_mac is None:
                                if to_addr_mac is not None:
                                    sync_mac = to_addr_mac
                                else:
                                    sync_mac = increase_mac_addr(oui_list[oui_idx], pmr._generated_idx)
                            packet[Ether].src = sync_mac
                            pmr.modified_smac += 1
                            break


def packet_modify_mac(packet : Packet, pmr : PacketModifyReport):
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        for target_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
            if src_mac == target_mac:
                if pmr.origin_predict_smac is None:
                    pmr.origin_predict_smac = GLOBAL.target_mac
                packet[Ether].src = GLOBAL.MINT_SMAC_REPLACE_LIST[target_mac]
                if pmr.modified_predict_smac is None:
                    pmr.modified_predict_smac = GLOBAL.MINT_SMAC_REPLACE_LIST[target_mac]
                pmr.modified_smac += 1
                break
        
        dst_mac = packet[Ether].dst
        for target_mac in GLOBAL.MINT_DMAC_REPLACE_LIST.keys():
            if dst_mac == target_mac:
                if pmr.origin_predict_dmac is None:
                    pmr.origin_predict_dmac = GLOBAL.target_mac
                packet[Ether].dst = GLOBAL.MINT_DMAC_REPLACE_LIST[target_mac]
                if pmr.modified_predict_dmac is None:
                    pmr.modified_predict_dmac = GLOBAL.MINT_DMAC_REPLACE_LIST[target_mac]
                pmr.modified_dmac += 1
                break
            
        # if session check is enabled
        if GLOBAL.MINT_ENABLED_CHECK_SESSION:
            for target_mac in GLOBAL.MINT_DMAC_REPLACE_LIST.keys():
                if src_mac == target_mac:
                    packet[Ether].src = GLOBAL.MINT_DMAC_REPLACE_LIST[target_mac]
                    pmr.modified_smac += 1
                    break

            for target_mac in GLOBAL.MINT_SMAC_REPLACE_LIST.keys():
                if dst_mac == target_mac:
                    packet[Ether].dst = GLOBAL.MINT_SMAC_REPLACE_LIST[target_mac]
                    pmr.modified_dmac += 1
                    break



def packet_modify_sync_oui_ipv4(packet : Packet, pmr : PacketModifyReport, to_addr_ipv4):
    sync_ip = None
    if GLOBAL.MINT_ENABLED_RAND_SOUI_SIP_SYNC or GLOBAL.MINT_ENABLED_RAND_DOUI_DIP_SYNC:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if GLOBAL.MINT_ENABLED_RAND_SOUI:
                if GLOBAL.MINT_ENABLED_RAND_SOUI_SIP_SYNC:
                    for sync_source_ip in GLOBAL.MINT_RAND_SOUI_SIP_SYNC:
                        if src_ip == sync_source_ip:
                            if pmr.origin_predict_sip is None:
                                pmr.origin_predict_sip = src_ip
                            if sync_ip is None:
                                if to_addr_ipv4 is not None:
                                    sync_ip = to_addr_ipv4
                                else:
                                    sync_ip = increase_ipv4_addr(sync_source_ip, pmr._generated_idx)

                            packet[IP].src = sync_ip
                            pmr.modified_sip += 1
                            if pmr.modified_predict_sip is None:
                                pmr.modified_predict_sip = sync_ip
                            break

                        elif GLOBAL.MINT_ENABLED_CHECK_SESSION:
                            if dst_ip == sync_source_ip:
                                if sync_ip is None:
                                    if to_addr_ipv4 is not None:
                                        sync_ip = to_addr_ipv4
                                    else:
                                        sync_ip = increase_ipv4_addr(sync_source_ip, pmr._generated_idx)
                                packet[IP].dst = sync_ip
                                pmr.modified_dip += 1
                                break
    
            if GLOBAL.MINT_ENABLED_RAND_DOUI:
                if GLOBAL.MINT_ENABLED_RAND_DOUI_DIP_SYNC:
                    for sync_source_ip in GLOBAL.MINT_RAND_DOUI_DIP_SYNC:
                        if dst_ip == sync_source_ip:
                            if pmr.origin_predict_dip is None:
                                pmr.origin_predict_dip = dst_ip
                            if sync_ip is None:
                                if to_addr_ipv4 is not None:
                                    sync_ip = to_addr_ipv4
                                else:
                                    sync_ip = increase_ipv4_addr(sync_source_ip, pmr._generated_idx)

                            packet[IP].dst = sync_ip
                            pmr.modified_dip += 1
                            if pmr.modified_predict_dip is None:
                                pmr.modified_predict_dip = sync_ip
                            break
                        
                        elif GLOBAL.MINT_ENABLED_CHECK_SESSION:
                            if src_ip == sync_source_ip:
                                if sync_ip is None:
                                    if to_addr_ipv4 is not None:
                                        sync_ip = to_addr_ipv4
                                    else:
                                        sync_ip = increase_ipv4_addr(sync_source_ip, pmr._generated_idx)
                                packet[IP].src = sync_ip
                                pmr.modified_sip += 1
                                break

            if not GLOBAL.MINT_DISABLE_CALC_IP_CHECKSUM: 
                # Fix the IP checksum 
                del packet[IP].chksum


def packet_modify_ipv4(packet : Packet, pmr):
    # Check the has layer (IP)
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        for ipv4_value in GLOBAL.MINT_SIP_REPLACE_LIST.keys():
            if src_ip == ipv4_value:
                if pmr.origin_predict_sip is None:
                    pmr.origin_predict_sip = src_ip
                packet[IP].src = GLOBAL.MINT_SIP_REPLACE_LIST[ipv4_value]
                if pmr.modified_predict_sip is None:
                    pmr.modified_predict_sip = GLOBAL.MINT_SIP_REPLACE_LIST[ipv4_value]
                pmr.modified_sip += 1
                break

        dst_ip = packet[IP].dst
        for ipv4_value in GLOBAL.MINT_DIP_REPLACE_LIST.keys():
            if dst_ip == ipv4_value:
                if pmr.origin_predict_dip is None:
                    pmr.origin_predict_dip = dst_ip
                packet[IP].dst = GLOBAL.MINT_DIP_REPLACE_LIST[ipv4_value]
                if pmr.modified_predict_dip is None:
                    pmr.modified_predict_dip = GLOBAL.MINT_DIP_REPLACE_LIST[ipv4_value]
                pmr.modified_dip += 1
                break
        
        # if session check is enabled
        if GLOBAL.MINT_ENABLED_CHECK_SESSION:
            for ipv4_value in GLOBAL.MINT_DIP_REPLACE_LIST.keys():
                if src_ip == ipv4_value:
                    packet[IP].src = GLOBAL.MINT_DIP_REPLACE_LIST[ipv4_value]
                    pmr.modified_sip += 1
                    break
            for ipv4_value in GLOBAL.MINT_SIP_REPLACE_LIST.keys():
                if dst_ip == ipv4_value:
                    packet[IP].dst = GLOBAL.MINT_SIP_REPLACE_LIST[ipv4_value]
                    pmr.modified_dip += 1
                    break
    
        if not GLOBAL.MINT_DISABLE_CALC_IP_CHECKSUM:        
            # Fix the IP checksum 
            del packet[IP].chksum



def packet_modify_mac_ip(packets : PacketList, mac_elements_exist, \
        ipv4_elements_exist, pmr, oui_list, oui_idx, \
            after_mac_part, after_ipv4):

    for packet_idx, packet in enumerate(packets):
        # Check the need to change element and has layer (MAC)
        if mac_elements_exist:
            packet_modify_mac(packet, pmr)
        else:
            if GLOBAL.MINT_ENABLED_RAND_SOUI or GLOBAL.MINT_ENABLED_RAND_DOUI:
                packet_modify_rand_oui_mac(packet, pmr, oui_list, oui_idx, after_mac_part)

        # Check the need to change element and has layer (IP)
        if ipv4_elements_exist:
            packet_modify_ipv4(packet, pmr)
        else:
            if GLOBAL.MINT_ENABLED_RAND_DOUI_DIP_SYNC or GLOBAL.MINT_ENABLED_RAND_SOUI_SIP_SYNC:
                packet_modify_sync_oui_ipv4(packet, pmr, after_ipv4)