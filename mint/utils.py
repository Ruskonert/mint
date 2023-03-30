import mint.general as GLOBAL

def mint_print(string = ""):
    if len(string) == 0:
        string = ""
    if not GLOBAL.MINT_SLIENT_MODE:
        print(string)



def increase_mac_addr(mac_addr : str, increase_value : int) -> str:
    old_mac_part = mac_addr.split(":")
    idx = len(old_mac_part) - 1
    for i in range(0, idx + 1):
        old_mac_part[i] = int(old_mac_part[i], 16)

    while True:
        new_value, old_mac_part[idx] = divmod(old_mac_part[idx] + increase_value, 254)
        if old_mac_part[idx] <= 0:
            old_mac_part[idx] = 1

        if new_value == 0:
            break
        else:
            increase_value = new_value
            idx -= 1
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(old_mac_part)



def increase_ipv4_addr(ipv4_addr : str, increase_value : int) -> str:
    old_ip_part = ipv4_addr.split(".")
    idx = len(old_ip_part) - 1
    for i in range(0, idx + 1):
        old_ip_part[i] = int(old_ip_part[i])
    while True:
        new_value, old_ip_part[idx] = divmod(old_ip_part[idx] + increase_value, 254)
        if old_ip_part[idx] <= 0:
            old_ip_part[idx] = 1

        if new_value == 0:
            break
        else:
            increase_value = new_value
            idx -= 1
    return "%d.%d.%d.%d" % tuple(old_ip_part)



def remove_pcap_file_extension(filename : str) -> str:
    filename = filename.replace(".pcap", "")
    filename = filename.replace(".pcapng", "")
    filename = filename.replace(".cap", "")
    return filename