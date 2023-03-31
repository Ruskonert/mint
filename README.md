# MINT (MAC, IP is Now you wanTed)
MINT(MAC, IP is Now you wanTed) is can be modify MAC, IP address value you want to, this makes it easy to create modulated PCAPs. In addition to generating new PCAPs, replay mode using modulated packet information is supported.
<br/><br/>
This tool is designed to simplify many cumbersome tasks, that's why I created this repository.

# Pre-install
This script requires Python 3.7 or higher.</br>
Also, you need to specific python modules: <code>scapy, pandas</code>.</br>
```
pip install pandas
pip install scapy
```
You can use the command as follows:
```
python3 mint.py [-h|--help] [-m|--mode] [-o|--output] [--pcapng-enabled] [--check-session] [-e|--eth] [--smac] [--dmac] [--sip] [--dip] [--random-soui] [--random-doui] [--disable-ip-checksum] [--generate-count] [--sync-sip] [--sync-dip] [--slient] [--export] [Path or specific file ...]
```

# Description
[-h or --help] : Output the guide </br>
[-m or --mode] : Set the execute mode [1: modify(default), 2: replay, 3: make&replay, 4: generate packet (rule-based)] </br>
[-o or --output] : Output modified PCAP file to specific path (modify-mode only) </br>
[--pcapng-enabled] : Save to the PCAPNG format when save the file (modify-mode only) </br>
[--check-session] : When changing the MAC or IP, change them together if the session is exchanging (modify-mode only) </br>
[-e or --eth] : Select the interface name for sending modified packet (replay-mode only) </br>
[--smac] : Change the specified source MAC [example: 00:11:22:33:44:55/aa:bb:cc:dd:ee:ff,00:19:38:2a:69:44/aa:bb:cc:dd:ee:ff]  </br>
[--dmac] : Change the specified destination MAC [example: 00:11:22:33:44:55/aa:bb:cc:dd:ee:ff,00:19:38:2a:69:44/aa:bb:cc:dd:ee:ff]  </br>
[--sip] : Change the specified source IP [example: 192.168.0.1/192.168.0.2]  </br>
[--dip] : Change the specified destination IP [example: 192.168.0.1/192.168.0.2]  </br>
[--random-soui] : Change the source MAC to random with OUI  </br>
[--random-doui] : Change the destination MAC to random with OUI  </br>
[--disable-ip-checksum] : Disable re-calculate a checksum value of the IP Layer when changed  </br>
[--generate-count] : Define the generate count when modified the PCAP with OUI (Need to enable --random-doui or soui)  </br>
[--sync-sip] : Sync the specific Source IP when SMAC address is changed with OUI  </br>
[--sync-dip] : Sync the specific Destination IP when DMAC address is changed with OUI  </br>
[--slient] : Disable the system output  </br>
[--export] : Export to CSV file of report  </br>
[Path or specific file ...] : Input the file or directory path [Example: /path/to/file.pcap or /path/to ...]  </br>

# License
This project is under the MIT License.
