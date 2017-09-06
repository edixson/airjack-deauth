# Airjack-Deauth
a script to automate the wifi deauth process
will scan and start deauth most WPA protected APs to obtain hash

# FYI - all files below are needed to run
blacklist file stores the MAC of AP after obtaining hash
good directory stores the 4-way handshake pcap(convert to hccapx then hashcat)
pw file is just one password to test the 4-way handshake
main.py is the program

to run execute the following in the program root directory
there are some requirements... python, aircrack-ng,..., kali,

sudo python main.py wlan0
