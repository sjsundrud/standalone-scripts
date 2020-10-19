from scapy.all import *
import sys
import argparse
from fpdf import FPDF
from netaddr import IPNetwork
#This defines the argparse configuration for the script
parser = argparse.ArgumentParser(
	description = 'This script scans target hosts for open ports.  Specify hosts with the -i tag, and the ports with the -p tag.  Both are required to run the script.',
)
parser.add_argument('-i', action='store', 
	dest='ip_addr',
	help='Specify the ip address(es) to be scanned.  You can either specify a range (192.168.1.20-40), a subnet (192.168.1.0/24), or separate hosts with a comma (192.168.1.20,102.168.1.40)',
)
parser.add_argument('-p', action='store',
	dest='port',
	help='Specify the ports to scan.  Like the above syntax for hosts, you can either select a range or multiple ports separated by commas.',
)
parser.add_argument('-t', action='store_true',
	dest='method_tcp',
	default=False,
	help='Conduct a TCP scan.',
)
parser.add_argument('-u', action='store_true',
	dest='method_udp',
	default=False,
	help='Conduct a UDP scan.',
)
parser.add_argument('-m', action='store_true',
	dest='method_icmp',
	default=False,
	help='Conduct an ICMP scan.',
)

def listPorts(ports_arg):
	ports = []
	if '-' in ports_arg:
		port_range = ports_arg.split('-')
		for num in range(int(port_range[0]), int(port_range[1])+1):
			ports.append(num)
	elif ',' in ports_arg:
		ports = ports_arg.split(',')
	else:
		ports.append(ports_arg)
	return ports

def listIP(ip_arg):
	ip_addr = []
	if ',' in ip_arg:
		ip_addr = ip_arg.split(',')
	elif '-' in ip_arg:
		temp = ip_arg.split('.')
		iprange = temp[-1].split('-')
		temp.pop()
		const_addr = '.'.join(temp)
		for num in range(int(iprange[0]), int(iprange[1])+1):
			ip_addr.append(const_addr + '.' + num)
	elif '/' in ip_arg:
		for address in IPNetwork(ip_arg):
			ip_addr.append(address)
	else:
		ip_addr.append(ip_arg)
	return ip_addr
def main(args):
	methods = []
	if args.method_tcp:
		methods.append("TCP")
	if args.method_udp:
		methods.append("UDP")
	if args.method_icmp:
		methods.append("ICMP")
	TIMEOUT = 2
	ports = listPorts(args.port)
	ip_addr = listIP(args.ip_addr)
	printout = []
	for address in ip_addr:

		for method in methods:
			if method == "ICMP":
				packet = IP(dst = address )/ICMP()
				reply = sr1(packet, timeout=TIMEOUT)
				if reply is not None:
					print(reply.dst + " - ICMP responded")
					printout.append(reply.dst + " - ICMP")
			elif method == "TCP":
				for port in ports:
					packet = IP(dst = address)/TCP(dport = int(port), flags="S")
					reply = sr1(packet, timeout=TIMEOUT)
					if reply is not None:
						print(reply.dst + ", port " + str(port) + " - TCP responded")
						printout.append(reply.dst + "-" + str(port) + "-" + " - TCP responded")
			else:
				for port in ports:
					packet = IP(dst = address)/UDP(dport = int(port))
					reply = sr1(packet, timeout=TIMEOUT)
					if reply is not None:
						print(reply.dst + ", port " + str(port) + " - UDP responded")
						printout.append(reply.dst + "-" + str(port) + "- UDP responded")
	if len(printout) > 0:
		pdf = FPDF()
		pdf.add_page()
		pdf.set_font('Times', '', 12)
		for line in printout:
			pdf.cell(0, 10, str(line), 0, 1)
		pdf.output('portscanner_output.pdf', 'F')
		print("Results saved to pdf in local folder")

def checkInt(num): #dedicated function allows for pretty breaking
	try:
		int(num)
		return True
	except ValueError:
		return False

def checkIP(ip_addr):
	try:
		seg = ip_addr.split(".")
		if len(seg) != 4:
			return False
		for item in seg:
			if not checkInt(item):
				return False
			if int(item) < 0 or int(item) > 255:
				return False
		return True
	except:
		return False

def ipValid(ip_addr_arg): #This determines that the ip address is in a valid format, checking for comma-separated values, ranges, or subnets
	if ',' in ip_addr_arg:
		addresses = ip_addr_arg.split(',')
		for address in addresses:
			if not checkIP(address):
				return False
	elif '-' in ip_addr_arg:
		try:
			temp = ip_addr_arg.split('.') #filter out the first portion
			iprange = temp[-1].split('-') #split the last segment
			temp.pop()
			const_addr = '.'.join(temp)
			if not checkIP(const_addr + "." + iprange[0]) or not checkIP(const_addr + "." + iprange[1]): #check both extremes of the range, make sure they're legal
				return False
			if int(iprange[0]) > int(iprange[1]): #make sure the range is from smaller to larger
				return False
		except:
			return False
	elif '/' in ip_addr_arg:
		address = ip_addr_arg.split('/')
		if not checkIP(address[0]):
			return False
		if not checkInt(address[1]):
			return False
		if int(address[1]) < 1 or int(address[1]) > 32: #check submask size
			return False

	else:
		if not checkIP(ip_addr_arg):
			return False
	return True

def portValid(port_arg): #Like the above function, this ensures that the ports are valid ports to scan
	if ',' in port_arg:
		ports = port_arg.split(',')
		for port in ports:
			if not checkInt(port):
				return False
			if int(port) < 1 or int(port) > 65535: #max and min port numbers
				return False
	elif '-' in port_arg:
		ports = port_arg.split('-')
		for port in ports:
			if not checkInt(port):
				return False
			if int(port) < 1 or int(port) > 65535:
				return False
		if int(ports[0]) > int(ports[1]): #make sure these go in order from smaller to larger
			return False

	else:
		if not checkInt(port_arg):
			return False
		if int(port_arg) < 1 or int(port_arg) > 65535:
			return False
	return True

if __name__ == "__main__":
	args = parser.parse_args()
	argsAreValid = True #Now checking to make sure all needed arguments have been passed in.  If so, we can run the main function.
	if args.ip_addr is None or args.port is None:
		print("ERR - You must specify both a target and a port")
		argsAreValid = False
	if args.method_tcp is False and args.method_udp is False and args.method_icmp is False:
		print("ERR - You must specify a method to scan")
		argsAreValid = False
	if args.ip_addr:
		if ipValid(args.ip_addr) is False:
			print("ERR - The IP address is in an invalid format")
			argsAreValid = False
	if args.port:
		if portValid(args.port) is False:
			print("Err - The port is in an invalid format")
			argsAreValid = False

	if argsAreValid: #Only run after validating
		main(args)
