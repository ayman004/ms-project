"""This IDPS is developed for the masters project.
	This is the ***Rate Limiting Algorithm***
	AKA RL algorithm		
		
	"""
#Import modules and libraries required
from pox.core import core                      # This is the main POX object
import pox.openflow.libopenflow_01 as of       # import OpenFlow 1.0 from pox module
import pox.lib.packet as pkt                   # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr  # IP and MAC libraries
import pox.lib.util as poxutil                 # poxutil
import pox.lib.revent as revent                # revent is for event handling
import pox.lib.recoco as recoco
from pox.lib.recoco import Timer               #handle time issues
from datetime import datetime
from pox.lib.revent import EventHalt            #Blocking traffic
from time import time

log = core.getLogger()
log.info("IDS Startes at %s", datetime.now())

packetdetails = []                                #used to store connection info
blacklist = set()                                 #store blaclisted MAC,used set to prevent duplicates
THRESHOLD = 50000                                    #threshold set to 20 SYN

def block(address):
    """ This function blocks a host by adding it to
    	the blacklisted host
    	"""
    global blacklist
    global THRESHOLD
    blacklist.add(address)

def RST_attack(conn):
    """ This function blocks a host if it sends more
    	than 5 REST packets without having sent SYN packets
    	"""
    global blacklist
    if conn:
        for c in conn:
            if c[2] == 0 and c[5] > 3:
                block(c[0])
                log.warning("RESET attack detected %s from %s" %(datetime.now(),c[0]))

def clear_cache():
    global packetdetails

    now = time()
    if packetdetails:
        for con in packetdetails:
            period = con[6]
            if int(now - period) > 60:
                log.info("Clearing cache at %s deleted host with mac %s " %(datetime.now(),con[0]))
                packetdetails.remove(con)
            else:
                log.info("Clearing cache at %s no host is deleted." %(datetime.now()))

def test (event):
    """ This function is the core of the IDS,it tracks
		connections and extract and blocks any host
		that violates IDS policy of threshold
		"""
    global THRESHOLD
    global packetdetails
    global blacklist

    packet = event.parsed                      #pass events

    tcp_packet = packet.find('tcp')            #Extract TCP packet
    ip = packet.find('ipv4')                   #Extract source and destination IP
    #source and destination MACs
    srcadd = packet.src
    dstadd = packet.dst
    #Store connection info in the format as
    #[source MAC, destination MAC, SYN, ACK, RST]
    cinfo = [srcadd,dstadd,1,0,0,0,time()]

    #If MAC of source host is blacklisted halt traffic
    if srcadd in blacklist:
        return EventHalt

    #TCP flags are PSH,URG,ECN,FIN,CWR pass
    if True in [tcp_packet.PSH,tcp_packet.URG,tcp_packet.ECN,tcp_packet.FIN,tcp_packet.CWR]:
			return

    #Check if there is a content in the packet
    if tcp_packet:
        #If TCP flag is SYN
        if tcp_packet.flags == 2:

          #get packet packetdetails         

          #start tracking connection    
          if cinfo[:2] not in [x[:2] for x in packetdetails]:
              packetdetails.append(cinfo)

          #update existing connection
          else:

              for packet in packetdetails:
                  if packet[0] == srcadd and packet[1] == dstadd:
                      packet[2] += 1
					  #check to see if threshold is reached, if so block host
                      if packet[2] > THRESHOLD - 1 and int(time() - packet[6]) < 60:
                          log.warning("Attack detected at %s from %s" %(datetime.now(),srcadd))
                          block(srcadd)

        elif tcp_packet.SYN and  tcp_packet.ACK:
          #get packet packetdetails
          for packet in packetdetails:
              if packet[0] == dstadd and packet[1] == srcadd:
                  packet[3] +=  1

        elif tcp_packet.ACK:
            #get packet packetdetails
            if packetdetails:
                for packet in packetdetails:
                    if packet[0] == srcadd and packet[1] == dstadd and packet[3] > 0:
                        packet[4] += 1

            else:
                packetdetails.append([srcadd,dstadd,0,0,1,0,time()])

        #If TCP flag is SYN-ACK
        elif tcp_packet.SYN and  tcp_packet.ACK:
          #get packet packetdetails
		  #Track conection
          for packet in packetdetails:
              if packet[0] == dstadd and packet[1] == srcadd:
                  packet[3] += 1

		#If TCP flag is ACK
        elif tcp_packet.ACK:
            #get packet packetdetails
            #update connection
            if packetdetails:
                for packet in packetdetails:
                    if packet[0] == srcadd and packet[1] == dstadd and packet[3] > 0:
                        packet[4] +=  1                    
			#start tracking connection
            else:
                packetdetails.append([srcadd,dstadd,0,0,1,0,time()])

        elif tcp_packet.RST:
            #print(srcadd ,' ',ip.srcip,' =>  ', dstadd,' ',ip.dstip, ' RST')
			#update connection
            if packetdetails:
                for packet in packetdetails:
                    if packet[0] == srcadd and packet[1] == dstadd and packet[4] == 0:
                        packet[5] += 1
                    if packet[0] == dstadd and packet[1] == srcadd and packet[2] == 0 and packet[3]==0 and packet[4] > 0:
                        packet[5] += 1
            #start tracking connection
            else:
                packetdetails.append([srcadd,dstadd,0,0,0,1,time()])

        else:
			log.info("Something went terribly wrong!!!")
			pass

        RST_attack(packetdetails)

Timer(30,clear_cache,recurring=True)
def launch():
    core.openflow.addListenerByName("PacketIn",test, priority=1)
