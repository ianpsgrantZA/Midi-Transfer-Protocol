# Midi Transfer Protocol (MTP)
# run using 'python3 MTP.py'

import sys
import concurrent.futures
import time
import random

class Node:
    node_n = 0
    node_list = []
    data = []
    resends_T = 0
    nosends_T = 0

    def __init__(self, name, IP): # initialise node
        self.IP = IP
        self.name = name
        self.MTPHostIP = None
        self.resends = 0
        Node.node_n += 1
        Node.node_list.append(self)

    def startMTPHost(self, ip): # start MTP on destination nodes
        for node in Node.node_list:
            if node.IP == ip:
                out = node.MTPConnect(self.IP)
                print(out)
        
    def MTPConnect(self, ip): # connect destination to host
        self.MTPHostIP = ip
        return self.name + ":" + self.IP + " successfully connected via MTP."

    def encapsulate(self, ip1, ip2, seq, size, data): # Creates a bytelist packet containing data sent over MTP
        s1 = [i for i in range(len(ip1)) if ip1.startswith('.', i)] #split IP via '.'
        s2 = [i for i in range(len(ip2)) if ip2.startswith('.', i)]

        # Create packet
        bytelist = []
        bytelist.append(int(ip1[0:s1[0]]) & 0xff) # Source IP
        bytelist.append(int(ip1[s1[0]+1:s1[1]]) & 0xff) 
        bytelist.append(int(ip1[s1[1]+1:s1[2]]) & 0xff)
        bytelist.append(int(ip1[s1[2]+1:]) & 0xff)
        bytelist.append(int(ip2[0:s2[0]]) & 0xff) # Destination IP
        bytelist.append(int(ip2[s2[0]+1:s2[1]]) & 0xff) 
        bytelist.append(int(ip2[s2[1]+1:s2[2]]) & 0xff)
        bytelist.append(int(ip2[s2[2]+1:]) & 0xff)
        bytelist.append(seq>>8 & 0x00ff) #Sequence
        bytelist.append(seq & 0x00ff)
       
        checksum = 0
        for i in range(0,10,2): # create header checksum
            checksum += bytelist[i]<<8 
            checksum += bytelist[i+1]
        

        checksum = (checksum & 0xFFFF) + (checksum >> 8)
        checksum = ((~checksum) & 0xFFFF)# ones compliment

        # ADD FORCED PACKET ERROR (33%)
        if random.randint(0,2)==0:
            checksum = (checksum+0x1) & 0xFFFF

        bytelist.append((checksum >> 8) & 0xFF) # add checksum to packet
        bytelist.append(checksum & 0xff)
        bytelist.append(size & 0xff) # add size to packet

        # add DATA (3 bytes)
        bytelist.append((data >> 16) & 0xFF) # byte 1
        bytelist.append((data >> 8) & 0xFF) # byte 2
        bytelist.append(data & 0xFF) # byte 3
        # Packet created

        # print(bytelist) # DEBUG
        
        return bytelist

    def checkPacket(self, bytelist):
        checksum = 0
        for i in range(0,10,2): # add packets together
            checksum += (bytelist[i]<<8) + bytelist[i+1]
        checksum = (checksum & 0xFFFF) + (checksum >> 8)
        check = (bytelist[10]<<8) + bytelist[11] # packet checksum

        if (checksum+check == 0xFFFF): # check if both add to 0xFFFF
            return 0 # checksum correct
        else:
            return 1 # checksum incorrect


    def sendMTP(self, ip, packet): # send 'packet' to destination with 'ip'
        for dest_node in Node.node_list:
            if (dest_node.IP == ip):
                dest_node.receiveMTP(packet,self)
                break
    
    def receiveMTP(self,packet,host): # destination recieves packet
        if self.checkPacket(packet)==0: # if checksum correct
            print(self.name +' '+ self.IP +': '+ hex(packet[13]) +' '+ hex(packet[14]) +' '+ hex(packet[15]))
        else:
            if self.resends>=3:
                print("ERROR: triple resend, note not received")
                Node.nosends_T+=1
            else: # attempt to recover data
                self.resends+=1
                Node.resends_T+=1
                seq = (packet[8]>>8) +packet[9]
                host.resendMTP(seq, host.IP, self.IP)

    def resendMTP(self, seq, ip1, ip2): # try to resend corrupt data
        packet = self.encapsulate(ip1,ip2,seq,sys.getsizeof(Node.data[seq]),Node.data[seq])
        self.sendMTP(packet, ip2)
        for dest_node in Node.node_list:
            if (dest_node.IP == ip2):
                dest_node.receiveMTP(packet,self)
                break

    def closeConnection(self): # close connection and reset data
        Node.node_n = 0
        Node.node_list = []
        Node.data = []
        Node.resends_T = 0
        Node.nosends_T = 0
        print("Closing host connection.")

def MTPthread(host, host_IP, dest_IP, i, size, data): # send data, used in multithreading
    bytelist = host.encapsulate(host_IP, dest_IP, i, size, data)
    host.sendMTP(dest_IP, bytelist)
    return 0


def main():
    # to simulate project tests
    test1 = False 
    test2 = False

    hostname = "Host" # Add host to network
    host_IP = "192.168.0.1"
    host = Node(hostname, host_IP)

    dest = [] # destination nodes
    dest_IP = [] # destination ips
    data = [] # data bytes

    if test1: # test1 case, change data corruption chance (ln 61)
        dest.append(Node("PC_A", "192.168.0.2"))
        dest_IP.append("192.168.0.2")
        data = [0x57a57a,0x00ff34,0x0000a5,0x34561c,0xffffff,0x000000]
    
    elif test2:  # test2 case
        dest.append(Node("PC_A", "192.168.0.2"))
        dest.append(Node("PC_B", "192.168.0.3"))
        dest.append(Node("PC_C", "192.168.0.4"))
        dest_IP.append("192.168.0.2")
        dest_IP.append("192.168.0.3")
        dest_IP.append("192.168.0.4")
        data = [0x101010,0x202020,0x303030,0x404040,0x505050,0x606060]
    else:  # default case
        dest.append(Node("PC_A", "192.168.0.2"))
        dest.append(Node("PC_B", "192.168.0.3"))
        dest_IP.append("192.168.0.2")
        dest_IP.append("192.168.0.3")
        data = [0x101010,0x202020,0x303030,0x404040,0x505050,0x606060]

    for d in dest_IP:
        host.startMTPHost(d) # start destination connections from host

    print('---------------------------------')

    Node.data = data # store data on system
    output = [] # DEBUG

    for i in range(0,len(data)):
        for dest_node in dest:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: # run each data point/destination as a thread
                output.append(executor.submit(MTPthread, host, host_IP, dest_node.IP, i, sys.getsizeof(data[i]), data[i]))
    while(not output[-1].done()):
        pass

    # for out in output: # DEBUG
    #     print(out.result(),end='')

    print('---------------------------------')
    print('Program complete!')
    print('Packets Arrived: '+ str((len(data)*len(dest))-Node.nosends_T) + '/' + str(len(data)*len(dest)))
    print('Resends: '+ str(Node.resends_T))
    print('Average resends per packet: ' + str(round(Node.resends_T/(len(data)*len(dest)), 2)))


if __name__ == '__main__':
    main()
