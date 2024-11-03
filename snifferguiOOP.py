import socket
import struct
import binascii
import tkinter as tk
from tkinter import ttk
import threading
from threading import Thread,Event
import string
import datetime

filtering = False
currentQuery = ''

# Some utilities
def prettifyMAC(mac):
    octets = []
    for b in mac:
        octets.append(format(b, '02x'))
    return ":".join(octets).upper()

def prettifyHex(hex):
    st = str(binascii.hexlify(hex,' ')).replace('b','').replace('\'','')
    res = ''
    first = True
    for i in st.split():
        if first == False:
            res += ' '
        else:
            first = False
        res += i.zfill(2)  
    return res.upper()
        
class Packet():
    def __init__(self,action='craft', raw='', time='00:00',id=0):
        self.time = time
        self.tableSrc = 'Unknown'
        self.tableDest = 'Unknown'
        self.tableProto = 'Unknown'
        self.raw = raw
        self.layers = []
        self.data = {}
        self.pretty = {}
        self.info = ''
        self.id = id

        self.pretty['ID'] = str(self.id)

        if action == 'decode':
            self.decodePacket()
        elif action == 'craft':
            self.craftPacket()

    def decodePacket(self):
        self.prettyRaw = prettifyHex(self.raw)
        self.prettyAscii = ''.join(map(lambda x: x if x in string.printable and x not in string.whitespace else '.', str(bytearray.fromhex(prettifyHex(self.raw)).decode(errors='ignore'))))
        
        self.layers.append('Ethernet')
        self.decodeEthernetFrame(self.raw)

        if self.pretty['Ethernet']['Type'] == 'IPv4': 
            self.layers.append('IPv4')
            self.decodeIPv4Header(self.data['Ethernet']['payload'])

            if self.pretty['IPv4']['Protocol'] == 'UDP':
                self.layers.append('UDP')
                self.decodeUDPHeader(self.data['IPv4']['payload'])
            elif self.pretty['IPv4']['Protocol'] == 'TCP':
                self.layers.append('TCP')
                self.decodeTCPHeader(self.data['IPv4']['payload'])
        elif self.pretty['Ethernet']['Type'] == 'ARP':
            self.layers.append('ARP')
            self.decodeARP(self.data['Ethernet']['payload']) 

    def decodeEthernetFrame(self,payload):
        # Definitions
        etherTypes = {2048:'IPv4', 34525:'IPv6',2054:'ARP'}

        # Unpack as bytes
        self.data['Ethernet'] = {}
        self.data['Ethernet']['frame'] = struct.unpack('! 6s 6s H',payload[:14])
        self.data['Ethernet']['destMAC'] = self.data['Ethernet']['frame'][0]
        self.data['Ethernet']['srcMAC'] = self.data['Ethernet']['frame'][1]
        self.data['Ethernet']['etherType'] = self.data['Ethernet']['frame'][2]
        self.data['Ethernet']['payload'] = payload[14:]

        # Prettify
        self.pretty['Ethernet'] = {}
        self.pretty['Ethernet']['Source MAC'] = prettifyMAC(self.data['Ethernet']['srcMAC'])
        self.pretty['Ethernet']['Destination MAC'] = prettifyMAC(self.data['Ethernet']['destMAC'])
        if self.data['Ethernet']['etherType'] in etherTypes:
            self.pretty['Ethernet']['Type'] = etherTypes[self.data['Ethernet']['etherType']]
        else:
            self.pretty['Ethernet']['Type'] = 'Unknown' 

        self.tableProto = self.pretty['Ethernet']['Type']
        self.tableSrc = self.pretty['Ethernet']['Source MAC']
        self.tableDest = self.pretty['Ethernet']['Destination MAC']

    def decodeARP(self,payload):
        # Definitions
        htypes = {1:'Ethernet'}
        ptypes = {2048:'IPv4', 34525:'IPv6',2054:'ARP'} #same as ethertype
        operations = {1: 'ARP Request', 2:'ARP Reply'}

        # Unpack as bytes
        self.data['ARP'] = {}
        self.data['ARP']['arpHeader'] = struct.unpack('! HHBBH',payload[:8])
        self.data['ARP']['htype'] = self.data['ARP']['arpHeader'][0]
        self.data['ARP']['ptype'] = self.data['ARP']['arpHeader'][1]
        self.data['ARP']['hlen'] = self.data['ARP']['arpHeader'][2]
        self.data['ARP']['plen'] = self.data['ARP']['arpHeader'][3]
        self.data['ARP']['operation'] = self.data['ARP']['arpHeader'][4]

        leftover = payload[8:]
        self.data['ARP']['senderHardwareAddr'] = leftover[:self.data['ARP']['hlen']]
        leftover = leftover[self.data['ARP']['hlen']:]
        self.data['ARP']['senderSoftwareAddr'] = leftover[:self.data['ARP']['plen']]
        leftover = leftover[self.data['ARP']['plen']:]
        self.data['ARP']['targetHardwareAddr'] = leftover[:self.data['ARP']['hlen']]
        leftover = leftover[self.data['ARP']['hlen']:]
        self.data['ARP']['targetSoftwareAddr'] = leftover[:self.data['ARP']['plen']]

        self.pretty['ARP'] = {}
        if self.data['ARP']['htype'] in htypes:
            self.pretty['ARP']['Hardware Type'] = htypes[self.data['ARP']['htype']] + ' (' + str(self.data['ARP']['htype']) + ')'
        else:
            self.pretty['ARP']['Hardware Type'] = 'Unknown (' + str(self.data['ARP']['htype']) + ')'

        if self.data['ARP']['ptype'] in ptypes:
            self.pretty['ARP']['Protocol Type'] = ptypes[self.data['ARP']['ptype']] + ' (' + str(self.data['ARP']['ptype']) + ')'
        else:
            self.pretty['ARP']['Protocol Type'] = 'Unknown (' + str(self.data['ARP']['ptype']) + ')'

        self.pretty['ARP']['Hardware Size'] = str(self.data['ARP']['hlen'])
        self.pretty['ARP']['Protocol Size'] = str(self.data['ARP']['plen'])

        if self.data['ARP']['operation'] in operations:
            self.pretty['ARP']['Operation'] = operations[self.data['ARP']['operation']] + ' (' + str(self.data['ARP']['operation']) + ')'
        else:
            self.pretty['ARP']['Operation'] = 'Unknown (' + str(self.data['ARP']['operation']) + ')'

        self.pretty['ARP']['Sender MAC Address'] = prettifyMAC(self.data['ARP']['senderHardwareAddr'])
        self.pretty['ARP']['Sender IP Address'] = socket.inet_ntop(socket.AF_INET,self.data['ARP']['senderSoftwareAddr'])
        self.pretty['ARP']['Target MAC Address'] = prettifyMAC(self.data['ARP']['targetHardwareAddr'])
        self.pretty['ARP']['Target IP Address'] = socket.inet_ntop(socket.AF_INET,self.data['ARP']['targetSoftwareAddr'])

        if self.data['ARP']['operation'] == 1:
            self.info += 'Who has ' + self.pretty['ARP']['Target IP Address'] +'? Tell ' + self.pretty['ARP']['Sender IP Address']
        elif self.data['ARP']['operation'] == 2:
            self.info += self.pretty['ARP']['Sender IP Address'] +' is at ' + self.pretty['ARP']['Sender MAC Address']

    def decodeIPv4Header(self,payload):
        # Definitions
        protocols = {0:'HOPOPT', 1:'ICMP', 2:'IGMP', 3:'GGP', 4:'IP-in-IP', 5:'ST', 6: 'TCP',7:'CBT', 8:'EGP',9:'IGP', 10:'BBN-RCC-MON', 11:'NVP-II', 12:'PUP', 13:'ARGUS', 14:'EMCON', 15:'XNET',
        16:'CHAOS', 17:'UDP'}

        # Unpack as bytes
        self.data['IPv4'] = {}
        self.data['IPv4']['ipv4Header'] = struct.unpack('! BBHHHBBH4s4s',payload[:20])
        self.data['IPv4']['version'] = self.data['IPv4']['ipv4Header'][0] >> 4
        self.data['IPv4']['HL'] = self.data['IPv4']['ipv4Header'][0] & 0xF
        self.data['IPv4']['TOS'] = self.data['IPv4']['ipv4Header'][1]
        self.data['IPv4']['totalLength'] = self.data['IPv4']['ipv4Header'][2]
        self.data['IPv4']['identification'] = self.data['IPv4']['ipv4Header'][3]
        self.data['IPv4']['flagsAndFrags'] = self.data['IPv4']['ipv4Header'][4] # TODO split flags and frags
        self.data['IPv4']['TTL'] = self.data['IPv4']['ipv4Header'][5]
        self.data['IPv4']['protocol'] = self.data['IPv4']['ipv4Header'][6]
        self.data['IPv4']['checksum'] = self.data['IPv4']['ipv4Header'][7]
        self.data['IPv4']['srcIP'] = self.data['IPv4']['ipv4Header'][8]
        self.data['IPv4']['destIP'] = self.data['IPv4']['ipv4Header'][9]
        optionsLength = 0
        if self.data['IPv4']['HL'] > 5: 
            optionsLength = (self.data['IPv4']['HL'] - 5) * 4
        self.data['IPv4']['options'] = payload[20:][:optionsLength]
        self.data['IPv4']['payload'] = payload[20:][optionsLength:]

        # Options

        # Prettify
        self.pretty['IPv4'] = {}
        self.pretty['IPv4']['Version'] = str(self.data['IPv4']['version'])
        self.pretty['IPv4']['Header Length'] = '{} bytes ({})'.format(int((int(self.data['IPv4']['HL'])*32)/8),int(self.data['IPv4']['HL']))
        self.pretty['IPv4']['TOS'] = str(self.data['IPv4']['TOS'])
        self.pretty['IPv4']['Total Length'] = int(self.data['IPv4']['totalLength'])
        self.pretty['IPv4']['Identification'] = str(self.data['IPv4']['identification'])
        self.pretty['IPv4']['TTL'] = int(self.data['IPv4']['TTL'])
        if self.data['IPv4']['protocol'] in protocols:
            self.pretty['IPv4']['Protocol'] = protocols[self.data['IPv4']['protocol']]
        else:
            self.pretty['IPv4']['Protocol'] = 'Unknown'
        self.pretty['IPv4']['Checksum'] = str(self.data['IPv4']['checksum'])
        self.pretty['IPv4']['Source IP'] = socket.inet_ntop(socket.AF_INET,self.data['IPv4']['srcIP'])
        self.pretty['IPv4']['Destination IP'] = socket.inet_ntop(socket.AF_INET,self.data['IPv4']['destIP'])

        self.tableSrc = self.pretty['IPv4']['Source IP']
        self.tableDest = self.pretty['IPv4']['Destination IP']
        if self.pretty['IPv4']['Protocol'] != 'Unknown': self.tableProto = self.pretty['IPv4']['Protocol']

    def decodeTCPHeader(self,payload):
        self.data['TCP'] = {}
        self.data['TCP']['tcpHeader'] = struct.unpack('! HHIIHHHH',payload[:20])
        self.data['TCP']['srcPort'] = self.data['TCP']['tcpHeader'][0]
        self.data['TCP']['destPort'] = self.data['TCP']['tcpHeader'][1]
        self.data['TCP']['seqnum'] = self.data['TCP']['tcpHeader'][2]
        self.data['TCP']['acknum'] = self.data['TCP']['tcpHeader'][3]

        self.data['TCP']['offset'] = self.data['TCP']['tcpHeader'][4] >> 12
        self.data['TCP']['flags'] = {}
        self.data['TCP']['flags']['fin'] = bool((self.data['TCP']['tcpHeader'][4]) & 0x01)
        self.data['TCP']['flags']['syn'] = bool((self.data['TCP']['tcpHeader'][4] >> 1) & 0x01)
        self.data['TCP']['flags']['rst'] = bool((self.data['TCP']['tcpHeader'][4] >> 2) & 0x01)
        self.data['TCP']['flags']['psh'] = bool((self.data['TCP']['tcpHeader'][4] >> 3) & 0x01)
        self.data['TCP']['flags']['ack'] = bool((self.data['TCP']['tcpHeader'][4] >> 4) & 0x01)
        self.data['TCP']['flags']['urg'] = bool((self.data['TCP']['tcpHeader'][4] >> 5) & 0x01)
        self.data['TCP']['flags']['ece'] = bool((self.data['TCP']['tcpHeader'][4] >> 6) & 0x01)
        self.data['TCP']['flags']['cwr'] = bool((self.data['TCP']['tcpHeader'][4] >> 7) & 0x01)
        self.data['TCP']['flags']['ns'] = bool((self.data['TCP']['tcpHeader'][4] >> 7) & 0x01)
        self.data['TCP']['activeFlags'] = []
        for key in self.data['TCP']['flags']:
            if self.data['TCP']['flags'][key]:
                self.data['TCP']['activeFlags'].append(key.upper())

        self.data['TCP']['windowsize'] = self.data['TCP']['tcpHeader'][5]
        self.data['TCP']['checksum'] = self.data['TCP']['tcpHeader'][6]
        self.data['TCP']['urgptr'] = self.data['TCP']['tcpHeader'][7]

        optionsLength = 0
        if self.data['TCP']['offset'] > 5: 
            optionsLength = (self.data['TCP']['offset'] - 5) * 4
        self.data['TCP']['params'] = payload[20:][:optionsLength]
        self.data['TCP']['payload'] = payload[20:][optionsLength:]

        # Prettify
        self.pretty['TCP'] = {}
        self.pretty['TCP']['Source Port'] = str(self.data['TCP']['srcPort'])
        self.pretty['TCP']['Destination Port'] = str(self.data['TCP']['destPort'])
        self.pretty['TCP']['Sequence Number'] = str(self.data['TCP']['seqnum'])
        self.pretty['TCP']['Acknoledgment Number'] = str(self.data['TCP']['acknum'])

        self.pretty['TCP']['Flags'] = str(self.data['TCP']['tcpHeader'][4] & 0xFF) + ' ' + ', '.join(self.data['TCP']['activeFlags'])
        

        self.pretty['TCP']['Window Size'] = str(self.data['TCP']['windowsize'])
        self.pretty['TCP']['Checksum'] = str(self.data['TCP']['checksum'])
        self.pretty['TCP']['Urgent Pointer'] = str(self.data['TCP']['urgptr'])

        if len(self.data['TCP']['activeFlags']) > 0: self.info = self.info + '[' + ', '.join(self.data['TCP']['activeFlags']) + ']'


    def decodeUDPHeader(self,payload):
        self.data['UDP'] = {}
        self.data['UDP']['udpHeader'] = struct.unpack('! HHHH',payload[:8])
        self.data['UDP']['srcPort'] = self.data['UDP']['udpHeader'][0]
        self.data['UDP']['destPort'] = self.data['UDP']['udpHeader'][1]
        self.data['UDP']['len'] = self.data['UDP']['udpHeader'][2]
        self.data['UDP']['checksum'] = self.data['UDP']['udpHeader'][3]
        self.data['UDP']['payload'] = payload[8:]

        # Prettify
        self.pretty['UDP'] = {}
        self.pretty['UDP']['Source Port'] = str(self.data['UDP']['srcPort'])
        self.pretty['UDP']['Destination Port'] = str(self.data['UDP']['destPort'])
        self.pretty['UDP']['Length'] = str(self.data['UDP']['len'])



    def craftPacket(self):
        pass

class Sniffer():
    # DO NOT TOUCH INIT
    def __init__(self):
        self.thread1 = None
        self.stop_threads = Event()

    def sniff(self):
        global id
        global filtering
        global currentQuery
        
        while not self.stop_threads.is_set():
            capturedRaw = s.recv(65535)  
            capturedPacket = Packet(action='decode',raw=capturedRaw,time=datetime.datetime.now(),id=id)
            capturedPackets.append(capturedPacket)             

            # Only do if matches filtering conditions
            print(filtering)
            if filtering == False:
                table.insert(parent='',index=tk.END,values=(capturedPacket.id, capturedPacket.time.strftime('%H:%M:%S'), capturedPacket.tableSrc, capturedPacket.tableDest, capturedPacket.tableProto,capturedPacket.info))
            elif filtering == True:
                if eval(filter(currentQuery,capturedPacket.pretty)) == True:
                    table.insert(parent='',index=tk.END,values=(capturedPacket.id, capturedPacket.time.strftime('%H:%M:%S'), capturedPacket.tableSrc, capturedPacket.tableDest, capturedPacket.tableProto,capturedPacket.info))
            id += 1

    # DO NOT TOUCH startSniffing and stopSniffing
    def startSniffing(self):
        self.stop_threads.clear()
        self.thread1 = Thread(target = self.sniff, daemon=True)
        self.thread1.start()
        menuBar.entryconfig('Start', state='disabled')
        menuBar.entryconfig('Stop', state='active')

    def stopSniffing(self):
        self.stop_threads.set()
        # self.thread1.join()
        self.thread1 = None
        menuBar.entryconfig('Stop', state='disabled')
        menuBar.entryconfig('Start', state='active')

def filter(query,dict):
    def evaluteExp(exp):
        lhs = ''
        rhs = ''
        if '==' in exp:
            try:
                lhs,rhs = exp.split('==')
                lhs = lhs.strip().split('_')
                layerCount = len(lhs)
                newlhs = dict[lhs[0]]
                
                if layerCount > 1:
                    for i in range(1,layerCount,1):
                        newlhs = newlhs[lhs[i]]
                if str(newlhs) == rhs.strip():
                    return 'True'
                else:
                    return 'False'
            except:
                return 'False'
        elif 'in' in exp:
            try:
                lhs,rhs = exp.split('in')
                rhs = rhs.strip().split('_')
                layerCount = len(rhs)
                newrhs = dict[rhs[0]]
                if layerCount > 1:
                    for i in range(1,layerCount,1):
                        newrhs = newrhs[rhs[i]]
                if lhs.strip() in str(newrhs):
                    return 'True'
                else:
                    return 'False'
            except:
                return 'False'
        else:
            return str(eval(exp))

    numRBrac = query.count('(')
    numLBrac = query.count(')')
    if numRBrac != numLBrac:
        return 'Error: Unequal brackets'
    if numRBrac == 0:
        if query.count('and') + query.count('or') > 1:
            return "Expression error"
        elif 'and' in query:
            splitExp = query.split('and')
            return str(eval(evaluteExp(splitExp[0].strip()) + ' and ' + evaluteExp(splitExp[1].strip())))
        elif 'or' in query:
            splitExp = query.split('or')
            return str(eval(evaluteExp(splitExp[0].strip()) + ' or ' + evaluteExp(splitExp[1].strip())))
        else:
            return evaluteExp(query)
            
    
    oglen = len(query)
    for i in range(oglen):
        if query[i] == '(':
            for j in range(i+1,len(query),1):
                if query[j] == ')':
                    numLBrac -= 1
                    numRBrac -= 1
                    # check the condition
                    currentExp = query[i+1:j]
                    if currentExp.count('and') + currentExp.count('or') > 1:
                        i = oglen + 10
                        break
                    elif 'and' in currentExp:
                        splitExp = currentExp.split('and')
                        query = query[:i] + str(eval(evaluteExp(splitExp[0].strip()) + ' and ' + evaluteExp(splitExp[1].strip()))) + query[j+1:]
                        i = oglen + 10
                        break
                    elif 'or' in currentExp:
                        splitExp = currentExp.split('or')
                        query = query[:i] + str(eval(evaluteExp(splitExp[0].strip()) + ' or ' + evaluteExp(splitExp[1].strip()))) + query[j+1:]
                        i = oglen + 10
                        break
                    else:
                        query = query[:i] + evaluteExp(currentExp.strip()) + query[j+1:]
                        i = oglen + 10
                        break
                elif query[j] == '(':
                    break
        if i > oglen:
            break
    query = filter(query,dict)
    return evaluteExp(query)

def filterView():
    global filtering
    global currentQuery
    currentQuery = filterEntryVar.get()
    table.delete(*table.get_children())
    if filterEntryVar.get().strip() != '':
        filtering = True
        for i in capturedPackets:
            if eval(filter(currentQuery,i.pretty)) == True:
                table.insert(parent='',index=tk.END,values=(i.id, i.time.strftime('%H:%M:%S'), i.tableSrc, i.tableDest, i.tableProto,i.info))
    else:
        filtering = False
        for i in capturedPackets:
            table.insert(parent='',index=tk.END,values=(i.id, i.time.strftime('%H:%M:%S'), i.tableSrc, i.tableDest, i.tableProto,i.info))

def displayDetails(id):
    # Display Packet Info
    for item in packetInfoTree.get_children():
        packetInfoTree.delete(item)

    for layer in capturedPackets[int(id)-1].layers:
        item = packetInfoTree.insert('',tk.END,text=layer)
        for info in capturedPackets[int(id)-1].pretty[layer]:
            packetInfoTree.insert(item,tk.END,text='{}: {}'.format(info, capturedPackets[int(id)-1].pretty[layer][info]))



    # Display raw packet
    packetRawText.config(state='normal')
    packetRawText.delete('1.0', tk.END)
    packetRawText.insert(tk.INSERT,capturedPackets[int(id)-1].prettyRaw)
    packetRawText.config(state='disabled')

    # Display Ascii
    packetAsciiText.config(state='normal')
    packetAsciiText.delete('1.0', tk.END)
    packetAsciiText.insert(tk.INSERT,capturedPackets[int(id)-1].prettyAscii)
    packetAsciiText.config(state='disabled')



def OnDoubleClick(event):
    item = table.selection()
    displayDetails(table.item(item[0], "values")[0])

# Variables
windowWidth = 1000
windowHeight = 600
capturedPackets = []
id = 1
sniffer = Sniffer()

# Socket
s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003)) 

# window 
window = tk.Tk()
window.title('Sniffer')
window.geometry('{}x{}'.format(windowWidth,windowHeight))   

# Menu bar
menuBar = tk.Menu(window)
menuBar.add_command(label='Start',command=sniffer.startSniffing, foreground='green')
menuBar.add_command(label='Stop',command=sniffer.stopSniffing, foreground='red')
window.config(menu=menuBar)

# Filter bar
filterEntryVar = tk.StringVar()
filterFrame = ttk.Frame()
filterEntry = ttk.Entry(master=filterFrame,textvariable = filterEntryVar)
filterButton = ttk.Button(master=filterFrame,text='Filter',command=filterView)
filterButton.grid(row=0,column=9,columnspan=1,sticky='nsew')
filterEntry.grid(row=0,column=0,columnspan=9,sticky='nsew')
for i in range(10):
    filterFrame.grid_columnconfigure(i, weight=1, uniform="foo")
filterFrame.grid_rowconfigure(0, weight=1, uniform="foo")
filterFrame.grid(row=0,column=0,columnspan=4,sticky='nsew',padx=2,pady=2)


# Table
tableFrame = ttk.Frame(window)
table = ttk.Treeview(master=tableFrame, columns=('ID','Time', 'Source', 'Destination', 'Protocol', 'Info'),show='headings')
table.heading('ID',text='ID')
table.heading('Time',text='Time')
table.heading('Source',text='Source')
table.heading('Destination',text='Destination')
table.heading('Protocol',text='Protocol')
table.heading('Info',text='Info')
table.column("ID", width=int(windowWidth*0.06))
table.column("Time" ,width=int(windowWidth*0.07))
table.column("Source", width=int(windowWidth*0.15))
table.column("Destination", width=int(windowWidth*0.15))
table.column("Protocol", width=int(windowWidth*0.07))
table.column("Info", width=int(windowWidth*0.5))
table.bind("<Double-1>", OnDoubleClick)
verscrlbar = ttk.Scrollbar(tableFrame,orient ="vertical", command = table.yview)
# style = ttk.Style()
# style.configure("Vertical.TScrollbar", background="blue")
table.configure(yscrollcommand = verscrlbar.set)
verscrlbar.pack(side ='right', fill ='y')
table.pack(fill='y',side='left')
tableFrame.grid(row=1,column=0,columnspan=4,sticky='nsew')



# Packet Info
packetInfoTree = ttk.Treeview(master=window,show='tree')
packetInfoTree.grid(row=2,column=0,columnspan=2,sticky='nsew')

# Raw 
packetRawText = tk.Text(master=window,wrap = tk.WORD,foreground='black')
packetRawText.grid(row=2,column=2,columnspan=1,sticky='nsew')
packetRawText.config(state='disabled')

# Ascii
packetAsciiText = tk.Text(master=window,wrap = tk.WORD,foreground='black')
packetAsciiText.grid(row=2,column=3,columnspan=1,sticky='nsew')
packetAsciiText.config(state='disabled')


# Configure grid
for i in range(4):
    window.grid_columnconfigure(i, weight=1, uniform="foo")
window.grid_rowconfigure(0, weight=1, uniform="foo")
window.grid_rowconfigure(1, weight=10, uniform="foo")
window.grid_rowconfigure(2, weight=10, uniform="foo")


# run
window.mainloop()