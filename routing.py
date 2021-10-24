from typing import Sized
from mysql.connector.catch23 import INT_TYPES
from mysql.connector.errors import DatabaseError
from netaddr import fbsocket

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import time
from ryu.ofproto import ether
from ryu.ofproto import inet
import mysql.connector
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.controller import handler
from ryu.lib import dpid as dpid_lib
from ryu.controller import dpset
from ryu.lib import mac
from collections import defaultdict
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import copy
import re
import logging
import array
import netaddr
from ryu.lib import hub
from operator import attrgetter
from ryu.app import simple_switch_13


flow_remove_time=0x12
max=5555
global fack_mac
default_band=2048
fack_mac='fe:ee:ee:ee:ee:ef'
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global flowcount
    BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

    global flag 
    flag={}
    
    
    flowcount={}
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.host_ip= {}
    
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #aaandjd
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)



    def graph_calculation(self):
        mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SDN")

        mycursor=mydb.cursor()
        mycursor0=mydb.cursor()

        sql0= "SELECT COUNT(id) FROM DELAY_TABLE"
        mycursor0.execute(sql0)
        m=mycursor0.fetchall()
        matrix_size=m[0][0]
        rows, cols = (matrix_size+1, matrix_size+1)

        matrix = [[0 for i in range(cols)] for j in range(rows)]

        sql="SELECT s1,s2 FROM topotable;"

        mycursor.execute(sql)
        connection=mycursor.fetchall()
        for element in connection:

            source_id=element[0]
            next_hop=element[1]
            source='switch'+element[0]
            dest='switch'+element[1]
            
            mydb1 = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SDN")
            mycursor1=mydb1.cursor()
            
            sql1="SELECT delay FROM DELAY_TABLE WHERE id='%s';"%(source)
            sql2="SELECT delay FROM DELAY_TABLE WHERE id='%s';"%(dest)
            
            sql3="SELECT s1_p FROM topotable WHERE s1= '%s' AND s2= '%s' ;"%(str(source_id),str(next_hop))
            mycursor1.execute(sql3)
            out_port_=mycursor1.fetchall()
            out_port=int(out_port_[0][0])
            sql4="SELECT per_unit FROM BAND_TABLE WHERE sid='%s' AND port ='%s';"%(str(source_id),str(out_port))
            mycursor1.execute(sql4)
            use_band_=mycursor1.fetchall()
            use_band=int(use_band_[0][0])
            band=default_band-int(use_band)

            
            
            
            
            mycursor1.execute(sql1)
            s_w=mycursor1.fetchall()
            source_weight=float(str(s_w[0][0]))
            mycursor1.execute(sql2)
            d_w=mycursor1.fetchall()
            dest_weight=float(d_w[0][0])
            source_switch=int(element[0])
            dest_switch=int(element[1])
            matrix[source_switch][dest_switch]=(source_weight+dest_weight-(2*flow_remove_time))*100+use_band
            

        graph = [[max for i in range(cols)] for j in range(rows)]	
        for i in range(0,rows):
            for j in range (0,cols):
                if(matrix[i][j]>0):
                    graph[i][j]=matrix[i][j]

        return graph







    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                            ev.msg.msg_len, ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        
        source_id=datapath.id
        port=datapath.ofproto
        pkt = packet.Packet(data=msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
        pkt_tcp=pkt.get_protocol(tcp.tcp)
        
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
    
    
        self.mac_to_port.setdefault(source_id, {})
        self.host_ip.setdefault(source_id,{})
        
        pkt = packet.Packet(msg.data)
        pkt_arp=pkt.get_protocol(arp.arp)
        
        
        if pkt_arp:
            print('********************************************************')
            self.handle_arp2(ev)
            print('********************************************************')	
            return
        
        if pkt_ipv4 :
            print('********************************************************')
            self.handle_ipv4_packet(ev)
            print('********************************************************')
            return
        
            
            


            
    def handle_arp2(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        source_id=int(datapath.id)
        ofproto=datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        
        pkt_arp=pkt.get_protocol(arp.arp)
        dst_ip=str(pkt_arp.dst_ip)
        src_ip=str(pkt_arp.src_ip)
        
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
#		print('arp packet recived with src '+src+'and dst'+dst)
        self.host_ip.setdefault(source_id,{})
        self.host_ip[source_id][src_ip]={'src':src,'port':in_port}
        
        #ARP TABLE SWITCHID	|	IP	|	MAC OF HOST
        global fack_mac
        if pkt_arp.opcode == arp.ARP_REQUEST:
        
            if(src!=fack_mac):
                
                self.logger.info("Arp Request arrived at switch %s with src_ip %s dst_ip %s src_mac %s dst_mac %s",source_id,str(src_ip),str(dst_ip),str(src),str(dst))

                data=self.arp_reply(ev,pkt_arp,eth)
                out_port=in_port
                #actions = [parser.OFPActionOutput(out_port)]
                #match = parser.OFPMatch(in_port=in_port, eth_dst=src)
                #self.add_flow(datapath, 1, match=match, actions=actions)
                
                self._send_packet(datapath, in_port, data)
                self.logger.info("Fake Arp reply Created and sent through out port %s\n",str(in_port))				
        if pkt_arp.opcode==arp.ARP_REPLY:
            self.logger.info("Arp Reply arrived at switch %s with src_ip %s dst_ip %s src_mac %s dst_mac %s\n",source_id,str(src_ip),str(dst_ip),str(src),str(dst))


    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
    
    def arp_reply(self,ev,pkt_arp,eth):
        p = self.build_arp(arp.ARP_REPLY,pkt_arp,eth)
        return p
        
    def arp_request(self,pkt,eth):
        p = self.build_arp(arp.ARP_REQUEST,pkt,eth)
        return p

    def build_arp(self, opcode,pkt_arp,eth):
        global fack_mac

        if opcode == arp.ARP_REQUEST:
            dst_mac = self.BROADCAST_MAC
            src_mac = fack_mac
        elif opcode == arp.ARP_REPLY:
            dst_mac = eth.src
            src_mac = fack_mac

        e = ethernet.ethernet(dst =dst_mac , src = src_mac,
                                ethertype = ether.ETH_TYPE_ARP)
        if opcode==arp.ARP_REPLY:
            a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                    opcode=opcode, src_mac=src_mac, src_ip=pkt_arp.dst_ip,
                    dst_mac=dst_mac, dst_ip=pkt_arp.src_ip)
        if opcode==arp.ARP_REQUEST:
            a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                    opcode=opcode, src_mac=src_mac, src_ip=pkt_arp.src,
                    dst_mac=dst_mac, dst_ip=pkt_arp.dst)
        
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        
        return p
    def modify_ipv4(self,eth_src,eth_dst,ip_pkt,tcp_pkt,pkt):
        e = ethernet.ethernet(dst =eth_dst , src = eth_src,
                                ethertype = 0x800)
        p=packet.Packet()
        pay_load=pkt.protocols[-1]
        p.add_protocol(e)
        p.add_protocol(ip_pkt)
        p.add_protocol(tcp_pkt)
        if(pay_load!=tcp_pkt):
            p.add_protocol(pay_load)
        
        p.serialize()
        return p
        

    def add_flow3(self, datapath, priority, match, actions ,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath,cookie=1,command=ofproto.OFPFC_ADD,
                                    priority=priority, match=match,idle_timeout=100,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(cookie=1,command=0x0000,datapath=datapath, priority=priority,idle_timeout=100,
                                    match=match, instructions=inst)
        
        datapath.send_msg(mod)





    def handle_ipv4_packet(self,ev):
        
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        source_id=int(datapath.id)
        ofproto=datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        src=pkt_ethernet.src
        dst=pkt_ethernet.dst
        pkt = packet.Packet(msg.data)
        pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
        pkt_tcp=pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            dst_ip=str(pkt_ipv4.dst)
            src_ip=str(pkt_ipv4.src)
            self.logger.info("IPv4 and TCP packet arravide at switch %s with identification_no %s src_ip %s dst_ip %s eth_src %s eth_dst %s\n",source_id,pkt_ipv4.identification,src_ip,dst_ip,src,dst)
            dest_id=int(self.destination_id(dst_ip))
            if(int(source_id)==dest_id):
                if dst_ip in self.host_ip[dest_id]:
                    out_port=int(self.host_ip[dest_id][dst_ip]['port'])
                    next_switch=str('self')
                    self.logger.info("TCP packet arrive at Destination switch %s with identification_no %s src_ip %s dst_ip %s eth_src %s eth_dst %s and forwarded to port %s\n",dest_id,pkt_ipv4.identification,src_ip,dst_ip,src,dst,out_port)
                    mod_ipv4=self.modify_ipv4(fack_mac,self.host_ip[source_id][dst_ip]['src'],pkt_ipv4,pkt_tcp,pkt)				
                    self.logger.info("Packet ethernet Header Modified and sent to destination_host %s:\n",dst_ip)
                    self._send_packet(datapath, out_port, mod_ipv4)
                    return
                
                else:
                    self.logger.info("TCP packet arrive at Destination switch %s with identification_no %s src_ip %s dst_ip %s eth_src %s eth_dst %s Arp request sent to destination host %s for port and mac:\n",dest_id,pkt_ipv4.identification,src_ip,dst_ip,src,dst,dst_ip)
                    data=self.arp_request(pkt_ipv4,pkt_ethernet)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=in_port, actions=actions, data=data.data)
                    datapath.send_msg(out)
                    print('********************************************************')
            
                    return					
            else:
                
                out=self.find_next_hop_out_port(src_ip,dst_ip,source_id)
                out_port=int(out[0])
                next_switch=out[1]
                self.logger.info("Tcp packet enter at switch %s and destination switch is %s next switch %s forwarded to port %s:\n",source_id,dest_id,next_switch,out_port)
            if(out_port!=-1):
                out_port=int(out_port)
                actions=[parser.OFPActionOutput(out_port)]
                match=parser.OFPMatch(ip_proto=6,eth_type=0x0800,in_port=in_port,ipv4_dst=dst_ip)	
                self.logger.info("Tcp packet enter at switch %s and destination switch is %s and next switch %s forwarded to port %s:\n",source_id,dest_id,next_switch,out_port)
                self.add_flow3(datapath,2,match,actions)
                self.logger.info("flow entry added in switch id %s",source_id)
            else:
                self.logger.info("Tcp packet enter at switch %s and destination switch is %s No route found and packet dropped\n",source_id,dest_id)

                

        
    def destination_id(self,ip):
        mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SDN")
        crsr = mydb.cursor()
    


        sql="SELECT switch FROM HostConnection WHERE ip='%s';"%(ip)
        crsr.execute(sql)
        switch_dst_id=crsr.fetchall()
        dest_id=int(switch_dst_id[0][0])
        return dest_id
        

    def find_next_hop_out_port(self,src_ip,dst_ip,source_id):

        graph=self.graph_calculation()
        mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SDN")
        crsr = mydb.cursor()
    


        sql="SELECT switch FROM HostConnection WHERE ip='%s';"%(dst_ip)
        crsr.execute(sql)
        switch_dst_id=crsr.fetchall()
        dest_id=int(switch_dst_id[0][0])
        
        next_hop=self.dijkstra(graph,int(source_id),dest_id)
        print("next hop is %s ",next_hop)
        if(next_hop!=-1):
            sql1="SELECT s1_p FROM topotable WHERE s1= '%s' AND s2= '%s' ;"%(str(source_id),str(next_hop))
            crsr.execute(sql1)
            out_port_=crsr.fetchall()
            out_port=int(out_port_[0][0])
            return [out_port,next_hop]
        else:
            return [-1,-1]

    def minDistance(self,dist,queue):
        # Initialize min value and min_index as -1
        minimum = float("Inf")
        min_index = -1
        
        # from the dist array,pick one which
        # has min value and is till in queue
        for i in range(len(dist)):
            if dist[i] < minimum and i in queue:
                minimum = dist[i]
                min_index = i
        return min_index


    def store(self, store):
        print(store)

        
        
    def printPath(self, parent, j):
        if parent[parent[j]] == -1:
            return j
        return self.printPath(parent , parent[j])


    def printSolution(self, dist, parent,src,dest):
        
        #print("Vertex \t\tDistance from Source\t\t\t\tNext hop")
        #for i in range(1, len(dist)):
        #print(parent)
        #if(dist[dist]!=max):
            #print(parent)    
        #print("\n%d --> %d \t\t%d \t\t\t\t\t" % (src, dest, dist[dest]),end=" ")
        return(self.printPath(parent,dest))


    def dijkstra(self, graph, src, dest):

        row = len(graph)
        col = len(graph[0])

        # The output array. dist[i] will hold
        # the shortest distance from src to i
        # Initialize all distances as INFINITE
        dist = [float("Inf")] * row

        #Parent array to store
        # shortest path tree
        parent = [-1] * row

        # Distance of source vertex
        # from itself is always 0
        dist[src] = 0
    
        # Add all vertices in queue
        queue = []
        for i in range(row):
            queue.append(i)
            
        #Find shortest path for all vertices
        while queue:

            # Pick the minimum dist vertex
            # from the set of vertices
            # still in queue
            u = self.minDistance(dist,queue)

            # remove min element	
            queue.remove(u)

            # Update dist value and parent
            # index of the adjacent vertices of
            # the picked vertex. Consider only
            # those vertices which are still in
            # queue
            for i in range(col):
                if graph[u][i] and i in queue:
                    if dist[u] + graph[u][i] < dist[i]:
                        dist[i] = dist[u] + graph[u][i]
                        parent[i] = u
                        

            
        # print the constructed distance array
        x=self.printSolution(dist,parent,src,dest)
        if(dist[dest]==max):
            return -1
        return x
    





