'''
create switch table 
take 5 flow add, remove time 
calculate average 
create database of topology
create database of end points( end devices connected with which switches )(mapping
of end devices IP address with switch dpid )
Take bandwidth information (mandeep)
create a distance table using bandwitch+delay
apply diskatra when  a flow entry will come 
insert flow entry whenever new packet will come to switch
remove tables when switch disconnected 

'''

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
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        switch_name=str("switch")+str(datapath.id)
        global flowcount
        switch_id=str(datapath.id)
        
        if switch_id in flowcount:
            #self.logger.log("Switch %s is already in dictionary",switch_id)
            a=1
        else:
            flowcount[switch_id]=0
        
        #self.logger.info("%s",flowcount)
        
        global flag
        switch_id=datapath.id
        if switch_id in flag:
            a=1
            #self.logger.log("Switch is already in dictionary", msg)
        else:
            flag[int(switch_id)]=0
        
        
        try:
            mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="SDN"
            )
            mycursor=mydb.cursor()
            sql="CREATE TABLE IF NOT EXISTS "+switch_name+ """( id varchar(50),entry_time varchar(50), remove_time varchar(50), difference varchar(50))""" ;
            sql1="CREATE TABLE IF NOT EXISTS DELAY_TABLE (id VARCHAR(20),delay VARCHAR(50) );"
            sql2="INSERT INTO DELAY_TABLE (id,delay) values ('%s',NULL);"%(switch_name)
            sql1="CREATE TABLE IF NOT EXISTS topotable (s1 VARCHAR(20),s1_p VARCHAR(20),s2 VARCHAR(20),s2_p VARCHAR(20) );"
            
            mycursor.execute(sql1)
            mycursor.execute(sql2)
            mycursor.execute(sql)
            mydb.commit()
            self.logger.info("Table %s created succesfully in the database",switch_name)
            
        finally:
            if mydb.is_connected():    
                mycursor.close()
                mydb.close()
        
        self.add_flow(datapath, 0, match, actions)
        self.add_flow2(datapath, 0, match, actions,ev)
        self._monitor(ev)

        
    #Normal add flow
    def add_flow(self, datapath, priority, match, actions ,buffer_id=None):
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
        
    # use for extract the flow packets which is used for calculate the time stamp of switch
    #   
    def add_flow2(self, datapath, priority, match, actions,ev, buffer_id=None):
        #self.logger.info("Xid->%s",ev.msg.xid)
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        match = parser.OFPMatch(eth_dst='33:33:33:33:33:33', eth_src='22:22:22:22:22:22')
        mod = parser.OFPFlowMod(command=0x0000,datapath=datapath, priority=priority,
                                    match=match, instructions=inst,hard_timeout=flow_remove_time,flags=0x0001)
        SwitchId=datapath.id
        flowAddTime=time.time()
        datapath.send_msg(mod)    
        global flowcount
        #self.logger.info("Dummy Flow entry Added at switch %s at time %s ",SwitchId,flowAddTime)
        
        switch_id=str(datapath.id)
        flowcount[switch_id]=(flowcount[switch_id])%5
        switch_id1='switch'+switch_id
        #self.logger.info(flowcount)
        #if enry not exist then Insert in database id flowentry flowremove=NULL time otherwise update database 
        cnxn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="SDN"
        )
        in_time=str(flowAddTime)
        crsr = cnxn.cursor()

        crsr.execute("SELECT entry_time FROM "+switch_id1+";")
        records= crsr.fetchall()
        counter=len(records)
        #print("Total rows are: ",counter)

        if counter==0 or counter<5:
            #insert into the table
            crsr.execute("INSERT INTO "+switch_id1+" (id,entry_time,remove_time) VALUES ('%s','%s','%s');"%(str(flowcount[switch_id]),in_time,'-1'))
            cnxn.commit()
        elif counter==5:
          #delete the first row and insert a new entry in the table
            crsr.execute("UPDATE "+switch_id1+" SET entry_time = '%s', remove_time= -1 WHERE id = '%s';"%(in_time,str(flowcount[switch_id])))
            #crsr.execute(sql_Update_query)
            cnxn.commit()
    
            crsr.execute("SELECT entry_time FROM "+switch_id1+";")
            records= crsr.fetchall()
            counter=len(records)
        #    print("Total rows after updation: ",counter)
        


    
    #flow remove message use for calculating the time stamp of the switch 
    #  
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match_field=parser.OFPMatch()


        match = parser.OFPMatch()
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        
        
        if(msg.match['eth_dst']=='33:33:33:33:33:33' and msg.match['eth_src']=='22:22:22:22:22:22'):
            
            SwitchId=dp.id
            flowRemoveReciveTime=time.time()
            #self.logger.info("Dummy flow entry removed from switch %s at time %s",SwitchId,flowRemoveReciveTime)            
            global flowcount
            switch_id=str(dp.id)
            switch_id1='switch'+str(switch_id)
            
            #update database add flow remove time
            
            try:
                mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SDN"
                )
                mycursor=mydb.cursor()
                remove_time=str(flowRemoveReciveTime)
                sql="UPDATE "+switch_id1+" SET remove_time= '%s' WHERE id = '%s';"%(remove_time,str(flowcount[switch_id]))
                mycursor.execute(sql)
                mydb.commit()
                #self.logger.info("flow Remove database update succesfully %s",str(flowcount[switch_id]))
                flowcount[switch_id]=(flowcount[switch_id]+1)%5
        
            finally:
                if mydb.is_connected():    
                    mycursor.close()
                    mydb.close()
                #    self.logger.info("Mysql connection is closed")

            self.add_flow2(dp, 0, match, actions,ev)
            self._monitor(ev)

          



#    when switch will remove it used for deleting the tables 

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        match = re.match(r'(EventSwitchLeave<dpid=)(\d+)(, \d+ ports>)', str(ev))
        first_id = match.group(1)
        id = match.group(2)
        second_id = match.group(3)
        switchid='switch'+str(id)
        global flag
        flag.pop(int(id))



        try:
            mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="SDN"
            )
            mycursor=mydb.cursor()
            sql="DROP TABLE IF EXISTS "+switchid +";"
            sql2="DELETE FROM DELAY_TABLE WHERE id='%s';"%(switchid)
            sql3 ="DELETE FROM topotable WHERE s1="+id+" OR s2="+id+";"
            sql4="DELETE FROM BAND_TABLE WHERE sid='%s';"%(id)
            mycursor.execute(sql)
            mycursor.execute(sql2)
            mycursor.execute(sql3)
            mycursor.execute(sql4)

            mydb.commit()
            self.logger.info("Switch %s removed and database deleted succesfully",id)
        
            
        finally:
            if mydb.is_connected():    
                mycursor.close()
                mydb.close()


# Switches topology information stored in database topotable(Table Name) 

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.topo_raw_links = copy.copy(get_link(self, None))

        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """
        #self.logger.info(topo_raw_switches)
        #print(" \t" + "Current Links:")
        mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="SDN"
        )
        mycursor=mydb.cursor()
            
        for l in self.topo_raw_links:
            #self.logger.info("%s",l)
            temp = re.findall(r'\d+', str(l))
            res = list(map(int, temp))
    #        print("Switch with dpid "+str(res[0])+ " having port no "+str(res[1])+" connected to switch dpid "+str(res[2])+" having port no "+str(res[3]) )
                
            
            sql="INSERT INTO topotable(s1,s1_p,s2,s2_p) VALUES ('%s','%s','%s','%s');"%(str(res[0]),str(res[1]),str(res[2]),str(res[3]))
            mycursor.execute(sql)
            mydb.commit()
    









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
        dst = pkt_eth.dst
        src = pkt_eth.src
    
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
        self.logger.info("protocol[-1 is %s",pay_load)
        p.add_protocol(tcp_pkt)
        if(pay_load!=tcp_pkt):
            print('pay  load ->')
            print(pay_load)
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
                    self.logger.info("Original data\n %s\n\n",pkt)
                    self.logger.info("TCP packet arrive at Destination switch %s with identification_no %s src_ip %s dst_ip %s eth_src %s eth_dst %s and forwarded to port %s\n",dest_id,pkt_ipv4.identification,src_ip,dst_ip,src,dst,out_port)
                    mod_ipv4=self.modify_ipv4(fack_mac,self.host_ip[source_id][dst_ip]['src'],pkt_ipv4,pkt_tcp,pkt)				
                    self.logger.info("Packet ethernet Header Modified and sent to destination_host %s:\n",dst_ip)
                    print('modified packet ')
                    print(mod_ipv4)
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
        graph=self.graph_calculation()
        ##print(graph)
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
        #source_id=1
        #dest_id=2
        
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
    







#       Bandwidth program


    def _monitor(self,ev):
        dp = ev.msg.datapath
        #self.logger.info("Monitor called for switch %s requst send",dp.id)
        self._request_stats(dp)
    

            
    def _request_stats(self, datapath):
        #self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    
  

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        switch_id=ev.msg.datapath.id
        body = ev.msg.body
        global flag
        
        mydb = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="SDN")
        mycursor0=mydb.cursor()
        sql0="CREATE TABLE IF NOT EXISTS BAND_TABLE (sid VARCHAR(20),tx1 VARCHAR(50), tx1_entry_time VARCHAR(50), tx2 VARCHAR(50), tx2_entry_time VARCHAR(50),port VARCHAR(20),total VARCHAR(50),diff_tx VARCHAR(50),per_unit VARCHAR(50));"
        mycursor0.execute(sql0)
        mydb.commit()


        global flag
        if flag[int(switch_id)]==0:
            for stat in sorted(body, key=attrgetter('port_no')):
                
                tx1= str(stat.tx_bytes)
                port=int(stat.port_no)
                sid=str(ev.msg.datapath.id)
                if( port<100):

                    mydb1 = mysql.connector.connect(
                            host="localhost",
                            user="root",
                            password="",
                            database="SDN")
                    mycursor=mydb1.cursor()

                    port=str(port)
                    count_query= "SELECT * from BAND_TABLE where sid="+sid+" and port="+port+";"
                    mycursor.execute(count_query)
                    records1= mycursor.fetchall()
                    count= len(records1)
                    
                    if count==0:
                        tx1AddTime=int(time.time())
                        tx1_time=str(tx1AddTime)
                        mycursor.execute("INSERT INTO BAND_TABLE (sid,tx1,tx1_entry_time,port) values (%s, %s, %s, %s)"%(sid,tx1,tx1_time,port))
                        #self.logger.info("FLAG 0 BAND_TABLE Inserted for switch %s port %s recived byte %s at time %s",sid,port,tx1,tx1_time)
                    elif count>=1:
                        tx1AddTime=int(time.time())
                        tx1_time=str(tx1AddTime)
                        mycursor.execute("UPDATE BAND_TABLE SET tx1='%s',tx1_entry_time='%s' where sid='%s' and port='%s';"%(tx1,tx1_time,sid,port))
                        #self.logger.info("FLAG 0 BAND_TABLE updated for switch %s port %s recived byte %s at time %s",sid,port,tx1,tx1_time)
                    
                    mydb1.commit()
                   

            flag[int(switch_id)]=1
            return
        else:
            for stat in sorted(body, key=attrgetter('port_no')):
                tx2= str(stat.tx_bytes)
                port=int(stat.port_no)
                sid=str(ev.msg.datapath.id)
                tx2AddTime=int(time.time())
                tx2_time=str(tx2AddTime)
                if(port<100):
                    port=str(port)
                    mydb2= mysql.connector.connect(
                            host="localhost",
                            user="root",
                            password="",
                            database="SDN")
                    crsr = mydb2.cursor()
                    sql1="SELECT tx1_entry_time,tx1 from BAND_TABLE where sid="+sid+" and port="+port+";"
                    crsr.execute(sql1)
                    
                    tx1data=crsr.fetchall()
                    
                    
                    
                    tx1AddTime=int(tx1data[0][0])
                    tx1=int(tx1data[0][1])
                    
                    total_time=str(int(tx2AddTime)-tx1AddTime)
                    tx_diff=str(int(tx2)-int(tx1))
                    

                    mydb1 = mysql.connector.connect(
                                host="localhost",
                                user="root",
                                password="",
                                database="SDN")
                    mycursor=mydb1.cursor()
                    per_unit=str(int(tx_diff)/int(total_time))                
                    mycursor.execute("UPDATE BAND_TABLE SET tx2='%s',tx2_entry_time='%s',total='%s',diff_tx='%s',per_unit='%s' where sid='%s' and port='%s';"%(tx2,tx2_time,total_time,tx_diff,per_unit,sid,port))
                    mydb1.commit()
                    #self.logger.info("FLAG 1 BAND_TABLE updated for switch %s port %s recived byte %s at time %s",sid,port,tx2,tx2_time)
                            
            flag[int(switch_id)]=0
            
            return









