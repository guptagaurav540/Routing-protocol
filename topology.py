
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import copy
import re
import mysql.connector
from ryu.topology.api import get_switch, get_link
import copy

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        try:
            mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="SDN"
            )
            mycursor=mydb.cursor()
            sql1="CREATE TABLE IF NOT EXISTS topotable (s1 VARCHAR(20),s1_p VARCHAR(20),s2 VARCHAR(20),s2_p VARCHAR(20) );"
            
            mycursor.execute(sql1)
            mydb.commit()
            
        finally:
            if mydb.is_connected():    
                mycursor.close()
                mydb.close()
        
       
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


# Switches topology information stored in database topotable(Table Name)
#iiiiiiiii

    @set_ev_cls(ofp_event.EventSwitchEnter)
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
            print("Switch with dpid "+str(res[0])+ " having port no "+str(res[1])+" connected to switch dpid "+str(res[2])+" having port no "+str(res[3]) )
                
            
            sql="INSERT INTO topotable(s1,s1_p,s2,s2_p) VALUES ('%s','%s','%s','%s');"%(str(res[0]),str(res[1]),str(res[2]),str(res[3]))
            mycursor.execute(sql)
            mydb.commit()
    

    @set_ev_cls(ofp_event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        match = re.match(r'(EventSwitchLeave<dpid=)(\d+)(, \d+ ports>)', str(ev))
        id = match.group(2)
        


        try:
            mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="SDN"
            )
            mycursor=mydb.cursor()
            sql3 ="DELETE FROM topotable WHERE s1="+id+" OR s2="+id+";"
            mycursor.execute(sql3)
            
            mydb.commit()
            self.logger.info("Switch %s removed and database deleted succesfully",id)
        
            
        finally:
            if mydb.is_connected():    
                mycursor.close()
                mydb.close()






