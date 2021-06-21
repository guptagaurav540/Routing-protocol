from typing import Sized
from mysql.connector.catch23 import INT_TYPES
from mysql.connector.errors import DatabaseError
from netaddr import fbsocket

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import time
import mysql.connector
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import copy
import re
import logging
import array
import netaddr
from ryu.lib import hub
from operator import attrgetter

flow_remove_time=0x12

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global flowcount
    
    global flag 
    flag={}
    
    
    flowcount={}
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
       
    
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
        self.logger.info("Dummy Flow entry Added at switch %s at time %s ",SwitchId,flowAddTime)
        
        switch_id=str(datapath.id)
        flowcount[switch_id]=(flowcount[switch_id])%5
        switch_id1='switch'+switch_id
        self.logger.info(flowcount)
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
            self.logger.info("Dummy flow entry removed from switch %s at time %s",SwitchId,flowRemoveReciveTime)            
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
            sql4="DELETE FROM BAND_TABLE WHERE sid='%s';"%(id)
            mycursor.execute(sql)
            mycursor.execute(sql2)
            mycursor.execute(sql4)

            mydb.commit()
            self.logger.info("Switch %s removed and database deleted succesfully",id)
        
            
        finally:
            if mydb.is_connected():    
                mycursor.close()
                mydb.close()



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






