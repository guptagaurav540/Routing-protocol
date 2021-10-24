import mysql.connector
import time
flow_remove_time=0x012

mydb = mysql.connector.connect(
		host="localhost",
		user="root",
		password="",
		database="SDN")

mycursor0=mydb.cursor()
sql0="CREATE TABLE IF NOT EXISTS DELAY_TABLE (id VARCHAR(20),delay VARCHAR(50) );"
mycursor0.execute(sql0)
mydb.commit()
mycursor=mydb.cursor()
				
		

time.sleep(15)
try:
	while 1:
		sql="SHOW TABLES"
		mycursor.execute(sql)
		for table in mycursor:
			if table[0].find("switch")!=-1:
				print(table[0],end=' ')
				
				mydb2 = mysql.connector.connect(
				host="localhost",
				user="root",
				password="",
				database="SDN")	
				cursor2= mydb2.cursor()

				intime_query= "Select entry_time from "+table[0]+";"
				outime_query= "Select remove_time from "+table[0]+";"
				
				cursor2.execute(intime_query)
				records1= cursor2.fetchall()

				cursor2.execute(outime_query)
				records2= cursor2.fetchall()

				length= len(records1)
				i=0
				
				#print("len1 ",length,"\n")
				in_timeArr= [None]*length
				out_timeArr= [None]*length
				diff_Arr= [None]*length

						
				for row in records1:
					if(i<length):
				#		print("intime= ",row)
						in_timeArr[i]=float('.'.join(str(elem) for elem in row))
						i=i+1
						
					else:
						i=0
						break
				i=0

				for row in records2:
					if(i<length):
				#		print("outime= ",row)
						out_timeArr[i]=float('.'.join(str(elem) for elem in row))
						i=i+1
						
					else:
						i=0
						break



				#for i in range(0,len(in_timeArr)):sfwsfs
				#	print("in_timeArr",in_timeArr[i],"\n")

				#for i in range(0,len(out_timeArr)):
				#	print("out_timeArr",out_timeArr[i],"\n")

				

				sum=0

				for i in range(0,len(in_timeArr)):
					
					if out_timeArr[i]==-1.0:
						continue
					else:
						sum=sum+out_timeArr[i]-in_timeArr[i]
						diff_Arr[i]=str(out_timeArr[i]-in_timeArr[i])

				#for i in range(0,len(diff_Arr)):
				#	print("diff_Arr",diff_Arr[i],"\n") 

				#update_diff= "UPDATE "+switch_id1+" SET remove_time= '%s' WHERE id = '%s';"%(remove_time,str(flowcount[switch_id]))       
				delay_time= str(sum/(len(in_timeArr)-1))
				print("\ndelay= ",delay_time)

				cursor2.execute("Update DELAY_TABLE SET delay="+delay_time +" WHERE id='%s';"%(table[0]))
				mydb2.commit()
				mydb2.close()

		time.sleep(20)





	
finally:
	if mydb.is_connected():    
		mycursor.close()
		mydb.close()
		print("Mysql connection is closed")
