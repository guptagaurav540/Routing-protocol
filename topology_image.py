import networkx as nx
import mysql.connector
import matplotlib.pyplot as plt
G=nx.Graph()

mydb = mysql.connector.connect(
host="localhost",
user="root",
password="",
database="SDN"
)
mycursor=mydb.cursor()
sql1="SELECT S1,S2 FROM topotable;"
mycursor.execute(sql1)
records= mycursor.fetchall()
print(records)
g=[]



G=nx.Graph()
G.add_edges_from(records)
print(G.nodes())
nx.draw(G,with_labels=True)
plt.show()