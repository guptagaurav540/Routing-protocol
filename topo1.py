from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch

class MyTopo( Topo ):

	def build( self ):
		"Create custom topo."
		
		s1 = self.addSwitch( 's1' )
		s2 = self.addSwitch( 's2' )
		s3 = self.addSwitch( 's3' )
		s4 = self.addSwitch( 's4' )
		s5 = self.addSwitch( 's5' )
		s6 = self.addSwitch( 's6' )
		s7 = self.addSwitch( 's7' )
		s8 = self.addSwitch( 's8' )
		s9 = self.addSwitch( 's9' )
		h1 = self.addHost('h1', ip='10.0.0.1', defaultRoute=None)
		h2 = self.addHost('h2', ip='10.0.0.2', defaultRoute=None)
		h3 = self.addHost('h3', ip='10.0.0.3', defaultRoute=None)
		h4 = self.addHost('h4', ip='10.0.0.4', defaultRoute=None)
		h5 = self.addHost('h5', ip='10.0.0.5', defaultRoute=None)
		h6 = self.addHost('h6', ip='10.0.0.6', defaultRoute=None)
		h7 = self.addHost('h7', ip='10.0.0.7', defaultRoute=None)
		h8 = self.addHost('h8', ip='10.0.0.8', defaultRoute=None)
		h9 = self.addHost('h9', ip='10.0.0.9', defaultRoute=None)
		h10 = self.addHost('h10', ip='10.0.0.10', defaultRoute=None)
		h11 = self.addHost('h11', ip='10.0.0.11', defaultRoute=None)
		h12 = self.addHost('h12', ip='10.0.0.12', defaultRoute=None)
		h13 = self.addHost('h13', ip='10.0.0.13', defaultRoute=None)
		h14 = self.addHost('h14', ip='10.0.0.14', defaultRoute=None)
		h15 = self.addHost('h15', ip='10.0.0.15', defaultRoute=None)
		
		self.addLink(s1, s2)
		self.addLink(s1, s8)
		self.addLink(s1, s9)
		self.addLink(s2, s3)
		self.addLink(s2, s4)
		self.addLink(s3, s4)
		self.addLink(s3, s9)
		self.addLink(s4, s5)
		self.addLink(s4, s6)
		self.addLink(s5, s6)
		self.addLink(s5, s9)
		self.addLink(s6, s7)
		self.addLink(s6, s8)
		self.addLink(s7, s9)
		self.addLink(s1, h1)
		self.addLink(s1, h2)
		self.addLink(s1, h3)
		self.addLink(s2, h4)
		self.addLink(s2, h5)
		self.addLink(s3, h6)
		self.addLink(s3, h7)
		self.addLink(s4, h8)
		self.addLink(s5, h9)
		self.addLink(s6, h10)
		self.addLink(s6, h11)
		self.addLink(s7, h12)
		self.addLink(s8, h13)
		self.addLink(s9, h14)
		self.addLink(s9, h15)
		
		

def runMytopo():
	topo=MyTopo()
	net = Mininet(topo=topo,controller=lambda name: RemoteControlle( name, ip='127.0.0.1'), switch=OVSSwitch, autoSetMacs=True )
	#c1 = net.addController('c1', controller=RemoteController,
#ip="192.168.56.101", port=6633)
	net.start()
	CLI( net )
	net.stop()	
	
	

if __name__=='main()__':
	setLogLevel('info')
	runMyTopo()
	
	
topos = { 'mytopo':MyTopo
 }

