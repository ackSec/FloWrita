from mininet.net import Mininet
from mininet.util import quietRun
from requests import put
from json import dumps
from subprocess import call, check_output
from os import listdir
import re
import socket

collector = '127.0.0.1'
sampling = 10
polling = 2

def getIfInfo(ip):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect((ip, 0))
  ip = s.getsockname()[0]
  ifconfig = check_output(['ifconfig'])
  ifs = re.findall(r'^(\S+).*?inet addr:(\S+).*?', ifconfig, re.S|re.M)
  for entry in ifs:
    if entry[1] == ip:
      return entry

def configSFlow(net,collector,ifname):
  print "*** Enabling sFlow:"
  sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=%s sampling=%s polling=%s --' % (ifname,collector,sampling,polling)
  for s in net.switches:
    sflow += ' -- set bridge %s sflow=@sflow' % s
  print ' '.join([s.name for s in net.switches])
  quietRun(sflow)

def wrapper(fn,collector):
  def result( *args, **kwargs):
    res = fn( *args, **kwargs)
    net = args[0]
    (ifname, agent) = getIfInfo(collector)
    configSFlow(net,collector,ifname)
    #sendTopology(net,agent,collector) 
    return res
  return result

setattr(Mininet, 'start', wrapper(Mininet.__dict__['start'], collector))
  
