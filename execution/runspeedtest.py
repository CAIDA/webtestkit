# Adapted from control_nossh.pl
# Used to obtain IP addresses of speed test websites

import re, sys, os, time, subprocess
from subprocess import check_output

# predefined parameters
repeat = 20
rate_control = 1
eth0 = "ens5"

comcast_server = "portland"
ookla_server = "san_diego"
ookla_net = "scalematrix"

sometabin = "./someta"

try:
  repeat = int(sys.argv[1])
  ss_platform = sys.argv[2]
  server_hint = sys.argv[3]
  eth0 = sys.argv[4]
except:
  pass

# speedtest = ["ndt","comcast", "ookla"]
display_filter = {'ndt':"dns.resp.name contains measurement-lab.org", 'comcast':"dns.resp.name contains sys.comcast.net", 'ookla':"tcp.port == 8080"}
dleth = "ether5-local-slave";
uleth = "ether4-local-slave";
print("create output dir\n")
subprocess.run(["mkdir", ss_platform])
subprocess.run(["chmod", "777", ss_platform])
ip_all = dict()
ip_all[ss_platform] = set()

# loop over each network setting
# for bw in range(bwlen):
ip_res = set()
for r in range(repeat):
  ctime = time.time()
  exprname = ss_platform + "_"  + str(ctime)
  if rate_control != 1:
    # no rate control, just need the timestamp
    exprname = ss_platform + "_" + str(ctime)
  print(exprname)
  pcapname = ss_platform + "/" + exprname + ".pcap"
  pid = os.fork()
  if pid == 0:
    subprocess.run(["tcpdump", "-i", eth0, "-n", "-s", "100", "-w", pcapname])
    os._exit(0)
  time.sleep(1)
  nodename = "chrome/"+ss_platform + ".js"
  outputname = ss_platform + "/" + exprname
  metaname = ss_platform+"/"+exprname+".meta"
  # block at node until if finishes
  if (ss_platform == 'comcast'):
    comcast_server = server_hint.split(',')[0]
    nodecmd = "node "+nodename+" "+outputname+" -host "+comcast_server 
    print(nodecmd)

  elif (ss_platform == 'ookla'):
    sys_user = check_output(['whoami'], shell=True).decode().split('\n')[0]
    hostalias = check_output(['cat','/home/'+sys_user+'/hostalias']).decode().split('\n')[0]
    if 'eu' in hostalias:
      is_eu = True
    else:
      is_eu = False
    ookla_server = server_hint.split(' - ')[0].split(',')[0].replace(" ","_")
    ookla_net = server_hint.split(' - ')[1].replace(" ","_")
    if not is_eu:
      nodecmd = "node "+nodename+" "+outputname+" -city "+ookla_server+" -net "+ookla_net
    else:
      nodecmd = "node "+"chrome/ookla_eu.js"+" "+outputname+" -city "+ookla_server+" -net "+ookla_net
    print(nodecmd)

  else:
    tmp = server_hint.split('.measurement-lab.org')
    ndt_server = tmp[0].replace('.','-') + '.measurement-lab.org'
    nodecmd = "ndt7-client " + "-hostname " + ndt_server + " > " + outputname + ".web.csv"
    print(nodecmd)
  subprocess.run([sometabin, "-M=cpu", "-M=mem", "-M=ss:interval=0.1s","-f", metaname, "-c", nodecmd])
        # `sudo $sometabin -M=cpu -M=mem -M=ss:interval=0.1s -f $metaname -c "sudo -u $username node $nodename $outputname $testparam"`;
  subprocess.run(["pkill", "tcpdump"])
time.sleep(3)
 
def disableinf(link):	
  return "/interface ethernet set " + link + " disabled=yes"
	

def enableinf(link):
  return "/interface ethernet set " + link + " disabled=no"
	

def setbwcmd(bw, link):
  return "/interface ethernet set " + link + " bandwidth=" + bw + "/unlimited"


def setqueuecmd(inf, qt):
  return "/queue interface set " + inf + " queue=" + qt
