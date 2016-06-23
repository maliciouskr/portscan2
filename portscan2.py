import optparse
import socket
from socket import *
from threading import *

def connscan(tgthost,tgtport):
    try:
        connskt = socket(AF_INET,SOCK_STREAM)
        connskt.connect((tgthost,tgtport))
        connskt.send('violentpython\r\n')
        results = connskt.recv(100)
        print '[+]%d/tcp open'% tgtport
        print '[+] ' +str(results)
        connskt.close()
    except:
        print '[-]%d/tcp closed'% tgtport

def portscan(tgthost,tgtports):
    try:
        tgtip =gethostbyname(tgthost)
    except:
        print "[-] cannot resolve '%s': unkonwn host"%tgthost
        return
    try:
        tgtname = gethostbyaddr(tgtip)
        print '\n[+] scan results for:' + tgtname[0]
    except:
        print '\n[+] scan results for:' + tgtip
    setdefaulttimeout(1)
    for tgtport in tgtports:
        print 'scanning port ' + tgtport
        connscan(tgthost,int(tgtport))
def main():
    parser = optparse.OptionParser('usage  -H ' + \
                                   '<target host > -p <target port>')
    parser.add_option('-H', dest='tgthost', type='string', help='specify host')
    parser.add_option('-p', dest='tgtport', type='int', help='specify port')
    (options, args) = parser.parse_args()
    tgthost = options.tgthost
    tgtports = str(options.tgtport).split(',')
    if (tgthost == None) | (tgtports[0] == None):
       print parser.usage
       exit(0)
    portscan(tgthost,tgtports)
if __name__ == '__main__':
    main()
