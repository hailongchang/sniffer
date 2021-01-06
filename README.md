# Sniffer

Sniffer is a network adapter sniffer application implemented using C++ and Perl. Based on libpcap, it can monitor sockets telecommunication and check sockets TCP connection status.

## Usage

### sniffer.exe

sniffer.exe conducts monitoring and outputs status code of TCP(SYN,ACK,FIN etc), it's command arguments typically includes:

* -u remote host username
* -p remote host password
* -d display all network interfaces
* -a address of remote host which would been captured packets.
* -i binding one network interface
* -m monitoring
* sniffer.exe -a 127.0.0.1 -d :will display all network interfaces of local host.
* sniffer.exe -a -i 0 -m  :will capture local socket packets of local network interface with id 0.
* sniffer.exe -u testuser -p testpasswd -a 192.168.127.12 -i 4 -m :capture socket packets of remote host: 192.168.127.12 with interface id 4.

### stat_tcp.pl

stat_tcp.pl implements a FMA，reads tcp status code and check connection status

* -p  ip of host which would been sniffered.

### Running

sniffer all of conmmunications established through network interface 0 between local source IP (127.0.0.1) and target IP(192.168.0.101):

* sniffer.exe -a 127.0.0.1 -i 0 -m | perl stat_tcp.pl -p 192.168.0.101