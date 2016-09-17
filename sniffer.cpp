//
// using pcaplib capture tcp/ip segments
//
//sniffer.exe -u username -p password -a 210.77.67.24 -i 4 -m | perl -ne "print $_ if(//);"
// this program only outputs tcp/ip status.
//
// author: hailongchang165210@gmail.com
//
// version: 1.0
//

#ifndef WIN32
#define WIN32
#endif

#ifndef WPCAP
#define WPCAP
#endif

#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif

#include"pcap.h"
#include<remote-ext.h>
#ifdef WIN32
#include<Winsock2.h>
#endif


#include<iostream>
#include<vector>
#include<string>
#include<sstream>
#include<cstring>
#include"GetOpt.h"

using namespace std;


// IP address from FreeBSD kernel Header
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// IPv4 header from FreeBSD kernel header
typedef struct _ip_header
{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length(4 bits)
    u_char	tos;			// Type of service 
    u_short     tlen;			// Total length 
    u_short     identification;         // Identification
    u_short     flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short     crc;			// Header checksum
    u_long      saddr;                  // source ip address
    u_long      daddr;                  // destination ip address
    u_int	op_pad;			// Option + Padding
}ip_header;

// TCP header from FreeBSD kernel header
typedef struct _tcp_header
{
    u_short     th_sport;	       // source port
    u_short     th_dport;	       // destination port
    u_long      th_seq;                // sequence number
    u_long      th_ack;                // acknowledgement number
    u_char      th_offx2;	       // data offset, rsvd
    u_char      th_flags;              // ACK FIN PSH SYN RST flags
    u_short     th_win;		       // window
    u_short     th_sum;		       // checksum
    u_short     th_urp;		       // urgent pointer
}tcp_header;

typedef struct _NET_INC{
    string name;
    string description;
}NET_INC;


vector<NET_INC> vecDevs;
pcap_t* fp;
char pcap_address[128] = {0};
string username;
string password;
bool g_isRemote = false;
string DecimalIP(u_long uip){

    stringstream decip;
    int dec1 =  uip & 0x000000ff;
    int dec2 = (uip & 0x0000ff00) >> 8;
    int dec3 = (uip & 0x00ff0000) >> 16;
    int dec4 = (uip & 0xff0000ff) >> 24;

    decip << dec1 << "."
	  << dec2 << "."
	  << dec3 << "."
	  << dec4;
    
    return decip.str();
}


void print_usage (){  
cout << "Usage: %s options [outputfile ...]" << endl;
cout << " -u --username    Windows target server username" << endl;
cout << " -p --password    Windows target server password" << endl;
cout << " -d --display     Display all network Interface." << endl;    
cout << " -a --remote      rpcap address(windows only)." << endl;
cout << " -i --interface   network interface index number, default is 0." << endl;
cout << " -m --monitor     start packet capture." << endl;  
}  


void init_interfaces(string address){
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    memset(pcap_address,0,128);
    string pcap_addr = "";

    struct pcap_rmtauth* prm = NULL;    
    if(address == "0.0.0.0" || address == "127.0.0.1"){
	// pcap_addr = "127.0.0.1";
	pcap_addr = "rpcap://";
	g_isRemote = false;
    }else{
	pcap_addr = "rpcap://" + address + ":2002";
	g_isRemote = true;
	prm = new struct pcap_rmtauth;
	memset(prm,0,sizeof(struct pcap_rmtauth));
	prm->type=1;
	prm->username= new char[64];
	prm->password= new char[64];
	memset(prm->username,0,64);
	memset(prm->password,0,64);  
	strcpy(prm->username,username.c_str());
	strcpy(prm->password,password.c_str());	
    }

    strcpy(pcap_address,pcap_addr.c_str());

    //if (pcap_findalldevs_ex("rpcap://210.77.67.24:2002", NULL, &alldevs, errbuf) == -1)   
    if (pcap_findalldevs_ex(pcap_address, prm, &alldevs, errbuf) == -1){
    	cout << "find all devs error" << endl;
    	return;
    }

    for(dev = alldevs;dev != NULL; dev = dev->next){
	string name = dev->name;
	string desp = dev->description;
	NET_INC nc = {name,desp};
    	vecDevs.push_back(nc);
    }
    
    pcap_freealldevs(alldevs);
    if(prm){
	delete []prm->username;
	delete []prm->password;
	delete prm;
	prm = NULL;
    }
}
void display_interfaces(){
    
    int i = 0;
    for(int i = 0; i<vecDevs.size();i++){
    	cout << "dev:" << i << "\t" << vecDevs[i].description << endl;
    	cout << endl;	
    }
}

void monitor(int iif){
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char name[128] = {0};
    strcpy(name,vecDevs[iif].name.c_str());
    
    struct pcap_rmtauth* prm = NULL;
    if(g_isRemote == true){
	prm = new struct pcap_rmtauth;
	memset(prm,0,sizeof(struct pcap_rmtauth));
	prm->type=1;
	prm->username= new char[64];
	prm->password= new char[64];
	memset(prm->username,0,64);
	memset(prm->password,0,64);  
	strcpy(prm->username,username.c_str());
	strcpy(prm->password,password.c_str());	
    }    
    if((fp =
	pcap_open(name,65535,1,1000,prm,errbuf))
       == NULL){
	cout << errbuf << endl;
	return;
    }

    u_int netmask = 0xffffff;
    struct bpf_program fcode;   
    if(pcap_compile(fp,&fcode,"ip and tcp",1,netmask) < 0){
	cout << "pcap_compile error" <<endl;
	return;
    }

    if(pcap_setfilter(fp,&fcode) < 0){
	cout << "set filter error" << endl;
	return;
    }

    int res = 0;

    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    while(1){
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0){
	    if(res == 0){
		continue;
	    }
	    if(res == -1){
		stringstream err;
		err << "Error reading the packets: " << pcap_geterr(fp);
		cout << err.str() << endl;
		continue;
	    }
	    long sec = (header->ts).tv_sec;
	    ip_header* my_ip;
	    my_ip = (ip_header*) (pkt_data + 14);
	    unsigned short ip_len = (my_ip->ver_ihl & 0xf) * 4;
	    tcp_header* my_tcp;
	    my_tcp = (tcp_header*)((u_char*)my_ip+ip_len);
	
	    unsigned short sport = ntohs(my_tcp->th_sport);
	    unsigned short dport = ntohs(my_tcp->th_dport);
	    unsigned short tcp_len = ((my_tcp->th_offx2 & 0xfc) >> 4) * 4;
	    unsigned int issyn = (my_tcp->th_flags & 0x02) >> 1;
	    unsigned int isack = (my_tcp->th_flags & 0x10) >> 4;
	    unsigned int isfin = (my_tcp->th_flags & 0x01);
	    unsigned int isrst = (my_tcp->th_flags & 0x04) >> 2;
	    unsigned int ispsh = (my_tcp->th_flags & 0x08) >> 3;
	    unsigned short datalength = ntohs(my_ip->tlen) - ip_len - tcp_len;

	    cout << sec << "\t"
		 << DecimalIP(my_ip->saddr) << ":" << sport << "\t" 
		 << DecimalIP(my_ip->daddr) << ":" << dport << "\t";
	    if(issyn)
		cout << "SYN" << " ";
	    if(isack)
		cout << "ACK" << " ";
	    if(isfin)
		cout << "FIN" << " ";
	    if(isrst)
		cout << "RST" << " ";
	    if(ispsh)
		cout << "PSH" << " ";
	    cout << "len=" <<datalength << " " << endl;
	}
	if(res < 0){
	    cout << "pcap_next_ex() function error" << endl;	
	}
    }
    if(prm){
	delete []prm->username;
	delete []prm->password;
	delete prm;
	prm = NULL;
    }
}
int main(int argc,char** argv){

    int opt;
    const char* const short_options = "u:p:da:i:m";

    string address;    

    int    ifindex = 0; 
    const struct option long_options[7]={
	{"user",1,NULL,0},
	{"password",1,NULL,2},	
	{"display",0,NULL,4},
	{"remote",1,NULL,5},
	{"interface",1,NULL,7},
	{"monitor",2,NULL,9},
	{NULL,0,NULL,NULL}	
    };

    opt = getopt_long(argc,argv,short_options,long_options,NULL);
    
    if(opt == -1){
	print_usage();
	return 0;
    }
    while(opt != -1){
        switch (opt){
	case 'd':
	    if(address.empty() || address == ""){
		address = "127.0.0.1";
	    }
	    if(vecDevs.size() == 0){
		init_interfaces(address);
	    }
	    
	    display_interfaces();
	    break;
	case 'a':
	    address = optarg;
	    if(address.empty() || address == ""){
		address = "127.0.0.1";
	    }
		
	    if(vecDevs.size() == 0){
		init_interfaces(address);
	    }
		
	    break;
	case 'i':
	    ifindex = atoi(optarg);
	    break;
	case 'm':
	    if(address.empty() || address == ""){
		address = "127.0.0.1";
	    }
	    if(vecDevs.size() == 0){
		init_interfaces(address);
	    }

	    if(ifindex > vecDevs.size() || ifindex < 0){
		ifindex = 0;
	    }
	    monitor(ifindex);
	    break;
	case 'u':
	    username = optarg;
	    break;
        case 'p':
	    password = optarg;
	    break;
	default: 
	    break;
        }
        opt = getopt_long (argc, argv, short_options,long_options, NULL);
    }
}

