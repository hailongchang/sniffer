#Sniffer

C++和Perl实现的网卡嗅探程序，利用libpcap, 可以执行端口sniffer，判断端口连接状态的程序。

#用法

##sniffer.exe

sniffer.exe 主要执行嗅探工作，输出TCP标志（SYN,ACK,FIN等），使用C++完成。

* -u 远程机器用户名
* -p 远程机器密码
* -d 显示所有的网卡名称
* -a 需要抓包的远程机器地址
* -i 指定要绑定的网卡
* -m 执行抓包操作

sniffer.exe -a 127.0.0.1 -d 显示本机网卡
sniffer.exe -a -i 0 -m 嗅探本机索引为0的网卡
sniffer.exe -u testuser -p testpasswd -a 192.168.127.12 -i 4 -m 嗅探远程192.168.127.12机器索引号为4的网卡

##stat_tcp.pl

stat_tcp.pl 实现了一个状态机，根据C++的输出判断TCP状态。<br>
-p 命令行选项，需要嗅探的本机IP <br>

##运行

嗅探本机源IP或目的IP为192.168.0.101，并且网卡索引为0的所有连接
sniffer.exe -a 127.0.0.1 -i 0 -m | perl stat_tcp.pl -p 192.168.0.101
	