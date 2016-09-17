@echo off
title Íø¿¨ÐáÌ½³ÌÐò

@echo on
sniffer.exe -a 127.0.0.1 -i 0 -m | perl stat_tcp.pl -p 192.168.0.101
pause