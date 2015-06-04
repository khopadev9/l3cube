/*
 * Read and dump pcap files with libcrafter
 *
 * The program assembles a set of ARP requests and TCP packets on a
 * container and then dumps the data on a pcap file. Finally, we
 * read that file and prints the first 5 packets. Not very useful
 * but shows how to work with pcap files.
 */

#include <iostream>
#include <vector>
#include <list>
#include <deque>
#include <string>
#include <tr1/memory>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

        typedef tr1::shared_ptr<Packet> packet_ptr;
	vector<packet_ptr> request_packets;

	vector<packet_ptr> request_packets_read;
	ReadPcap(&request_packets_read,"arp-storm.pcap");
	vector<packet_ptr> tcp_packets_read;
	ReadPcap(&tcp_packets_read,"tcp-ecn-sample.pcap");

	vector<packet_ptr>::iterator it_vec;
	vector<packet_ptr>::iterator it_lst;
		
        
	/* Print first 5 packets */
	cout << endl;
	cout << "[@] ++++++++++++++++ ARP requests : " << endl;
	cout << endl;
	for(it_vec = request_packets_read.begin() ; it_vec < request_packets_read.begin() + 5 ; it_vec++)
	{
	        
	        cout<<endl;
	        (*it_vec)->Print();
	        cout<<endl;
	}
	
	
	

	/* Print first 5 packets */
	cout << endl;
	cout << "[@] ++++++++++++++++ TCP packets : " << endl;
	cout << endl;
	for(it_lst = tcp_packets_read.begin() ; it_lst < tcp_packets_read.begin() + 5 ; it_lst++)
	{
	        cout<<endl;
		(*it_lst)->Print();
		cout<<endl;
	}


	return 0;
}
/*
[vaibhav@localhost libcrafter]$ gedit all.cpp
[vaibhav@localhost libcrafter]$ g++ all.cpp -o all -lcrafter
[vaibhav@localhost libcrafter]$ ./all

[@] ++++++++++++++++ ARP requests : 


< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:07:0d:af:f4:54 , Type = 0x806 , >
< ARP (28 bytes) :: HardwareType = 0x1 , ProtocolType = 0x800 , HardwareLength = 6 , ProtocolLength = 4 , Operation = 1 , SenderMAC = 00:07:0d:af:f4:54 , SenderIP = 24.166.172.1 , TargetMAC = 00:00:00:00:00:00 , TargetIP = 24.166.173.159 , >
< RawLayer (18 bytes) :: Payload = \x6\x1\x4\x0\x0\x0\x0\x2\x1\x0\x3\x2\x0\x0\x5\x1\x3\x1>


< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:07:0d:af:f4:54 , Type = 0x806 , >
< ARP (28 bytes) :: HardwareType = 0x1 , ProtocolType = 0x800 , HardwareLength = 6 , ProtocolLength = 4 , Operation = 1 , SenderMAC = 00:07:0d:af:f4:54 , SenderIP = 24.166.172.1 , TargetMAC = 00:00:00:00:00:00 , TargetIP = 24.166.172.141 , >
< RawLayer (18 bytes) :: Payload = \x1\x0\x0\x10\x0\x1\x0\x0\x0\x0\x0\x0 CKAAA>


< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:07:0d:af:f4:54 , Type = 0x806 , >
< ARP (28 bytes) :: HardwareType = 0x1 , ProtocolType = 0x800 , HardwareLength = 6 , ProtocolLength = 4 , Operation = 1 , SenderMAC = 00:07:0d:af:f4:54 , SenderIP = 24.166.172.1 , TargetMAC = 00:00:00:00:00:00 , TargetIP = 24.166.173.161 , >
< RawLayer (18 bytes) :: Payload = \x2\x1\x4\x0\x0\x0\x5\x2\x1\x0\x3\x2\x0\x0\x5\x1\x1\x2>


< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:07:0d:af:f4:54 , Type = 0x806 , >
< ARP (28 bytes) :: HardwareType = 0x1 , ProtocolType = 0x800 , HardwareLength = 6 , ProtocolLength = 4 , Operation = 1 , SenderMAC = 00:07:0d:af:f4:54 , SenderIP = 65.28.78.1 , TargetMAC = 00:00:00:00:00:00 , TargetIP = 65.28.78.76 , >
< RawLayer (18 bytes) :: Payload = \x1\x0\x0\x10\x0\x1\x0\x0\x0\x0\x0\x0 CKAAA>


< Ethernet (14 bytes) :: DestinationMAC = ff:ff:ff:ff:ff:ff , SourceMAC = 00:07:0d:af:f4:54 , Type = 0x806 , >
< ARP (28 bytes) :: HardwareType = 0x1 , ProtocolType = 0x800 , HardwareLength = 6 , ProtocolLength = 4 , Operation = 1 , SenderMAC = 00:07:0d:af:f4:54 , SenderIP = 24.166.172.1 , TargetMAC = 00:00:00:00:00:00 , TargetIP = 24.166.173.163 , >
< RawLayer (18 bytes) :: Payload = \x1\x1\x4\x0\x0\x0\x0\x2\x1\x0\x3\x2\x0\x0\x5\x1\x3\x3>


[@] ++++++++++++++++ TCP packets : 


< Ethernet (14 bytes) :: DestinationMAC = c0:01:14:7c:00:01 , SourceMAC = c0:02:12:68:00:00 , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 44 , Identification = 0x7645 , Flags = 0 , FragmentOffset = 0 , TTL = 255 , Protocol = 0x6 , CheckSum = 0x2081 , SourceIP = 1.1.23.3 , DestinationIP = 1.1.12.1 , >
< TCP (20 bytes) :: SrcPort = 46557 , DstPort = 80 , SeqNumber = 179265614 , AckNumber = 0 , DataOffset = 6 , Reserved = 0 , Flags = ( SYN ECE CWR ) , WindowsSize = 4128 , CheckSum = 0x44b2 , UrgPointer = 0 , >
< TCPOptionMaxSegSize (4 bytes) :: Kind = 2 , Length = 4 , MaxSegSize = 536 , >
< RawLayer (2 bytes) :: Payload = \x0\x0>


< Ethernet (14 bytes) :: DestinationMAC = c0:02:12:68:00:00 , SourceMAC = c0:01:14:7c:00:01 , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 44 , Identification = 0x194 , Flags = 0 , FragmentOffset = 0 , TTL = 254 , Protocol = 0x6 , CheckSum = 0x9632 , SourceIP = 1.1.12.1 , DestinationIP = 1.1.23.3 , >
< TCP (20 bytes) :: SrcPort = 80 , DstPort = 46557 , SeqNumber = 2798152218 , AckNumber = 179265615 , DataOffset = 6 , Reserved = 0 , Flags = ( SYN ACK ECE ) , WindowsSize = 4128 , CheckSum = 0x343e , UrgPointer = 0 , >
< TCPOptionMaxSegSize (4 bytes) :: Kind = 2 , Length = 4 , MaxSegSize = 536 , >


< Ethernet (14 bytes) :: DestinationMAC = c0:01:14:7c:00:01 , SourceMAC = c0:02:12:68:00:00 , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 0 , TotalLength = 40 , Identification = 0x7646 , Flags = 0 , FragmentOffset = 0 , TTL = 255 , Protocol = 0x6 , CheckSum = 0x2084 , SourceIP = 1.1.23.3 , DestinationIP = 1.1.12.1 , >
< TCP (20 bytes) :: SrcPort = 46557 , DstPort = 80 , SeqNumber = 179265615 , AckNumber = 2798152219 , DataOffset = 5 , Reserved = 0 , Flags = ( ACK ) , WindowsSize = 4128 , CheckSum = 0x489f , UrgPointer = 0 , >
< RawLayer (6 bytes) :: Payload = \x0\x0\x0\x0\x0\x0>


< Ethernet (14 bytes) :: DestinationMAC = c0:01:14:7c:00:01 , SourceMAC = c0:02:12:68:00:00 , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 2 , TotalLength = 201 , Identification = 0x7647 , Flags = 0 , FragmentOffset = 0 , TTL = 255 , Protocol = 0x6 , CheckSum = 0x1fe0 , SourceIP = 1.1.23.3 , DestinationIP = 1.1.12.1 , >
< TCP (20 bytes) :: SrcPort = 46557 , DstPort = 80 , SeqNumber = 179265615 , AckNumber = 2798152219 , DataOffset = 5 , Reserved = 0 , Flags = ( ACK ) , WindowsSize = 4128 , CheckSum = 0x8076 , UrgPointer = 0 , >
< RawLayer (161 bytes) :: Payload = GET /show-tech HTTP/1.1\r\nUser-Agent: cisco-IOS\r\nHost: 1.1.12.1\r\nAuthorization: Basic YWRtaW46Y2lzY28=\r\nDate: Fri, 01 Mar 2002 00:30:47 GMT\r\nConnection: close\r\n\r\n>


< Ethernet (14 bytes) :: DestinationMAC = c0:02:12:68:00:00 , SourceMAC = c0:01:14:7c:00:01 , Type = 0x800 , >
< IP (20 bytes) :: Version = 4 , HeaderLength = 5 , DiffServicesCP = 0 , ExpCongestionNot = 2 , TotalLength = 296 , Identification = 0x195 , Flags = 0 , FragmentOffset = 0 , TTL = 254 , Protocol = 0x6 , CheckSum = 0x9533 , SourceIP = 1.1.12.1 , DestinationIP = 1.1.23.3 , >
< TCP (20 bytes) :: SrcPort = 80 , DstPort = 46557 , SeqNumber = 2798152219 , AckNumber = 179265776 , DataOffset = 5 , Reserved = 0 , Flags = ( ACK ) , WindowsSize = 3967 , CheckSum = 0xb9e2 , UrgPointer = 0 , >
< RawLayer (256 bytes) :: Payload = HTTP/1.1 200 OK\r\nDate: Fri, 01 Mar 2002 00:34:40 GMT\r\nServer: cisco-IOS\r\nConnection: close\r\nContent-Length: 83122\r\nExpires: Fri, 01 Mar 2002 00:34:40 GMT\r\nLast-Modified: Fri, 01 Mar 2002 00:34:40 GMT\r\nCache-Control: no-store, no-cache, must-revalidate\r\nAcc>

[vaibhav@localhost libcrafter]$ 
*/
