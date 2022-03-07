dstaddr=get_host_ip();
srcaddr=this_host();
IPH = 20;
IP_LEN = IPH;
sslport=443;
nonsslport = 80;


myopt = raw_string(0x04,0x02,0x00,0x00);


# Case 1) set TTL to 5.  We should never get an ACK to this
display("Starting Test 1 - Send a SYN packet with TTL set to 10\n");


sport = (rand() % 48000) + 1400;
filter = string("src port ", sslport, " and dst port ", sport);

ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 10,
                        ip_off : 0,
                        ip_src : srcaddr);


tcpip = forge_tcp_packet(
                             ip       : ip,
                             th_sport : sport,
                             th_dport : sslport,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 65536,
                             th_urp   : 0,
                             data     : myopt);

result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:2);

if (result)
{
		display("Got a response to our packet.  ");
        display(string("Likely SSL BitW proxy detected\n"));
}
else
{
	display("No response to our SYN packet with TTL set to 10.  Checking for an ICMP 'time exceeded' error message\n");
	# send same packet but filter for ICMP time exceeded message
	filter = string("icmp and (icmp[0] = 11)" );
	result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
	if (! result)
	{
		display("We did NOT get an ICMP 'time exceeded' traffic.  There is some filtering taking place\n");
		display("Attempting to generate an ICMP error message on a non-SSL port\n");
		sport = (rand() % 48000) + 1400;
		ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 10,
                        ip_off : 0,
                        ip_src : srcaddr);


		tcpip = forge_tcp_packet(
                             ip       : ip,
                             th_sport : sport,
                             th_dport : nonsslport,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1D,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 65536,
                             th_urp   : 0,
                             data     : myopt);

		result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
		if (result)
		{
			display(string("Got an ICMP 'time exceeded' message on port ", nonsslport, "\n"));
			display("Likely SSL BitW proxy between you and the host\n");
		}
		else
		{
			display(string("No ICMP 'time exceeded message on port ", nonsslport, "\n"));
		}

	}
	else
	{
		display ("ICMP time exceeded error message received\n");
	}
}


# Test 2

# Here we send an ACK/FIN packet.  First we send to the SSL server, second we send to the known, open, non-ssl port
# We *should* get a RST packet in return to both...

display("Starting Test 2 - Send an ACK/FIN to Non-SSL and SSL port\n");


sport = (rand() % 48000) + 1400;
filter = string("src port ", sslport, " and dst port ", sport);

ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 128,
                        ip_off : 0,
                        ip_src : srcaddr);


tcpip = forge_tcp_packet(
                             ip       : ip,
                             th_sport : sport,
                             th_dport : sslport,
                             th_flags : 0x11,	# ACK/FIN
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 65536,
                             th_urp   : 0,
                             data     : myopt);

result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);

if (! result)
{
	display(string("No response to ACK/FIN packet on port ", sslport, "\n"));
	display(string("Sending an ACK/FIN packet to port ", nonsslport, "\n"));
	sport = (rand() % 48000) + 1400;
	filter = string("src port ", nonsslport, " and dst port ", sport);

	ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 128,
                        ip_off : 0,
                        ip_src : srcaddr);


	tcpip = forge_tcp_packet(
                             ip       : ip,
                             th_sport : sport,
                             th_dport : nonsslport,
                             th_flags : 0x11,	# ACK/FIN
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 65536,
                             th_urp   : 0,
                             data     : myopt);

	result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
	if (result)
	{
		display(string("Received a RST on port ", nonsslport, "\n"));
		display("It is highly probable that you are running traffic through an SSL filter\n");
	}
	else
	{
		display(string("No response to ACK/FIN packet on port ", nonsslport, "\n"));
		display("There appears to be some filtering on the network\n");
	}
}
else
{
	display(string("We received a response to our ACK/FIN packet\n"));
}


# case 3 - attempt same as case 2 but with a SYN/FIN packet
# Here we send an SYN/FIN packet.  First we send to the SSL server, second we send to the known, open, non-ssl port
# We *should* get a RST packet in return to both...

display("Starting Test 3 - Send an SYN/FIN to Non-SSL and SSL port\n");


sport = (rand() % 48000) + 1400;
filter = string("src port ", sslport, " and dst port ", sport);

ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 128,
                        ip_off : 0,
                        ip_src : srcaddr);


tcpip = forge_tcp_packet(
                             ip       : ip,
                             th_sport : sport,
                             th_dport : sslport,
                             th_flags : 0x03,	# SYN/FIN
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 65536,
                             th_urp   : 0,
                             data     : myopt);

result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);

if (! result)
{
	display(string("No response to SYN/FIN packet on port ", sslport, "\n"));
	display(string("Sending an SYN/FIN packet to port ", nonsslport, "\n"));
	sport = (rand() % 48000) + 1400;
	filter = string("src port ", nonsslport, " and dst port ", sport);

	ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 128,
                        ip_off : 0,
                        ip_src : srcaddr);


	tcpip = forge_tcp_packet(
                             ip       : ip,
                             th_sport : sport,
                             th_dport : nonsslport,
                             th_flags : 0x03,	# SYN/FIN
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 6,
                             th_win   : 65536,
                             th_urp   : 0,
                             data     : myopt);

	result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
	if (result)
	{
		display(string("Received a RST on port ", nonsslport, "\n"));
		display("It is highly probable that you are running traffic through an SSL filter\n");
	}
	else
	{
		display(string("No response to SYN/FIN packet on port ", nonsslport, "\n"));
		display("There appears to be some filtering on the network\n");
	}
}
else
{
	display(string("We received a response to our ACK/FIN packet\n"));
}



