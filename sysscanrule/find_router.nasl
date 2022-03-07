include("network_func.inc");

macaddr   = get_local_mac_addr();

# """This function returns the MAC address of the gateway we'll route thru when doing a connection to a remote host,
# or the MAC address of the remote host itself if it is on the local subnet"""
dmacaddr = get_gw_mac_addr();


if ( ( ! macaddr ) || (! dmacaddr) )
        exit(0);

proto       = raw_string(0x08, 0);



ethernet = dmacaddr + macaddr + proto; # Ethernet header

change_ip(s:this_host());

# so, if it's routing traffic, then when it decrements TTL to zero, it should send me an ICMP time exceeded
pfilter = string("icmp and (src ", get_host_ip(), ") and (dst ", this_host(), ") and (icmp[0] = 11)" );

for (mu=0; mu<2; mu++)
{
	r = inject_packet(packet:mypacket, filter:pfilter , timeout:2);
	if (r)
	{
		display(string(get_host_ip(), " routes traffic.  You can set it as default gw\n"));
		exit(0);
	}
}	



function change_ip(s)
{
	# NOTE: we are setting TTL to 1 to ensure that we are just testing broadcast domain
	ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_UDP, ip_id:rand(), ip_ttl:0x01,
                         ip_src:this_host());

	# we gotta overwrite the dst IP in memory and then recalculate the IP checksum

	# change dst IP to our IP
	mysrc = split(s, sep:".", keep:FALSE);

	ip[16] = raw_string(int(mysrc[0]));
	ip[17] = raw_string(int(mysrc[1]));
	ip[18] = raw_string(int(mysrc[2]));
	ip[19] = raw_string(int(mysrc[3]));

	# zero out the old checksum bytes
	ip[10] = raw_string(0);
	ip[11] = raw_string(0);

	# new checksum
	sum2 = ip_checksum(data:ip);

	# insert new checksum
	ip[11] = raw_string(ord(sum2[0]));
	ip[10] = raw_string(ord(sum2[1]));


	# this is just a DNS query for 0x.com
	mydat = raw_string(0,0x19,1,0,0,1,0,0,0,0,0,0,2,0x30,0x78,3,0x63, 0x6f, 0x6d, 0, 0, 1, 0, 1);

	udpip = forge_udp_packet(                ip : ip,
                                                 uh_sport : rand() % 65536,
                                                 uh_dport : 53,
                                                 uh_ulen : 8 + strlen(mydat),
                                                 data : mydat);

	mypacket = ethernet + udpip;


}


