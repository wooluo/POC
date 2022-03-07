include("network_func.inc");

# jlampe@tenable.com


if(description)
{
 script_id(999999);
 script_version("$Revision: 1.7 $");

 script_name(english:"UDP Open Ports");

 script_set_attribute(attribute:"synopsis", value:
"The following ports are open on the remote server.");
 script_set_attribute(attribute:"description", value:
"The following UDP ports are open on the remote server");
 script_set_attribute(attribute:"solution", value:
"Manually inspect open ports for security ramifications." );

script_set_attribute(attribute:"plugin_publication_date", value: "2018/06/19");
script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"UDP Port check");
 script_copyright(english:"This script is free");
 script_timeout(1728000);	# 20 days in seconds...adjust accordingly for NERC environment
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 exit(0);
}


DEBUG = 1;
start_port = 1;
end_port = 65535;
timeout_in_secs = 1;
trips_around_the_sun = 0;
port_count = 0;
full_report = string("The following UDP ports were found open on the remote machine\n");
opt = script_get_preference("Enter timeout value");


for (i=start_port; i<=end_port; i++)
{
    is_open = scan_udp_port(port:i, timeout:timeout_in_secs);
    if (is_open)
    {
        full_report = string(full_report, "\n  -", i );
        port_count++;
        if (DEBUG)
            display(string("DEBUG SUCCESS logging an open port : ", i, "\n"));
    }

    trips_around_the_sun++;

    if ((trips_around_the_sun % 25) == 0)    
    {
        spoofed = spoof_packet();
        if (spoofed && DEBUG)
            display(string("DEBUG SUCCESS our spoof-packet trick worked and we received the packet from default gw\n"));
    }

}

if (port_count > 0)
    security_note(port:0, extra:full_report);
else
    security_note(port:0, extra:string(full_report, "\nNo Open UDP ports\n"));





function scan_udp_port(port,timeout)
{
    local_var start_time, end_time, filter, mydat, ip, udpip, result, elapsed_time;

    filter = string("icmp and icmp[0] = 3 and icmp[1] = 3 and (src ", get_host_ip(), ") and (dst ", this_host(), ")");

    mydat = raw_string(0xde, 0xad, 0xbe, 0xef);

    ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : 20,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_UDP,
                        ip_ttl : 32,
                        ip_off : 0,
                        ip_src : this_host());


    udpip = forge_udp_packet(            ip : ip,
                                         uh_sport : rand() % 65536,
                                         uh_dport : port,
                                         uh_ulen : 8 + strlen(mydat),
                                         data : mydat);

    start_time = unixtime();    
    result = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:timeout);
    end_time = unixtime();
    elapsed_time = end_time - start_time;
    if ( elapsed_time < timeout)
        sleep(timeout - elapsed_time);

    if (! result)
	return 1;
    else
	return 0;
}


# this function flips the srcIP and dstIP, recomputes the checksum, then sends the packet to the default gw for transmission back to us
function spoof_packet()
{
    ret = 0;
    macaddr   = get_local_mac_addr();
    dmacaddr = get_gw_mac_addr();

    if ( ( ! macaddr ) || (! dmacaddr) )
    {
        if (DEBUG)
            display(string("DEBUG FAILED to get a src and dst mac addr\n"));

        return ret;
    }
    else if (DEBUG)
        display(string("DEBUG SUCCESS we successfully retrieved the local mac and gateway mac.\n"));

    proto = raw_string(0x08, 0);
    ethernet = dmacaddr + macaddr + proto; # Ethernet header

    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0,ip_off:0,ip_len:20,
                         ip_p:IPPROTO_UDP, ip_id:rand(), ip_ttl:0x20,
                         ip_src:this_host());


    # In memory, flip the src and dst IPs and recompute the checksum    
    mysrc = split(this_host(), sep:".", keep:FALSE);
    mydst = split(get_host_ip(), sep:".", keep:FALSE);

    ip[12] = raw_string(int(mydst[0]));
    ip[13] = raw_string(int(mydst[1]));
    ip[14] = raw_string(int(mydst[2]));
    ip[15] = raw_string(int(mydst[3])); 
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
    pfilter = string("udp and (src ", get_host_ip(), ") and (dst ", this_host(), ")");
    for (mu=0; mu<2; mu++)
    {
        r = inject_packet(packet:mypacket, filter:pfilter , timeout:2);
        if (r)
        {
            if (DEBUG)
                display(string("DEBUG SUCCESS we received our spoof packet over ethernet\n"));
            return 1;
        }
    }

    return ret;
}


function get_target_mac()
{
    raw = link_layer();
    if (strlen(raw) > 6)
    {
        for (i=0; i < 6; i++)
            dst_mac = raw_string(dst_mac, ord(raw[i]));
    }
    else
    {
        return 0;
    }

    return dst_mac;
}
