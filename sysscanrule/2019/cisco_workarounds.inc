#TRUSTED 7054b31a396e207e6b3dc642e113d19bfbaa74c6919965abb234d2bcbbf3f9d6717f87f5e9abbf4c2c09d394dbce811e49038232700935010c4cf44529c6686017e98df8168c1ece84f5a393a5cdfc22d2587202b78fa93e0fec658decfcd9c0bc22e61712a3ff2aa00e73075fd718aac7ddbae12dd84912892faa31c71d19c16db0c1f665c112841637f0028554b99eb8aec9d4769c3e0634d4511a25acd7132532c4292860de9de578dfb6ec78bb90429e42a78915f424e2840c1a623739a4c1a70fd199f49fb87d425c7ca97a0b74a838453e51635e37555678d12d3713820f17ded1da646065b987e0b75122ae69bb280a20ca1561a6c5979675888f05db6b6a401b7058cf5e61bcffbf950498d29d1e082df3060af6534e6d6561c2ea68cf8b7edbf82b9c55c5b373e889b3e64bf66f051cbb2b4ed8fe0fa91be5a191c002ff2dbcadd3868154b737f77e06d9709f109d1de94793aa0280a9b1357e4102965d6d52fc43aaa661afbd1e5d7c459e4ff2de11b1a969704aa4564173735f87b9b4b107c0704582ff497fb6573cc36f4e3d7ee75b83edf8991007566d46ea51d458e35b632e22bdc147d9e85dc628ad1bb002505576670c11e08e12b713ddb97ebafe915f4f6bf076910c4b520dda96f9178374315d49de3bdcd6f2ca1af7fbef9fb74d09b447474bec000dad77ed09719cb774e6a0b5c45d5bf75a0f07b01f
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

CISCO_WORKAROUNDS = {
    "no_workaround" : function () { return make_array('flag' , 1 , 'override' , 0); },
    "show_udp_ike": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (params['check_queue_limit'])
      {
        var buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
        if (check_cisco_result(buf2))
        {
          if (preg(string:buf2, pattern:"^crypto ikev2 limit queue sa-init [0-9]+", multiline:TRUE))
          {
            return ret;
          }
        }
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
      if (check_cisco_result(buf))
      {
        # IKE is UDP 500, 848, 4500
        if (preg(string:buf, pattern:"^\s*17(\(v6\))?\s+[^\s]+\s+[^\s]+\s+(500|848|4500)\s+", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_ip_sock_ike": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (params['check_queue_limit'])
      {
        var buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
        if (check_cisco_result(buf2))
        {
          if (preg(string:buf2, pattern:"^crypto ikev2 limit queue sa-init [0-9]+", multiline:TRUE))
          {
            return ret;
          }
        }
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
      if (check_cisco_result(buf))
      {
        # IKE is UDP 500, 848, 4500
        if (preg(string:buf, pattern:"^\s*17(\(v6\))?\s+[^\s]+\s+[^\s]+\s+(500|848|4500)\s+", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_udp_dmvpn": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        # DMVPN is UDP 18999
        if (preg(string:buf, pattern:"^\s*17(\(v6\))?\s+[^\s]+\s+[0-9]*\s+[^\s]+\s+(18999)\s+[0-9]+", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "MIB_check": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_mib", "show snmp mib");
      var args = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        # "Not all of the MIBs will be displayed in the output of the show
        # snmp mib command but may still be enabled. Customers are advised
        # to implement the entire exclude list as detailed in the
        # Workarounds section of the advisory.""

        if (preg(multiline:TRUE, pattern:args[0], string:buf))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "include_map-server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include map-server", "show running-config | include map-server");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("ipv4 map-server" >< buf && "ipv6 map-server" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ip_helper-address": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*ip helper-address\s+(\d{1,3}.){3}[0-9]{1,3}", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ipv4_helper-address": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ipv4 helper-address", "show running-config | include ipv4 helper-address");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(buf =~ "ipv4 helper-address\s+(vrf\s+[A-z]+\s+)?(\d{1,3}.){3}[0-9]{1,3}")
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ip_dns_server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip dns server", "show running-config | include ip dns server");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("ip dns server" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "service_private_config_encryption": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config all | include service private-config-encryption", "show running-config all | include service private-config-encryption");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("service private-config-encryption" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "http|transport": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include http|transport", "show running-config | include http|transport");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(("transport-map type persistent webui https-webui" >< buf) && ("transport-map type persistent webui http-webui" >< buf) &&
          ("no ip http server" >< buf) && ("ip http authentication local">< buf) && ("ip http secure-server" >< buf) &&
          ("transport type persistent webui input http-webui" >< buf))

          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_pnp_profile": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show pnp profile", "show pnp profile");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(
            ("Initiator Profile" >< buf) &&
            ("Max message (RX)" >< buf) &&
            ("XEP" >< buf) &&
            ("Keepalive" >< buf) &&
            ("Reconnect time" >< buf)
          )
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "aaa_auth_listener": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*aaa authentication listener", multiline:TRUE, string:buf))
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "BGP_EVPN": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*bgp", multiline:TRUE, string:buf) &&
           preg(pattern:"^\s*address-family", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "refresh_upgrade_or_pcd_migration": function () {
      # Check two commands
      var buf = cisco_command_kb_item("Host/Cisco/Config/file view install system-history.log", "file view install system-history.log");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("root: Upgrade (refresh)" >!< buf)
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      if(ret['flag'] == 0)
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/file view install install.log", "file view install install.log");
        if (check_cisco_result(buf))
        {
          if("VOS_INSTALL_CONTEXT = M1" >!< buf)
              ret['flag'] = 1;
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
      }
      return ret;
    },
    "AsyncOS FTP": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/showconfig", "showconfig");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("<ftpd_port>" >< buf)
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "smart_install_check": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if ((preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
           (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_lldp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_lldp", "show lldp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("LLDP" >< buf && "not enabled" >!< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ipv6_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ipv6\s+enable", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*ipv6\s+address", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nxos_nxapi": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^feature nxapi", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s+nxapi (http|https|sandbox)", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "cfs_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*cfs distribute", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s*cfs ipv[46]", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "L2TP_check": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*encapsulation l2tp", multiline:TRUE, string:buf)) ret['flag'] = 1;
        if (preg(pattern:"^\s*vpdn enable", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*vpdn-group.* (encapsulation|protocol) l2tp", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "energywise": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*energywise domain", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "profinet": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*profinet", multiline:TRUE, string:buf) &&
            !preg(pattern:"^\s*no profinet", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ospfv3": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ospfv3", "show ospfv3");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*OSPFv3", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "HTTP_Server_iosxe": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (params['no_active_sessions'])
        {
          if (preg(string:buf, pattern:"^\s*ip http (secure-)?active-session-modules none", multiline:TRUE))
          {
            return ret;
          }
        }
        if (preg(string:buf, pattern:"^\s*ip http (secure-)?server", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "cdp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*cdp run", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "crypto_map": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto map", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "tunnel_ipsec": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*tunnel protection ipsec", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ospfv3_ipsec": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ospfv3 authentication ipsec", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ptp_clock": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ptp_clock", "show ptp clock");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*PTP CLOCK INFO", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "cluster": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (params['is_member'])
        {
          if (preg(string:buf, pattern:"^\s*cluster commander-address", multiline:TRUE))
            return ret;
        }
        if (preg(string:buf, pattern:"^\s*cluster run", multiline:TRUE))
        {
          ret['flag'] = 1;
          if (params['is_configured'])
          {
            ret['flag'] = 0;
            if (preg(string:buf, pattern:"^\s*cluster (member|commander-address)", multiline:TRUE))
              ret['flag'] = 1;
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nat": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (params['sip_agl_disabled'])
        {
          if (preg(string:buf, pattern:"^\s*no ip nat service sip", multiline:TRUE))
          {
            return ret;
          }
        }
        if (preg(string:buf, pattern:"^\s*ip nat (inside|enable)", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*ip nat (outside|enable)", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*ip nat inside source", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "errdisable_bpduguard": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (preg(string:buf, pattern:"^\s*errdisable detect cause bpduguard shutdown vlan", multiline:TRUE) &&
              (preg(string:buf, pattern:"^\s*spanning-tree\s+portfast bpduguard", multiline:TRUE) ||
               preg(string:buf, pattern:"^\s*spanning-tree bpduguard enable", multiline:TRUE))
           )
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "errdisable_psecure": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var buf2= cisco_command_kb_item("Host/Cisco/Config/show_port-security", "show port-security");
      if (check_cisco_result(buf) && check_cisco_result(buf2))
      {
        if (preg(string:buf, pattern:"^\s*switchport port-security violation shutdown vlan", multiline:TRUE))
        {
          if ("Shutdown Vlan" >< buf2)
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf) || cisco_needs_enable(buf2))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "errdisable_security": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (preg(string:buf, pattern:"^\s*errdisable detect cause security-violation shutdown vlan", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*authentication port-control", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*switchport voice vlan", multiline:TRUE) &&
            !preg(string:buf, pattern:"^\s*authentication violation (protect|replace|restrict)", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ASA_HTTP_Server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*http server enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "IKEv2_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto ikev2 enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
        if (params['check_anyconnect'])
        {
          ret['flag'] = 0;
          if (preg(pattern:"^\s*anyconnect enable", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "CA_Server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto ca server", multiline:TRUE, string:buf))
          ret['flag'] = 1;
        if (params['check_no_shutdown'])
        {
          ret['flag'] = 0;
          if (preg(pattern:"^\s*no shutdown", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "mdm_proxy": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*mdm-proxy", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ssl_vpn": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*webvpn", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "proxy_bypass": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*webvpn", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*proxy-bypass", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "mus": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*webvpn", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*mus server enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "rest_api": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*rest-api image", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*rest-api agent", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "section_call-home": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | section call-home", "show running-config | section call-home");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*call-home", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*active", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "platform_software_et-analytics_interfaces": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show platform software et-analytics interfaces", "show platform software et-analytics interfaces");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ET-Analytics interfaces", multiline:TRUE, string:buf) &&
            (!preg(pattern:"^\s*none", multiline:TRUE, string:buf) ||
             !preg(pattern:"^\s*No interface has ET-Analytics", multiline:TRUE, string:buf)))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "hsrp_v2": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show standby", "show standby");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if ("(version 2)" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "acl_on_gigabit_ethernet_management_interface": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | section interface GigabitEthernet0$", "show running-config | section interface GigabitEthernet0$");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ip access-group", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s*ipv6 traffic-filter", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nbar": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show ip nbar control-plane | include NBAR state", "show ip nbar control-plane | include NBAR state");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*NBAR state is ACTIVATED", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s*NBAR state: ACTIVATED", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "pfrv3": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^domain ", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "smart_license": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*license smart enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "grpc": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*grpc", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ldap": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ldap-server host", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nxos_dot1x": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*feature dot1x", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "aci_secmode_strict": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (!preg(pattern:"^\s*system fabric-security-mode strict", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "vss": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var cdp_buf = cisco_command_kb_item("Host/Cisco/Config/show_cdp", "show cdp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(cdp_buf) && 'cdp is not enabled' >!< tolower(cdp_buf))
      {
        if (check_cisco_result(buf) && !preg(pattern:"^\s*no cdp tlv app", multiline:TRUE, string:buf))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf) || cisco_needs_enable(cdp_buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_webvpn_saml_idp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_webvpn_saml_idp", "show webvpn saml idp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("saml idp" >< buf && "url sign-in" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "sierra_wireless": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show inventory | include Sierra Wireless", "show inventory | include Sierra Wireless");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(
            ("NAME:" >< buf) &&
            ("DESCR:" >< buf)
          )
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    }
};
