include('compat.inc');

if (description)
{
  script_id(14272);
  script_version("1.76");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/05/30");

  script_name(english:"Netstat Portscanner (SSH)");
  script_summary(english:"Find open ports with netstat.");

  script_set_attribute(attribute:'synopsis', value:
"Remote open ports can be enumerated via SSH.");
  script_set_attribute(attribute:'description', value:
"GizaNE was able to run 'netstat' on the remote host to enumerate the
open ports.

See the section 'plugins options' about configuring this plugin.

Note: This plugin will run on Windows (using netstat.exe) in the
event that the target being scanned is localhost.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Netstat");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_SCANNER);
  script_family(english:"Port scanners");

  script_copyright(english:"This script is Copyright (C) 2004-2018 and is owned by WebRAY, Inc.");

  script_dependencies("ping_host.nasl", "ssh_settings.nasl", "portscanners_settings.nasl");

  script_timeout(600);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ports.inc");
include("ssh_func.inc");
include("agent.inc");

global_var _ssh_socket;

function run_cmd_by_sshlib(cmd)
{
  local_var session, channel, login_res, escl_method, escl_extra;

  var buf = NULL;
  session = new("sshlib::session");
  login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:FALSE);
  if(!login_res)
  {
    session.close_connection();

    # If it failed, remove the failure so that plugins down the chain can verify after
    # service detection.
    rm_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed");
    return NULL;
  }

  session.set_recv_timeout(60);
  escl_method = get_kb_item(sshlib::SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + "/escalation_type");
  if(!escl_method)
  {
    #buf = session.run_exec_command(command:cmd, timeout:120);
    buf = session.run_exec_command(command:cmd);
    if(empty_or_null(buf))
    {
      channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"));
      if(!isnull(channel))
        buf = session.run_shell_command(channel:channel, command:cmd);
    }
  }
  else
  {
    channel = session.open_shell(shell_handler:new("sshlib::sh_shell_handler"));
    if(!isnull(channel))
    {
      escl_extra = sshlib::get_kb_args(kb_prefix:("Secret/" + sshlib::SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + "/escalation_extra"));
      channel.shell_handler.set_priv_escalation(type:escl_method, extra:escl_extra);
      buf = session.run_shell_command(channel:channel, command:cmd, force_priv_escl:TRUE);
    }
    if(empty_or_null(buf))
    {
      #buf = session.run_exec_command(command:cmd, timeout:120);
      buf = session.run_exec_command(command:cmd);
    }
    if(empty_or_null(buf))
    {
      session.shell_handler.unset_priv_escalation();
      if(!isnull(channel))
        buf = session.run_shell_command(channel:channel, command:cmd);
    }
  }

  session.close_connection();
  return buf;
}

if(isnull(get_kb_item("/tmp_start_time")))
  replace_kb_item(name: "/tmp/start_time", value: unixtime());

disable_ssh_wrappers();
if ( get_kb_item("PortscannersSettings/run_only_if_needed") &&
     get_kb_item("Host/full_scan") )
  exit(0, "The remote host has already been port-scanned.");

# If plugin debugging is enabled, enable packet logging
if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_LOG_PACKETS = TRUE;

buf = "";
ssh_banner = "";
n_tcp = 0; n_udp = 0;

# On the local machine, just run the command
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "The NASL 'pread()' function is not defined.");
  os = get_kb_item("Host/os");
  if ("Windows" >< os)
    netstat_cmd = "C:\Windows\System32\netstat.exe";
  else
    netstat_cmd = "/bin/netstat";
  buf = pread(cmd: netstat_cmd, argv: make_list("netstat", "-a", "-n"));
  if ( buf )
  {
    set_kb_item(name:"Host/netstat", value:buf);
    set_kb_item(name:"Host/netstat/method", value:"local");
    if (agent())
    {
      agent_ip = agent_get_ip();
      if(!isnull(agent_ip))
        report_xml_tag(tag:"host-ip", value:agent_ip);
    }
  }
  else exit(1, "Failed to run the command 'netstat -a -n' on localhost.");
}
else if ( get_kb_item("Secret/SSH/login") )
{
  port22 = kb_ssh_transport();
  if ( port22 && get_port_state(port22) )
  {
    soc = open_sock_tcp(port22);
    if ( soc )
    {
      ssh_banner = recv_line(socket:soc, length:1024);

      if (ssh_banner == "" || isnull(ssh_banner))
        ssh_banner = recv_line(socket:soc, length:1024, timeout:10);

      close(soc);
      if (
         "-cisco-" >< tolower(ssh_banner) ||
         "-cisco_" >< tolower(ssh_banner)
      ) exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
    }
  }

  # Need to set try none for Sonicwall
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);

  if ("force10networks.com" >< ssh_banner) sleep(1);

  ret = ssh_open_connection();

  # nb: Sonicwall needs a delay between the initial banner grab
  #     and  calling 'ssh_open_connection()'.
  if (
    !ret &&
    "please try again" >< get_ssh_error()
  )
  {
    for (i=0; i<5 && !ret; i++)
    {
      # We need to unset login failure if we are going to try again
      if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
      sleep(i*2);
      ret = ssh_open_connection();
    }
  }

  cmd = "cmd /c netstat -an";
  if (ret)
  {
    buf = ssh_cmd(cmd:cmd, timeout:60);
  }
  else
  {
    ssh_close_connection();
  }

  if(!buf) buf = run_cmd_by_sshlib(cmd:cmd);

  if (get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_failed") &&
      get_kb_item("SSH/login/failed"))
  {
    exit(1, "Failed to open an SSH connection.");
  }

  if('Command Line Interface is starting up, please wait' >< buf)
  {
    ssh_close_connection();
    exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
  }

  if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
  {
    # Brocade
    if (
      !buf &&
      'rbash: sh: command not found' >< ssh_cmd_error()
    )
    {
      if(!ret)
      {
        sock_g = ssh_open_connection();
        if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      }

      cmd = "netstat -an";
      buf = ssh_cmd(cmd:cmd, nosh:TRUE, timeout:60);
    }
    # NetApp Data ONTAP
    else if (
      !buf &&
      "cmd not found.  Type '?' for a list of commands" >< ssh_cmd_error()
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }
    #NetApp Data ONTAP clustered
    else if (
      !buf &&
      "Error: Ambiguous command" >< ssh_cmd_error() ||
      "is not a recognized command" >< ssh_cmd_error()
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "system node run -node local -command netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
      if ( !buf && "is not a recognized command" >< ssh_cmd_error() )
      cmd = "node run -node local -command netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
      if ( !buf && "is not a recognized command" >< ssh_cmd_error() )
      cmd = "run -node local -command netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }

    # ScreenOS
    else if (
      !buf &&
      "-NetScreen" >< ssh_banner
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "get socket";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }
    else
    {
      ssh_close_connection();
      cmd = 'netstat -a -n';
      /**
      - sshlib
      -- If there are no escalation credentials
      --- Try exec
      --- If that doesn't work, try sh shell handler
      -- If there are escalation credentials
      --- Try sh shell handler
      --- If that doesn't work
      ---- Try exec without credentials
      ---- If that doesn't work, try sh shell handler without credentials
      - If none of that worked, old lib
      -- ssh_cmd() with no extra args (will be either exec or shell depending on escalation)
      -- If that didn't work
      --- If there were no escalation creds, try noexec:TRUE to force shell
      --- If there were escalation creds
      ---- try ssh_cmd() with nosudo
      ---- if that didn't work, try ssh_cmd() with noexec

      **/
      buf = run_cmd_by_sshlib(cmd: cmd);

      # Try legacy SSH if all of that failed
      if(empty_or_null(buf))
      {
        ret = ssh_open_connection();
        if (!ret) exit(1, "Failed to reopen an SSH connection.");

        buf = ssh_cmd(cmd:cmd, timeout:60);
        if(empty_or_null(buf))
        {
          if(!escl_method)
          {
            buf = ssh_cmd(cmd:cmd, noexec:TRUE, timeout:60);
          }
          else
          {
            buf = ssh_cmd(cmd:cmd, nosudo:TRUE, timeout:60);
            if(empty_or_null(buf))
            {
              buf = ssh_cmd(cmd:cmd, nosudo:TRUE, noexec:TRUE, timeout:60);
            }
          }
        }
      }
    }

    if (
      !buf ||
      "Cmd exec error" >< buf ||
      "Cmd parse error" >< buf ||
      "command parse error before" >< buf ||
      "(Press 'a' to accept):" >< buf ||
      "Syntax error while parsing " >< buf
    ) { ssh_close_connection(); exit(1, "The 'netstat' command failed to be executed."); }
  }
  ssh_close_connection();
  set_kb_item(name:"Host/netstat", value:buf);
  set_kb_item(name:"Host/netstat/method", value:"ssh");
}
else exit(0, "No credentials are available to login to the host.");

ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;

check = get_kb_item("PortscannersSettings/probe_TCP_ports");


if ("yes" >< get_preference("unscanned_closed"))
  unscanned_closed = TRUE;
else
  unscanned_closed = FALSE;

if (unscanned_closed)
{
  tested_tcp_ports = get_tested_ports(proto: 'tcp');
  tested_udp_ports = get_tested_ports(proto: 'udp');
}
else
{
  tested_tcp_ports = make_list();
  tested_udp_ports = make_list();
}

discovered_tcp_ports = make_array();
discovered_udp_ports = make_array();

# to help make the regex a little bit cleaner
ipv4addr = '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+';
ipv6addr = '[a-f0-9:]+(?:%[0-9a-z]+)?';
unspec_ipv4 = '0\\.0\\.0\\.0';
unspec_ipv6 = ':+(?:%[0-9a-z]+)?';

# supports IPv4, IPv6, IPv6 zone ids
win_regex = win_regex = '^[ \t]*(TCP|UDP)[ \t]+(?|(' +ipv4addr+ ')|\\[(' +ipv6addr+ ')\\]|(\\*)):([0-9]+)[ \t]+(?|(' +unspec_ipv4+ ')|(\\[?' +unspec_ipv6+ '\\]?)|(\\*)):(?:[0-9]+|\\*)(?:[ \t]+LISTENING)?';

# unix regex supports ipv6/ipv4 embedded address
# tcp 0 0 ::ffff:192.168.1.3:7001 :::* LISTEN (ipv6/ipv4 embedded address)
nix_regex = '^(tcp|udp)4?6?[ \t].*[ \t]+(?|(?:::ffff[:.])?(' +ipv4addr+ ')|(' +ipv6addr+ ')|(\\*))[:.]([0-9]+)[ \t]+(?|(' +unspec_ipv4+ ')|(' +unspec_ipv6+ ')|(\\*))[:.](?:[0-9]+|\\*)(?:[ \t]+LISTEN)?';

foreach line (lines)
{
  line = chomp(line);
  # Windows
  v = pregmatch(pattern: win_regex, string: line, icase: 0);

  # Unix
  if (isnull(v))
    v = pregmatch(pattern: nix_regex, string: line, icase: 1);

  # Solaris 9 / NetApp
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
      {
        v = pregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
        if (isnull(v)) v = pregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+(\\*\\.\\*|[0-9.]+)[ \t]+[0-9]+[ \t]+[0-9]+$', string: line);
      }
      else
        v = pregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);

      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = pregmatch(pattern: '^(TCP|UDP)(: +IPv4)?[ \t\r\n]*$', string: line);
      if (isnull(v)) v = pregmatch(pattern: '^Active (TCP|UDP) (connections|sockets) \\(including servers\\)[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }

  # ScreenOS
  # Socket  Type   State      Remote IP         Port    Local IP         Port
  #    1  tcp4/6  listen     ::                   0    ::                443
  #    2  tcp4/6  listen     ::                   0    ::                 23
  #    3  tcp4/6  listen     ::                   0    ::                 22
  #   67  udp4/6  open       ::                   0    ::                500
  if (isnull(v))
  {
    v = pregmatch(pattern:'^[ \t]*[0-9]+[ \t]+(tcp|udp)4/6[ \t]+(listen|open)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+([0-9]+)[ \t]*', string:line, icase:TRUE);
    if (!isnull(v))
    {
      proto = v[1];
      state = v[2];
      local_ip = v[4];
      local_port = v[5];

      # "Fix" array
      v[1] = proto;
      v[2] = local_ip;
      v[3] = local_port;
    }
  }

  if (!isnull(v))
  {
    proto = tolower(v[1]);
    addr = v[2];
    port = int(v[3]);
    checktcp = (check && proto == "tcp");

    if (port < 1 || port > 65535)
    {
      spad_log(message:'netstat_portscan(' + get_host_ip() + '): invalid port number ' + port + '\n');
    }

    # no loopback addresses, unless target is localhost
    addr_parts = split(addr, sep:".");
    if ((addr_parts[0] == "127." || addr == "::1") && addr != ip)
      continue;

    if (unscanned_closed)
      if (
        (proto == "tcp" && ! tested_tcp_ports[port]) ||
        (proto == "udp" && ! tested_udp_ports[port])
      ) continue;

    if (
      (proto == "tcp" && discovered_tcp_ports[port]) ||
      (proto == "udp" && discovered_udp_ports[port])
    ) continue;

    if (checktcp)
    {
      soc = open_sock_tcp(port);
      if (soc)
      {
        scanner_add_port(proto: proto, port: port);
        close(soc);
      }
    }
    else
    {
      scanner_add_port(proto: proto, port: port);
    }

    if (proto == "tcp")
    {
      n_tcp ++;
      discovered_tcp_ports[port]++;
    }
    else if (proto == "udp")
    {
      n_udp ++;
      discovered_udp_ports[port]++;
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (scanned)
{
  set_kb_item(name: "Host/scanned", value: TRUE);
  set_kb_item(name: "Host/udp_scanned", value: TRUE);
  set_kb_item(name: "Host/full_scan", value: TRUE);

  set_kb_item(name:"NetstatScanner/TCP/OpenPortsNb", value: n_tcp);
  set_kb_item(name:"NetstatScanner/UDP/OpenPortsNb", value: n_udp);

  set_kb_item(name: "Host/TCP/scanned", value: TRUE);
  set_kb_item(name: "Host/UDP/scanned", value: TRUE);

  set_kb_item(name: "Host/TCP/full_scan", value: TRUE);
  set_kb_item(name: "Host/UDP/full_scan", value: TRUE);

  set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
}

scanner_status(current: n, total: n);
