#TRUSTED 2ee7c624710630d503160b70117ef3f3428a61a57cc82d19332c3f07ebcf1ae3b435684e95d1710eddf2d61d52e27c4238cb691e9ff232cde48b7b88d7bdcd5fa3cd77c770298d41686ce08c2b8151b558108c36d18cec30ddf7f811fb8a8a0c8dabb47230363214d0036fd0533e8f6fc3b1b94b533baa8677ebd636da11de7d77d2aa1fdd7af72813b22be309164f3d43873be878ee2b5070f4ab63e5562cbefb1898d7e4a0e58c73669ed329005723111ab71e79698eea7e52f38f969406a0b1a4f9b7ec291a7019907394a2469c9d90dd6d46d4c88f3cdcfa4ca5927a90e742664ca78f02bfa29cacaf4f3e76495a2c1b254a7c0ec575368b536348f671693944e44654c8d79731d6bf2ff233bf4cae242724177c29bf8e9fd47b793185d6018d95e58860ad67a8d480c74b732f36c307beb100e77759a63177e888178356a3696707db0c141ed84170d9f0e00bbd06108642ca293a717d08c6f36b4ba158e0454b3a18c1950d53b2386142182349661d3545f72ab09c243a0acef25ab5eb2ebe72b34e34bb46709e2dc7781ba48d48161a93005ca5bae2c0813bbdbca3f6aed46323c02ce04fd605ed4cbcfcb2ee2d86db4d879ccdb8447bd7812f380473e8b64fa06f670e5a3d22e9f73f81da8302417c25ec20d67c8c02b574814ad6bbe15038845a4ecc654ae39d517c2e149e4e51891dd06e30da46c1acd239580226
#
# 
#

include("compat.inc");

if (description)
{
  script_id(110267);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/06/04");

  script_name(english:"Apache Zookeeper Server Detection");
  script_summary(english:"Detects an Apache Zookeeper server.");

  script_set_attribute(attribute:"synopsis", value:
"An Apache Zookeeper server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an Apache Zookeeper server.");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl", "process_on_port.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/unknown", 2181);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("lists.inc");
include("install_func.inc");

service_name = "Apache Zookeeper";
protocol = "zookeeper";

ports = make_list(2181);

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_kb_list("Services/unknown");
  if (!isnull(additional_ports))
    ports = make_list(ports, additional_ports);
}

ports = list_uniq(ports);
port = branch(ports);

if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

socket = open_sock_tcp(port);
if (!socket)
  audit(AUDIT_SOCK_FAIL, port);

send(socket:socket, data:"stat");
response = recv(socket:socket, length:2048);
close(socket);
if (empty_or_null(response))
  audit(AUDIT_NOT_DETECT, service_name, port);

match = pregmatch(pattern:"Zookeeper version: ([0-9.]+)[-,]", string:response);
if (empty_or_null(match) || empty_or_null(match[1]))
  audit(AUDIT_NOT_DETECT, service_name, port);

version = match[1];

register_service(port:port, ipproto:"tcp", proto:"zookeeper");
replace_kb_item(name:"zookeeper/" + port + "/version", value:version);

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else
  disable_ssh_wrappers();

uname = get_kb_item("Host/uname");
proto = get_kb_item("HostLevelChecks/proto");
cmdline = base64_decode(str:get_kb_item("Host/Listeners/tcp/"+port+"/cmdline"));

if (('Linux' >< uname || 'AIX' >< uname) && proto && cmdline)
{
  if (proto == 'local')
  {
    info_t = INFO_LOCAL;
  }
  else if (proto == 'ssh')
  {
    sock_g = ssh_open_connection();
    if (sock_g) info_t = INFO_SSH;
  }
  if (info_t)
  {
    match = pregmatch(pattern:"(?<=-cp\x00)([^\x00]+)", string:cmdline);
    if(match && match[1])
    {
      class_paths = split(match[1], sep:':', keep:FALSE);
      match = collib::filter(f:function ()
          {return _FCT_ANON_ARGS[0] =~ "/.*?zookeeper[^/]*\.jar$";}, class_paths);
      if (match && max_index(match) == 1)
      {
        jar_path = dirname(match[0]);
        res = info_send_cmd(cmd:'cd "'+ jar_path +'" && pwd');
        if (res)
          jar_path = res;
      }
    }
    conf_path = pregmatch(pattern:"([^\x00]+?zoo\.cfg)",string:cmdline);
    if (conf_path && conf_path[1])
      res = '';
      res = info_send_cmd(cmd:'cat "'+ conf_path[1] +'"');
    if (res)
    {
      match = pregmatch(pattern:"(?m)^\s*?clientPort=([0-9]+)", string:res, icase:TRUE);
      if (match && match[1] && match[1] == port)
      {
        config = res;
      }
    }
  }

  if (sock_g)
    ssh_close_connection();
}

if (jar_path && config)
{
  register_install(
    app_name:service_name,
    port:port,
    path:jar_path,
    version:version,
    extra_no_report:{'config': config},
    cpe: "cpe:/a:apache:zookeeper"
  );
  report_installs(app_name:service_name);
}
else
{
  info = '\n  Version : ' + version + '\n';
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:info);
}
