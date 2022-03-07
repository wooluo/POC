include("compat.inc");

if (description)
{
  script_id(109552);
  script_version("1.1");
  script_cvs_date("Date: 2018/05/03 19:07:47");

  script_name(english:"Oracle WebLogic T3 Protocol Detection");
  script_summary(english:"Detects the Oracle WebLogic T3 Protocol.");

  script_set_attribute(attribute:"synopsis", value:
"A server that understands T3 was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the WebLogic t3 Protocol.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bea:weblogic_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"Copyright (C) 2004-2018 WebRAY");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", "Services/www", 7001, 7002);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("t3.inc");

# default port list
ports = make_list(7001,7002);

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_unknown_svc_list();
  if (!empty_or_null(additional_ports))
  {
    ports = make_list(ports, additional_ports);
  }
}

# add the weblogic ports to the search
possible_wls_ports = get_kb_list('Services/www');
if (!empty_or_null(possible_wls_ports))
{
  ports = make_list(ports, possible_wls_ports);
}

# remove duplicates and fork!
ports = list_uniq(ports);
port = branch(ports);

if (!get_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port);
}

sock = open_sock_tcp(port);
if (!sock)
{
  audit(AUDIT_SOCK_FAIL, port);
}

version = t3_connect(sock:sock, port:port);
close(sock);

if (empty_or_null(version))
{
  audit(AUDIT_NOT_DETECT, "t3", port);
}

# register and save the version for downstream
register_service(port:port, ipproto:"tcp", proto:"t3");
replace_kb_item(name:"t3/" + port + "/version", value: version);

info = '\nVersion : ' + version + '\n';
security_report_v4(severity:SECURITY_NOTE, port:port, extra:info);
