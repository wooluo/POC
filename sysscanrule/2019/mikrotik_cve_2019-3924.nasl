#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123797);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/10 16:10:17");

  script_cve_id("CVE-2019-3924");

  script_name(english:"MikroTik RouterOS Unauthenticated Intermediary");
  script_summary(english:"Checks for RouterOS vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by an unauthenticated
intermediary vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote networking device is running a version of MikroTik
RouterOS vulnerable to an unauthenticated intermediary vulnerability.
Therefore, an unauthenticated remote attacker could use the MikroTik
router to proxy arbitrary traffic or bypass the router's firewall.");
  script_set_attribute(attribute:"see_also", value:"https://www.WebRAY.com/security/research/tra-2019-07");
  script_set_attribute(attribute:"solution", value:"Upgrade to MikroTik RouterOS 6.42.12 / 6.43.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3924");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mikrotik_winbox_detect.nasl");
  script_require_ports("Services/mikrotik_winbox");

  exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

# request to 255.255.255.255 port 80 req: {bff0005:1,u3:4294967295,u4:80,uff0006:1,uff0007:1,s7:'GizaNE',Uff0001:[104]} 
pkt = '\x34\x01\x00\x32\x4d\x32\x05\x00\xff\x01\x03\x00\x00\x08\xff\xff\xff\xff\x04\x00\x00\x09\x50\x06\x00\xff\x09\x01\x07\x00\xff\x09\x01\x07\x00\x00\x21\x06\x6e\x65\x73\x73\x75\x73\x01\x00\xff\x88\x01\x00\x68\x00\x00\x00';

port = get_service(svc:"mikrotik_winbox", exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:pkt);
res = recv(socket:soc, length:1024);
close(soc);

if (!empty_or_null(res) && 'Network is unreachable' >< res)
  security_report_v4(port:port, severity:SECURITY_WARNING);
else
  audit(AUDIT_LISTEN_NOT_VULN,'MikroTik RouterOS' , port);
