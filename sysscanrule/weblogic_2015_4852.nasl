include("compat.inc");

if (description)
{
  script_id(87011);
  script_version("1.17");
  script_cvs_date("Date: 2018/05/03 19:07:47");

  script_cve_id("CVE-2015-4852");
  script_bugtraq_id(77539);
  script_osvdb_id(129952, 130288, 130424);
  script_xref(name:"CERT", value:"576313");
  script_xref(name:"IAVA", value:"2015-A-0287");

  script_name(english:"Oracle WebLogic Java Object Deserialization RCE");
  script_summary(english:"Sends an unexpected Java object to the server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle WebLogic server is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle WebLogic server is affected by a remote code
execution vulnerability in the WLS Security component due to unsafe
deserialize calls of unauthenticated Java objects to the Apache
Commons Collections (ACC) library. An unauthenticated, remote attacker
can exploit this to execute arbitrary Java code in the context of the
WebLogic server.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"Copyright (C) 2015-2018 WebRAY.");

  script_dependencies("weblogic_detect.nasl","t3_detect.nasl");
  script_require_ports("Services/t3", 7001);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("t3.inc");

appname = "Oracle WebLogic Server";

port = get_service(svc:'t3', default:7001, exit_on_fail:TRUE);

# Try to talk T3 to the server
sock = open_sock_tcp(port);
if (!sock) audit(AUDIT_SOCK_FAIL, port);
version = t3_connect(sock:sock, port:port);

# send ident so we can move on to login
t3_send_ident_request(sock:sock, port:port);

# send our "login request"
auth_request = '\x05\x65\x08\x00\x00\x00\x01\x00\x00\x00\x1b\x00\x00\x00\x5d\x01\x01\x00\x73\x72\x01\x78\x70\x73\x72\x02\x78\x70\x00\x00\x00\x00\x00\x00\x00\x00\x75\x72\x03\x78\x70\x00\x00\x00\x00\x78\x74\x00\x08\x77\x65\x62\x6c\x6f\x67\x69\x63\x75\x72\x04\x78\x70\x00\x00\x00\x0c\x9c\x97\x9a\x9a\x8c\x9a\x9b\xcf\xcf\x9b\x93\x9a\x74\x00\x08\x77\x65\x62\x6c\x6f\x67\x69\x63\x06\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x02\x5b\x42\xac\xf3\x17\xf8\x06\x08\x54\xe0\x02\x00\x00\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x10\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x56\x65\x63\x74\x6f\x72\xd9\x97\x7d\x5b\x80\x3b\xaf\x01\x03\x00\x03\x49\x00\x11\x63\x61\x70\x61\x63\x69\x74\x79\x49\x6e\x63\x72\x65\x6d\x65\x6e\x74\x49\x00\x0c\x65\x6c\x65\x6d\x65\x6e\x74\x43\x6f\x75\x6e\x74\x5b\x00\x0b\x65\x6c\x65\x6d\x65\x6e\x74\x44\x61\x74\x61\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00';
# this is an org.apache.commons.collections.functors.ConstantTransforms object
# that is part of the deserialization blacklist.
auth_request += '\xac\xed\x00\x05\x73\x72\x00\x3b\x6f\x72\x67\x2e\x61\x70\x61\x63\x68\x65\x2e\x63\x6f\x6d\x6d\x6f\x6e\x73\x2e\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2e\x66\x75\x6e\x63\x74\x6f\x72\x73\x2e\x43\x6f\x6e\x73\x74\x61\x6e\x74\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x58\x76\x90\x11\x41\x02\xb1\x94\x02\x00\x01\x4c\x00\x09\x69\x43\x6f\x6e\x73\x74\x61\x6e\x74\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x78\x70\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e\x74\x65\x67\x65\x72\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6c\x75\x65\x78\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4e\x75\x6d\x62\x65\x72\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00\x78\x70\x00\x00\x00\x01';
auth_request += '\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x25\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x49\x6d\x6d\x75\x74\x61\x62\x6c\x65\x53\x65\x72\x76\x69\x63\x65\x43\x6f\x6e\x74\x65\x78\x74\xdd\xcb\xa8\x70\x63\x86\xf0\xba\x0c\x00\x00\x78\x72\x00\x29\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6d\x69\x2e\x70\x72\x6f\x76\x69\x64\x65\x72\x2e\x42\x61\x73\x69\x63\x53\x65\x72\x76\x69\x63\x65\x43\x6f\x6e\x74\x65\x78\x74\xe4\x63\x22\x36\xc5\xd4\xa7\x1e\x0c\x00\x00\x78\x70\x77\x02\x06\x00\x73\x72\x00\x26\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6d\x69\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x4d\x65\x74\x68\x6f\x64\x44\x65\x73\x63\x72\x69\x70\x74\x6f\x72\x12\x48\x5a\x82\x8a\xf7\xf6\x7b\x0c\x00\x00\x78\x70\x77\x34\x00\x2eauthenticate\x28\x4c\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x61\x63\x6c\x2eUserInfo\x3b\x29\x00\x00\x00\x1b\x78\x78\xfe\x00\xff';
send_t3(sock:sock, data:auth_request);

# read in the response to our bad login request
return_val = recv_t3(sock:sock);
close(sock);

if (isnull(return_val) ||
  "org.apache.commons.collections.functors.ConstantTransformer cannot be cast to" >!< return_val)
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);

report =
  '\nWe can exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);