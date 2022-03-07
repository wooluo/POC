#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125736);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/06  4:35:35");

  script_cve_id(
    "CVE-2018-7123",
    "CVE-2019-5355",
    "CVE-2019-5390",
    "CVE-2019-5391",
    "CVE-2019-5392",
    "CVE-2019-5393"
    );
  script_xref(name:"TRA", value:"TRA-2018-28");
  script_xref(name:"TRA", value:"TRA-2019-12");
  script_xref(name:"HP", value:"HPESBHF03930");

  script_name(english:"HPE Intelligent Management Center dbman Multiple Vulnerabilities");
  script_summary(english:"Checks command response");

  script_set_attribute(attribute:"synopsis", value:
"A database backup and restoration tool running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HPE Intelligent Management Center (iMC) dbman process running
on the remote host is affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this issue, via a command 10014 request, to
    cause the dbman process to restart. (CVE-2018-7123)

  - A denial of service (DoS) vulnerability exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this issue, via a command 10003 request, to
    cause the dbman process to stop responding. (CVE-2019-5355)

  - A command injection vulnerability exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this, via a series of specially crafted
    requests, to execute arbitrary commands. (CVE-2019-5390)

  - A stack-based buffer overflow condition exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this, via a series of specially crafted
    requests, to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2019-5391)

  - An information disclosure vulnerability exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this, via a command 10001 request, to
    disclose potentially sensitive information. (CVE-2019-5392)

  - An information disclosure vulnerability exists due to improper
    validation of user-supplied data. An unauthenticated, remote
    attacker can exploit this, via a command 10002 request, to
    backup iMC database files to a directory that allows
    unauthenticated access over HTTP. (CVE-2019-5393)

Note that the HPE iMC running on the remote host is reportedly
affected by additional vulnerabilities; however, this plugin has
not tested for these.");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03930en_us
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade HPE iMC version to 7.3 E0703 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5390");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_dependencies("hp_imc_dbman_detect.nbin");
  script_require_ports("hpe_imc_dbman",2810);
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

port = get_service(svc:'hpe_imc_dbman', default:2810, exit_on_fail:TRUE);
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = '\x00\x00\x27\x25\x00\x00\x00\x00';
send(socket: soc, data: req);
res = recv(socket: soc, length:256);
close(soc);

if(isnull(res))
  audit(AUDIT_RESP_NOT, port, 'a dbman command');

#
# Patched dbman encrypts the command, so an error msg is returned:
#
# 0x00:  00 00 00 01 00 00 00 3A 30 38 02 01 FF 04 33 44    .......:08....3D
# 0x10:  62 6D 61 6E 20 64 65 61 6C 20 6D 73 67 20 65 72    bman deal msg er
# 0x20:  72 6F 72 2C 20 70 6C 65 61 73 65 20 74 6F 20 73    ror, please to s
# 0x30:  65 65 20 64 62 6D 61 6E 5F 64 65 62 75 67 2E 6C    ee dbman_debug.l
# 0x40:  6F 67
#
if('dbman_debug.log' >< res)
  audit(AUDIT_HOST_NOT, 'affected');
else
  security_report_v4(port: port, severity: SECURITY_HOLE);
