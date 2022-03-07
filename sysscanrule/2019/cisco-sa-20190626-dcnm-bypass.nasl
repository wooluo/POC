#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126643);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id("CVE-2019-1619");
  script_bugtraq_id(108902);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo64641");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190626-dcnm-bypass");
  script_xref(name:"IAVA", value:"2019-A-0221");

  script_name(english:"Cisco Data Center Network Manager < 11.1(1) Authentication Bypass Vulnerability");
  script_summary(english:"Checks the version of Cisco Data Center Network Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Data
Center Network Manager (DCNM) could allow an unauthenticated, remote
attacker to bypass authentication and execute arbitrary actions with
administrative privileges on an affected device. The vulnerability is
 due to improper session management on affected DCNM software.
 An attacker could exploit this vulnerability by sending a crafted
 HTTP request to the affected device. A successful exploit could
 allow the attacker to gain administrative access on the affected
 device.

According to its self-reported version, Cisco Data Center Network
Manager is affected by a vulnerability. Please see the included Cisco
BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190626-dcnm-bypass
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo64641");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo64641");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1619");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/cisco_dcnm_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Cisco Prime DCNM";
app_id  = "cisco_dcnm_web";
get_install_count(app_name:app_id, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app_id, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];

match = pregmatch(string:ver, pattern:"^([0-9.]+)\(([^)]+)\)");
if (isnull(match)) exit(1, "Failed to parse the version ("+ver+").");

major = match[1];
build = match[2];

version = major + '.' + build;

# Version 11.0(1) is not vulnerable as stated in the advisory
if (major == '11.0' && build = '1') audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, ver);

if (ver_compare(ver:version, fix:'11.1.1', strict:FALSE) < 0)
{

  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 11.1(1)' +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}

else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, ver);