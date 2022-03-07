#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124565);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/06 10:10:18");

  script_cve_id(
    "CVE-2012-5883",
    "CVE-2012-6708",
    "CVE-2015-9251",
    "CVE-2018-5407",
    "CVE-2019-4013"
  );
  script_bugtraq_id(
    102792,
    105658,
    105897,
    107870,
    56385
  );
  script_xref(name:"IAVB", value:"2019-B-0029");

  script_name(english:"IBM BigFix Platform 9.5.x < 9.5.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.5.x prior to 9.5.12. 
It is, therefore, affected by multiple vulnerabilities :

  - An arbitrary file upload vulnerability exists in IBM BigFix
    Platform. An authenticated, remote attacker can exploit this
    to upload arbitrary files on the remote host as the root user.
    (CVE-2019-4013)

  - An information disclosure vulnerability exists in IBM BigFix
    Platform due to the PortSmash side-channel attack against
    processors leveraging SMT/Hyper-Threading. An authenticated,
    local attacker can exploit this to disclose potentially 
    sensitive information. (CVE-2018-5407)

  - A cross-site scripting (XSS) vulnerability exists due to 
    improper validation of user-supplied input before returning 
    it to users. An unauthenticated, remote attacker can exploit 
    this, by convincing a user to click a specially crafted URL, 
    to execute arbitrary script code in a user's browser session.
    (CVE-2012-5883, CVE-2012-6708, CVE-2015-9251)

IBM BigFix Platform was formerly known as Tivoli Endpoint Manager,
IBM Endpoint Manager, and IBM BigFix Endpoint Manager.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www-01.ibm.com/support/docview.wss?uid=ibm10874666
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Platform version 9.5.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4013");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

kb_version = "www/BigFixHTTPServer/"+port+"/version";
version = get_kb_item_or_exit(kb_version);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app, port);

app_info = vcf::get_app_info(
  app:app,
  port:port,
  kb_ver:kb_version,
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "9.5", "fixed_version" : "9.5.12" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
