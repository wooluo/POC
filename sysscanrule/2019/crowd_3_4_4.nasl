#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(125477);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id("CVE-2019-11580");

  script_name(english:"Atlassian Crowd 2.1.x < 3.0.5 / 3.1.x < 3.1.6 / 3.2.x < 3.2.8 / 3.3.x < 3.3.5 / 3.4.x < 3.4.4 RCE Vulnerability");
  script_summary(english:"Checks the version of Crowd");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Crowd installed on the remote host is affected
by an remote code execution (RCE) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Crowd installed on the remote host is 2.1.x prior
to 3.0.5, 3.1.x prior to 3.1.6, 3.2.x prior to 3.2.8, 3.3.x prior to 3.3.5 
or 3.4.x prior to 3.4.4. It is, therefore, affected by a remote code execution
(RCE) vulnerability. An unauthenticated, remote attacker can exploit this, by
using pdkinstall development plugin, to install arbitrary plugins, which permits
remote code execution.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
#https://confluence.atlassian.com/crowd/crowd-security-advisory-2019-05-22-970260700.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.0.5, 3.1.6, 3.2.8, 3.3.5, 3.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11580");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:crowd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");


  script_dependencies("crowd_detect.nasl","os_fingerprint.nasl");
  script_require_keys("www/crowd");
  script_require_ports("Services/www", 8095);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:8095);

app = "crowd";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.1.0", "fixed_version" : "3.0.5" },
  { "min_version" : "3.1.0", "fixed_version" : "3.1.6" },
  { "min_version" : "3.2.0", "fixed_version" : "3.2.8" },
  { "min_version" : "3.3.0", "fixed_version" : "3.3.5" },
  { "min_version" : "3.4.0", "fixed_version" : "3.4.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
