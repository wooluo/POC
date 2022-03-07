#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128055);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/22  6:34:48");

  script_cve_id("CVE-2019-3397");
  script_bugtraq_id(108447);

  script_name(english:"Atlassian Bitbucket Data Center 5.13.x < 5.13.6 / 5.14.x < 5.14.4 / 5.15.x < 5.15.3 / 5.16.x < 5.16.3 / 6.0.x < 6.0.3 / 6.1.x < 6.1.2 Path Traversal Vulnerability (SA-2019-05-22)");
  script_summary(english:"Checks the version of Bitbucket Data Center");

  script_set_attribute(attribute:"synopsis", value:
"The version of Atlassian Bitbucket Data Center installed on the remote host is affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"Atlassian Bitbucket Data Center licensed instances starting with version 5.13.0 before 5.13.6 (the fixed version for
5.13.x), from 5.14.0 before 5.14.4 (fixed version for 5.14.x), from 5.15.0 before 5.15.3 (fixed version for 5.15.x),
from 5.16.0 before 5.16.3 (fixed version for 5.16.x), from 6.0.0 before 6.0.3 (fixed version for 6.0.x), and from
6.1.0 before 6.1.2 (the fixed version for 6.1.x) allow remote attackers who have admin permissions to achieve remote
code execution on a Bitbucket server instance via path traversal through the Data Center migration tool.

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://confluence.atlassian.com/bitbucketserver/bitbucket-server-security-advisory-2019-05-22-969526871.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.13.6 / 5.14.4 / 5.15.3 / 5.16.3 / 6.0.3 / 6.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3397");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:bitbucket");
  script_set_attribute(attribute:"potential_vulnerability",value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("bitbucket_detect.nbin","os_fingerprint.nasl");
  script_require_keys("www/bitbucket", "Settings/ParanoidReport");
  script_require_ports("Services/www", 7990);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:7990);

app = 'bitbucket';

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

#
# We cannot remotely differenciate Bitbucket and Bitbucket Data Center
#
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [
  { 'min_version' : '5.13.0', 'fixed_version' : '5.13.6' },
  { 'min_version' : '5.14.0', 'fixed_version' : '5.14.4' },
  { 'min_version' : '5.15.0', 'fixed_version' : '5.15.3' },
  { 'min_version' : '5.16.0', 'fixed_version' : '5.16.3' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.3' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
