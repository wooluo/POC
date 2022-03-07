#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127058);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/26 16:07:49");

  script_cve_id("CVE-2019-7238");

  script_name(english:"Sonatype Nexus Repository Manager Missing Access Controls RCE");
  script_summary(english:"Checks the version of the Nexus Repository Manager server.");

  script_set_attribute(attribute:"synopsis", value:
"The Nexus Repository Manager server running on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Sonatype Nexus Repository Manager server application running on
the remote host is version 3.x prior to 3.15.0. It is, therefore, affected 
by a remote code execution vulnerability due to insufficient access controls.
An unauthenticated, remote attacker can exploit this to bypass authentication 
and execute arbitrary commands.");
  # https://support.sonatype.com/hc/en-us/articles/360017310793-CVE-2019-7238-Nexus-Repository-Manager-3-Missing-Access-Controls-and-Remote-Code-Execution-February-5th-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sonatype Nexus Repository Manager version 3.15.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7238");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonatype:nexus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("sonatype_nexus_detect.nbin");
  script_require_ports("Services/www", 8081);
  script_require_keys("installed_sw/Sonatype Nexus");

  exit(0);
}

include('vcf.inc');
include('http.inc');

appname = 'Sonatype Nexus';
port = get_http_port(default:8081);

vcf::add_separator('-'); # used in parsing version for vcf
app = vcf::get_app_info(app:appname, webapp:TRUE, port:port);

constraints = [{'min_version' : '3.0', 'fixed_version' : '3.15.0'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
