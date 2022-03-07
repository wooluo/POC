#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127127);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/05 11:57:19");

  script_cve_id("CVE-2019-9740");
  script_bugtraq_id(107466);

  script_name(english:"Ansible Tower 3.3.x < 3.3.6 / 3.4.x < 3.4.4 / 3.5.x < 3.5.1 CRLF Vulnerability");
  script_summary(english:"Checks for the product and version in the about page.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
a Unauthorized Access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ansible Tower running on the remote web server is 3.3.x
prior to 3.3.6, 3.4.x prior to 3.4.4, or 3.5.x prior to 3.5.1. It is, 
therefore, affected by a CRLF injection vulnerability in the urllib2 library
of python 2.x through 2.7.16 & python 3.x through 3.7.3.");

  # https://docs.ansible.com/ansible-tower/3.5.1/html/release-notes/relnotes.html#ansible-tower-version-3-5-1
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.ansible.com/ansible-tower/3.4.4/html/release-notes/relnotes.html#ansible-tower-version-3-4-4
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.ansible.com/ansible-tower/3.3.6/html/release-notes/relnotes.html#ansible-tower-version-3-3-6
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ansible Tower version 3.3.6, 3.4.4, 3.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9740");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ansible:tower");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ansible_tower_installed.nbin","ansible_tower_detect.nbin");
  script_require_ports("installed_sw/Ansible Tower", "installed_sw/Ansible Tower WebUI", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if(!isnull(get_kb_item("installed_sw/Ansible Tower")))
  app = vcf::get_app_info(app:"Ansible Tower");
else
{
  port = get_http_port(default:443);
  app = vcf::get_app_info(app:"Ansible Tower WebUI", webapp:TRUE, port:port);
}

constraints = 
[
  {"min_version" : "3.0.0", "fixed_version" : "3.3.6"},
  {"min_version" : "3.4.0", "fixed_version" : "3.4.4"},
  {"min_version" : "3.5.0", "fixed_version" : "3.5.1"},
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
