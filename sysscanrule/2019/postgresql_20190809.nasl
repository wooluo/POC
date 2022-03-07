#
# (C) WebRAY Network Security, Inc
#

include("compat.inc");

if (description)
{
  script_id(127906);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16 13:04:23");

  script_cve_id("CVE-2019-10209");
  script_xref(name:"IAVB", value:"2019-B-0072");

  script_name(english:"PostgreSQL 11.x < 11.5 Memory disclosure in cross-type comparison for hashed subplan");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 11.x prior
to 11.5. It is, therefore, affected by a memory disclosure
vulnerability that allows an attacker to read arbitrary bytes of
server memory.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1960/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/11/release-11-5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10209");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('vcf.inc');
include('backport.inc');

app = 'PostgreSQL';
port = get_service(svc:'postgresql', default:5432, exit_on_fail:TRUE);
kb_base = 'database/' + port + '/postgresql/';
kb_ver = kb_base + 'version';
get_kb_item_or_exit(kb_ver);

kb_backport = NULL;
source = get_kb_item_or_exit(kb_base + 'source');
get_backport_banner(banner:source);
if (backported) kb_backport = kb_base + 'backported';

app_info = vcf::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);

constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
