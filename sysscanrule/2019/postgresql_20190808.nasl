#
# (C) WebRAY Network Security, Inc
#

include("compat.inc");

if (description)
{
  script_id(127905);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16 13:04:23");

  script_cve_id(
    "CVE-2019-10208",
    "CVE-2019-10210",
    "CVE-2019-10211"
  );
  script_xref(name:"IAVB", value:"2019-B-0072");

  script_name(english:"PostgreSQL 9.4.x < 9.4.24 / 9.5.x < 9.5.19 / 9.6.x < 9.6.15 / 10.x < 10.10 / 11.x < 11.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.4.x
prior to 9.4.24, 9.5.x prior to 9.5.19, 9.6.x prior to 9.6.15,
10.x prior to 10.10, or 11.x prior to 11.5. It is, therefore, affected
by multiple vulnerabilities :

  - An unspecified vulnerability that allows an attacker to execute arbitrary
    SQL as the function's owner. (CVE-2019-10208)

  - An insecure password handling vulnerability exists in the
    EnterpriseDB Windows intstaller due to use of a temporary file.
    An attack can exploit this to read the PostgreSQL superuser
    password from the file. (CVE-2019-10210)

  - An arbitrary code execution vulnerability exists in libeay32.dll
    due to use of a hard-coded configuration directory. An attacker
    can exploit this to load and execute arbitrary code as the user
    running a PostgreSQL server or client. (CVE-2019-10211)");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1960/");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.4/release-9-4-24.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.5/release-9-5-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.6/release-9-6-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/10/release-10-10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/11/release-11-5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.4.24 / 9.5.19 / 9.6.15 /
10.10 / 11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10208");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
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
  { 'min_version' : '9.4.0', 'fixed_version' : '9.4.24' },
  { 'min_version' : '9.5.0', 'fixed_version' : '9.5.19' },
  { 'min_version' : '9.6.0', 'fixed_version' : '9.6.15' },
  { 'min_version' : '10.0', 'fixed_version' : '10.10' },
  { 'min_version' : '11.0', 'fixed_version' : '11.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
