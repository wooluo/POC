#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125264);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/28 10:05:53");

  script_cve_id(
    "CVE-2019-10127",
    "CVE-2019-10128",
    "CVE-2019-10129",
    "CVE-2019-10130"
  );

  script_name(english:"PostgreSQL 9.4.x < 9.4.22 / 9.5.x < 9.5.17 / 9.6.x < 9.6.13 / 10.x < 10.8 / 11.x < 11.3 Multiple vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.4.x prior to 9.4.22, 9.5.x prior to 9.5.17, 9.6.x prior to
9.6.13, 10.x prior to 10.8, or 11.x prior to 11.3. It is, therefore, affected by multiple vulnerabilities.

  - A remote code execution vulnerability exists in both, the BigSQL and the EnterpriseDB Windows installers due to the
    installers not locking down the permissions of the PostgreSQL binary installation directory and the data directory.
    An authenticated, local attacker can exploit this, to cause the PostgreSQL service account to execute arbitrary
    code.
    (CVE-2019-10127, CVE-2019-10128)

  - A memory disclosure vulnerability exists in the partition routing component. An authenticated, remote attacker can
    exploit this, via the execution of a crafted INSERT statement to a partitioned table to disclose memory contents.
    (CVE-2019-10129)

  - A security bypass vulnerability exists in the core server. An authenticated, remote attacker can exploit this, via
    the execution of a crafted SQL query with a leaky operator to disclose potentially sensitive information.
    (CVE-2019-10130)
");
  # https://www.postgresql.org/about/news/1939/
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to PostgreSQL 9.4.22 / 9.5.17 / 9.6.13 / 10.8 / 11.3 or later.");

  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10127");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
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
  { 'min_version' : '9.4.0', 'fixed_version' : '9.4.22' },
  { 'min_version' : '9.5.0', 'fixed_version' : '9.5.17' },
  { 'min_version' : '9.6.0', 'fixed_version' : '9.6.13' },
  { 'min_version' : '10.0', 'fixed_version' : '10.8' },
  { 'min_version' : '11.0', 'fixed_version' : '11.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
