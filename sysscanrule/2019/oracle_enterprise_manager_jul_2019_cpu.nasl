#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126775);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id(
    "CVE-2018-11775",
    "CVE-2018-1258",
    "CVE-2018-8039",
    "CVE-2019-0222",
    "CVE-2019-1559"
  );
  script_bugtraq_id(
    104222,
    105335,
    106357,
    107174,
    107622
  );
  script_xref(name:"IAVA", value:"2019-A-0251");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jul 2019 CPU)");
  script_summary(english:"Checks for the patch ID.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - An unspecified vulnerability in the Enterprise Manager Base Platform component of
  Oracle Enterprise Manager Products Suite (subcomponent: Connector Framework (Apache CXF)),
  which could allow an unauthenticated, remote attacker to compromise
  Enterprise Manager Base Platform. (CVE-2018-8039)

  - An unspecified vulnerability in the Oracle Enterprise Manager Base Platform component
  of Oracle Enterprise Manager Products Suite (subcomponent: Valid Session (Apache ActiveMQ)),
  which could allow an unauthenticated, remote attacker to compromise
  Oracle Enterprise Manager Base Platform. (CVE-2019-0222)

  - An unspecified vulnerability in the Enterprise Manager Base Platform component of
  Oracle Enterprise Manager Products Suite (subcomponent: Discovery Framework (OpenSSL)), which
  could allow and unauthenticated, remote attacker to compromise
  Enterprise Manager Base Platform. (CVE-2019-1559)
");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.oracle.com/rs?type=doc&id=2534806.1
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019
Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8039");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('oracle_rdbms_cpu_func.inc');
include('install_func.inc');

product = 'Oracle Enterprise Manager Cloud Control';
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patchid = NULL;
missing = NULL;
patched = FALSE;
fix = NULL;

if (version =~ '^13\\.3\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '29835547';
  fix = '13.3.0.0.190716';
}
else if (version =~ '^13\\.2\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '29835501';
  fix = '13.2.0.0.190716';
}
else if (version =~ '^12\\.1\\.0\\.5(\\.[0-9]+)?$')
{
  patchid = '29835388';
  fix = '12.1.0.5.190716';
}

if (isnull(patchid))
  audit(AUDIT_HOST_NOT, 'affected');

# compare version to check if we've already adjusted for patch level during detection
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

# Now look for the affected components
patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));
if (isnull(patchesinstalled))
  missing = patchid;
else
{
  foreach applied (keys(patchesinstalled[emchome]))
  {
    if (applied == patchid)
    {
      patched = TRUE;
      break;
    }
    else
    {
      foreach bugid (patchesinstalled[emchome][applied]['bugs'])
      {
        if (bugid == patchid)
        {
          patched = TRUE;
          break;
        }
      }
      if (patched) break;
    }
  }
  if (!patched)
    missing = patchid;
}

if (empty_or_null(missing))
  audit(AUDIT_HOST_NOT, 'affected');

order = make_list('Product', 'Version', 'Missing patch');
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
