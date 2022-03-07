#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126789);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 10:38:51");

  script_cve_id(
    "CVE-2019-2828",
    "CVE-2019-2775",
    "CVE-2019-2782",
    "CVE-2019-2837",
    "CVE-2019-2829",
    "CVE-2019-2666",
    "CVE-2019-2668",
    "CVE-2019-2672",
    "CVE-2019-2825",
    "CVE-2019-2773",
    "CVE-2019-2783",
    "CVE-2019-2809",
    "CVE-2019-2761"
  );
  script_bugtraq_id(
    109261,
    109263,
    109264,
    109265,
    109266,
    109230,
    109246
  );
  script_xref(name:"IAVA", value:"2019-A-0258");

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (Jul 2019 CPU)");
  script_summary(english:"Checks for the July 2019 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2019 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities as noted in the
July 2019 Critical Patch Update advisory :

 - An unspecified vulnerability in the Oracle Field Service component
   of Oracle E-Business Suite subcomponent Wireless, which could allow
   an unauthenticated, remote attacker via HTTP to compromise Oracle
   Field Service which can result in takeover of Oracle Field Service.
   (CVE-2019-2828)


 - An unspecified vulnerability in the Oracle Payments component of
   Oracle E-Business Suite subcomponent Transmission, which could allow
   an unauthenticated, remote attacker via HTTP to compromise Oracle
   Payments which can result in unauthorized creation, deletion or
   modification access to critical data or all Oracle Payments accessible
   data and unauthorized ability to cause a hang or frequently repeatable
   crash (complete denial of service) of Oracle Payments. (CVE-2019-2775)


 - An unspecified vulnerability in the Oracle Payments component of
   Oracle E-Business Suite subcomponent Transmission, which could allow
   an unauthenticated, remote attacker via HTTP to compromise Oracle
   Payments which can result in an unauthorized access to critical data
   or complete access to all Oracle Payments accessible data.
   (CVE-2019-2782)

In addition, Oracle E-Business is also affected by multiple additional
vulnerabilities. Please consult the CVRF details for the applicable
CVEs for additional information.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2828");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

version = get_kb_item_or_exit('Oracle/E-Business/Version');
patches = get_kb_item_or_exit('Oracle/E-Business/patches/installed');

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '29692308';
p12_2 = '29692310';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2),
  '12.2.7', make_list(p12_2),
  '12.2.8', make_list(p12_2)
);
patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  foreach required_patch (patchids)
  {
    foreach applied_patch (patches)
    {
      if(required_patch == applied_patch)
      {
        patched = applied_patch;
        break;
      }
    }
    if(patched) break;
  }
  if(!patched) patchreport = join(patchids, sep:' or ');
}

if (!patched && affectedver)
 {
  report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + version + ' Patch ' + patchreport +
      '\n';
    security_report_v4(port:0,extra:report,severity:SECURITY_HOLE);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
