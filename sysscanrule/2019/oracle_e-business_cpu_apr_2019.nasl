#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124118);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id(
    "CVE-2018-0734",
    "CVE-2019-2551",
    "CVE-2019-2583",
    "CVE-2019-2600",
    "CVE-2019-2603",
    "CVE-2019-2604",
    "CVE-2019-2621",
    "CVE-2019-2622",
    "CVE-2019-2633",
    "CVE-2019-2638",
    "CVE-2019-2639",
    "CVE-2019-2640",
    "CVE-2019-2641",
    "CVE-2019-2642",
    "CVE-2019-2643",
    "CVE-2019-2651",
    "CVE-2019-2652",
    "CVE-2019-2653",
    "CVE-2019-2654",
    "CVE-2019-2655",
    "CVE-2019-2660",
    "CVE-2019-2661",
    "CVE-2019-2662",
    "CVE-2019-2663",
    "CVE-2019-2664",
    "CVE-2019-2665",
    "CVE-2019-2669",
    "CVE-2019-2670",
    "CVE-2019-2671",
    "CVE-2019-2673",
    "CVE-2019-2674",
    "CVE-2019-2675",
    "CVE-2019-2676",
    "CVE-2019-2677",
    "CVE-2019-2682"
  );

  script_bugtraq_id(
    105758,
    107932,
    107938,
    107942,
    107957
  );

  script_name(english:"Oracle E-Business Suite Multiple Vulnerabilities (Apr 2019 CPU)");
  script_summary(english:"Checks for the April 2019 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the April 2019 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities as noted in the
April 2019 Critical Patch Update advisory :

  - An unspecified flaw exists in the Oracle Advanced Outbound Telephony component of Oracle E-Business Suite which 
    allows a remote unauthenticated attacker to compromise Oracle Advanced Outbound Telephony. (CVE-2019-2663)

  - An unspecified vulnerability in the Oracle Common Applications component of Oracle E-Business Suite which allows a 
    remote unauthenticated attacker to compromise the application. (CVE-2019-2665)

  - An unspecified flaw exists in the Oracle Applications Framework component of Oracle E-Business Suite which allows a 
    remote attacker with HTTP access to compromise the application. (CVE-2019-2682)
 
In addition, Oracle E-Business is also affected by multiple additional
vulnerabilities. Please consult the CVRF details for the applicable
CVEs for additional information.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2663");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:e-business_suite");
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

p12_1 = '29224722';
p12_2 = '29224724';

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
