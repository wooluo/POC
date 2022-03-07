#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121250);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id(
  "CVE-2019-2396",
  "CVE-2019-2400",
  "CVE-2019-2445",
  "CVE-2019-2447",
  "CVE-2019-2453",
  "CVE-2019-2470",
  "CVE-2019-2485",
  "CVE-2019-2488",
  "CVE-2019-2489",
  "CVE-2019-2491",
  "CVE-2019-2492",
  "CVE-2019-2496",
  "CVE-2019-2497",
  "CVE-2019-2498",
  "CVE-2019-2546"
  );
  script_bugtraq_id(
    106620,
    106624
  );


  script_name(english:"Oracle E-Business Multiple Vulnerabilities (Jan 2019 CPU)");
  script_summary(english:"Checks for the January 2019 CPU.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the January 2019 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities as noted in the
January 2019 Critical Patch Update advisory :

  - Oracle CRM Technical Foundation Messages component is easily 
    exploited by an unauthenticated attacker. A successful attack 
    requires human interaction from a person other than the attacker. 
    Successful attacks can result in unauthorized update, insert, or 
    delete access. (CVE-2019-2396)

  - Oracle iStore User Registration component of Oracle E-Business 
    Suite is easily exploited and allows an unauthenticated 
    attacker to compromise Oracle iStore. Successful attacks require 
    human interaction from a person other than the attacker and can 
    result in unauthorized access to critical data or complete 
    access to all Oracle iStore accessible data as well as 
    unauthorized update, insert, or delete access. (CVE-2019-2400)

  - Oracle Marketing User Interface component of Oracle E-Business 
    Suite is easily exploited and allows an unauthenticated 
    attacker to compromise Oracle Marketing. Successful attacks 
    require human interaction from a person other than the 
    attacker and can result in unauthorized access to critical data 
    or complete access to all Oracle Marketing accessible data as 
    well as unauthorized update, insert, or delete access. 
    (CVE-2019-2440) 

  - Oracle Content Manager Cover Letter component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker to compromise Oracle Content Manager. 
    Successful attacks require human interaction from a person other 
    than the attacker and can result in unauthorized access to 
    critical data or complete access to all Oracle Content Manager 
    accessible data as well as unauthorized update, insert or delete 
    access. (CVE-2019-2445) 

  - Oracle Partner Management Partner Detail component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker with network access via HTTP to 
    compromise Oracle Partner Management. Successful attacks require 
    human interaction from a person other than the attacker and can 
    result in unauthorized access to critical data or complete access
    to all Oracle Partner Management accessible data as well as 
    unauthorized update, insert or delete. (CVE-2019-2447)

  - Oracle Performance Management Performance Management Plan 
    component of Oracle E-Business Suite is easily exploited and 
    allows unauthorized creation, deletion or modification access to 
    critical data and complete access to all Oracle Performance 
    Management accessible data. (CVE-2019-2453)

  - Oracle Partner Management Partner Detail component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker to gain unauthorized access to critical 
    data as well as unauthorized update, insert or delete access to 
    some of Oracle Partner Management accessible data. (CVE-2019-2470)

  - Oracle Mobile Field Service Administration component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker the ability to perform unauthorized 
    update, insert or delete of data. (CVE-2019-2485)
  
  - Oracle CRM Technical Foundation Session Management component of 
    Oracle E-Business Suite is easily exploited and allows an 
    unauthenticated attacker to obtain unauthorized read access data.
    (CVE-2019-2488)

  - Oracle One-to-One Fulfillment OCM Query component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker with the ability to perform 
    unauthorized creation, deletion or modification access to 
    critical data as well as unauthorized access all data. 
    (CVE-2019-2489)

  - Oracle Email Center Message Display component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker with the ability to perform an 
    unauthorized update, insert or delete access to some of Oracle 
    Email Center accessible data. (CVE-2019-2491)

  - Oracle Email Center Message Display component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker with the ability to perform an 
    unauthorized update, insert or delete access to some of 
    Oracle Email Center accessible data. (CVE-2019-2492)

  - Oracle CRM Technical Foundation Messages component of Oracle 
    E-Business Suite is easily exploited and allows an
    unauthenticated attacker with the ability to perform an 
    unauthorized update, insert or delete access to some of Oracle 
    CRM Technical Foundation accessible data.  (CVE-2019-2496)

  - Oracle CRM Technical Foundation Messages component of Oracle 
    E-Business Suite is easily exploited and allows an 
    unauthenticated attacker with the ability to perform an 
    unauthorized update, insert or delete access to some of Oracle 
    CRM Technical Foundation accessible data.  (CVE-2019-2497)

  - Oracle Partner Management Partner Dash board component of Oracle 
    E-Business Suite is easily exploited and allows an
    unauthenticated attacker with the ability to perform an 
    unauthorized update, insert or delete access to some of Oracle 
    CRM Technical Foundation accessible data.  (CVE-2019-2498)

  - Oracle Applications Manager SQL Extensions component of Oracle 
    E-Business Suite is easily exploited and allows an
    unauthenticated attacker with the ability to perform an 
    unauthorized update, insert or delete access to some of Oracle 
    CRM Technical Foundation accessible data.  (CVE-2019-2546)

In addition, Oracle E-Business is also affected by multiple additional
vulnerabilities. Please consult the CVRF details for the applicable
CVEs for additional information.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2489");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:e-business_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '28840561';
p12_2 = '28840562';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2),
  '12.2.7', make_list(p12_2)
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
  if(!patched) patchreport = join(patchids,sep:" or ");
}

if (!patched && affectedver)
  {
  report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_report_v4(port:0,extra:report,severity:SECURITY_HOLE);
  }
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
