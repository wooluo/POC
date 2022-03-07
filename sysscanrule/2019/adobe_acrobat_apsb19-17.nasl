#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124007);
  script_version("1.5");
  script_cvs_date("Date: 2019/05/28 15:40:31");

  script_cve_id(
    "CVE-2019-7061",
    "CVE-2019-7088",
    "CVE-2019-7109",
    "CVE-2019-7110",
    "CVE-2019-7111",
    "CVE-2019-7112",
    "CVE-2019-7113",
    "CVE-2019-7114",
    "CVE-2019-7115",
    "CVE-2019-7116",
    "CVE-2019-7117",
    "CVE-2019-7118",
    "CVE-2019-7119",
    "CVE-2019-7120",
    "CVE-2019-7121",
    "CVE-2019-7122",
    "CVE-2019-7123",
    "CVE-2019-7124",
    "CVE-2019-7125",
    "CVE-2019-7127",
    "CVE-2019-7128"
  );
  script_bugtraq_id(
    107805,
    107809,
    107811,
    107812,
    107815
  );

  script_name(english:"Adobe Acrobat <= 2015.006.30482 / 2017.011.30127 / 2019.010.20098 Multiple Vulnerabilities (APSB19-17)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a
version prior or equal to 2015.006.30482, 2017.011.30127, or
2019.010.20098. It is, therefore, affected by multiple
vulnerabilities.

  - Out-of-Bounds Read potentially leading to Information
    Disclosure (CVE-2019-7061, CVE-2019-7109, CVE-2019-7110,
    CVE-2019-7114, CVE-2019-7115, CVE-2019-7116,
    CVE-2019-7121, CVE-2019-7122, CVE-2019-7123,
    CVE-2019-7127)

  - Out-of-Bounds Write potentially leading to Arbitrary
    Code Execution (CVE-2019-7111, CVE-2019-7118,
    CVE-2019-7119, CVE-2019-7120, CVE-2019-7124)

  - Type Confusion potentially leading to Arbitrary Code
    Execution (CVE-2019-7117, CVE-2019-7128)

  - Use After Free potentially leading to Arbitrary Code
    Execution (CVE-2019-7088, CVE-2019-7112)

  - Heap Overflow potentially leading to Arbitrary Code
    Execution (CVE-2019-7113, CVE-2019-7125)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-17.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30493 or 2017.011.30138 or
2019.010.20099 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7111");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"Adobe Acrobat", win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { "min_version" : "15.6", "max_version" : "15.006.30482", "fixed_version" : "15.006.30493" },
  { "min_version" : "17.8", "max_version" : "17.011.30127", "fixed_version" : "17.011.30138" },
  { "min_version" : "15.7", "max_version" : "19.010.20098", "fixed_version" : "19.010.20099" }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
