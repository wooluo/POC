#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127903);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id(
    "CVE-2019-7832",
    "CVE-2019-7965",
    "CVE-2019-8002",
    "CVE-2019-8003",
    "CVE-2019-8004",
    "CVE-2019-8005",
    "CVE-2019-8006",
    "CVE-2019-8007",
    "CVE-2019-8008",
    "CVE-2019-8009",
    "CVE-2019-8010",
    "CVE-2019-8011",
    "CVE-2019-8012",
    "CVE-2019-8013",
    "CVE-2019-8014",
    "CVE-2019-8015",
    "CVE-2019-8016",
    "CVE-2019-8017",
    "CVE-2019-8018",
    "CVE-2019-8019",
    "CVE-2019-8020",
    "CVE-2019-8021",
    "CVE-2019-8022",
    "CVE-2019-8023",
    "CVE-2019-8024",
    "CVE-2019-8025",
    "CVE-2019-8026",
    "CVE-2019-8027",
    "CVE-2019-8028",
    "CVE-2019-8029",
    "CVE-2019-8030",
    "CVE-2019-8031",
    "CVE-2019-8032",
    "CVE-2019-8033",
    "CVE-2019-8034",
    "CVE-2019-8035",
    "CVE-2019-8036",
    "CVE-2019-8037",
    "CVE-2019-8038",
    "CVE-2019-8039",
    "CVE-2019-8040",
    "CVE-2019-8041",
    "CVE-2019-8042",
    "CVE-2019-8043",
    "CVE-2019-8044",
    "CVE-2019-8045",
    "CVE-2019-8046",
    "CVE-2019-8047",
    "CVE-2019-8048",
    "CVE-2019-8049",
    "CVE-2019-8050",
    "CVE-2019-8051",
    "CVE-2019-8052",
    "CVE-2019-8053",
    "CVE-2019-8054",
    "CVE-2019-8055",
    "CVE-2019-8056",
    "CVE-2019-8057",
    "CVE-2019-8058",
    "CVE-2019-8059",
    "CVE-2019-8060",
    "CVE-2019-8061",
    "CVE-2019-8077",
    "CVE-2019-8094",
    "CVE-2019-8095",
    "CVE-2019-8096",
    "CVE-2019-8097",
    "CVE-2019-8098",
    "CVE-2019-8099",
    "CVE-2019-8100",
    "CVE-2019-8101",
    "CVE-2019-8102",
    "CVE-2019-8103",
    "CVE-2019-8104",
    "CVE-2019-8105",
    "CVE-2019-8106"
  );
  script_bugtraq_id(108320);
  script_xref(name:"IAVA", value:"2019-A-0298");

  script_name(english:"Adobe Acrobat <= 2015.006.30498 / 2017.011.30143 / 2019.012.20035 Multiple Vulnerabilities (APSB19-41)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a
version prior or equal to 2015.006.30498, 2017.011.30143, or
2019.012.20035. It is, therefore, affected by multiple
vulnerabilities.

  - Out-of-Bounds Read potentially leading to Information
    Disclosure (CVE-2019-8077, CVE-2019-8094, CVE-2019-8095,
    CVE-2019-8096, CVE-2019-8102, CVE-2019-8103,
    CVE-2019-8104, CVE-2019-8105, CVE-2019-8106,
    CVE-2019-8002, CVE-2019-8004, CVE-2019-8005,
    CVE-2019-8007, CVE-2019-8010, CVE-2019-8011,
    CVE-2019-8012, CVE-2019-8018, CVE-2019-8020,
    CVE-2019-8021, CVE-2019-8032, CVE-2019-8035,
    CVE-2019-8037, CVE-2019-8040, CVE-2019-8043,
    CVE-2019-8052)

  - Out-of-Bounds Write potentially leading to Arbitrary
    Code Execution (CVE-2019-8098, CVE-2019-8100, CVE-2019-7965,
    CVE-2019-8008, CVE-2019-8009, CVE-2019-8016,
    CVE-2019-8022, CVE-2019-8023, CVE-2019-8027)

  - Type Confusion potentially leading to Arbitrary Code
    Execution (CVE-2019-8019)

  - Use After Free potentially leading to Arbitrary Code
    Execution (CVE-2019-8003, CVE-2019-8013, CVE-2019-8024,
    CVE-2019-8025, CVE-2019-8026, CVE-2019-8028,
    CVE-2019-8029, CVE-2019-8030, CVE-2019-8031,
    CVE-2019-8033, CVE-2019-8034, CVE-2019-8036,
    CVE-2019-8038, CVE-2019-8039, CVE-2019-8047,
    CVE-2019-8051, CVE-2019-8053, CVE-2019-8054,
    CVE-2019-8055, CVE-2019-8056, CVE-2019-8057,
    CVE-2019-8058, CVE-2019-8059, CVE-2019-8061)
  
  - Command injection potentially leading to Arbitrary Command
    Execution (CVE-2019-8060)

  - Heap Overflow potentially leading to Arbitrary Code
    Execution (CVE-2019-7832, CVE-2019-8014, CVE-2019-8015,
    CVE-2019-8041, CVE-2019-8042, CVE-2019-8046,
    CVE-2019-8049, CVE-2019-8050)

  - Buffer Error potentially leading to Arbitrary Code
    Execution (CVE-2019-8048)

  - Double Free potentially leading to Arbitrary Code
    Execution (CVE-2019-8044)

  - Integer Overflow potentially leading to Arbitrary Code
    Execution or Denial of Service (CVE-2019-8099, CVE-2019-8101)

  - Internal IP Disclosure potentially leading to Information
    Disclosure (CVE-2019-8097)

  - Type Confusion potentially leading to Arbitrary Code
    Execution (CVE-2019-8019)

  - Untrusted Pointer Dereference potentially leading to 
    Arbitrary Code Execution or Denial of Service (CVE-2019-8006, CVE-2019-8017, CVE-2019-8045)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb19-41.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat version 2015.006.30499 or 2017.011.30144 or 2019.012.20036 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7832");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Adobe Acrobat', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '15.6', 'max_version' : '15.006.30498', 'fixed_version' : '15.006.30499' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30143', 'fixed_version' : '17.011.30144' },
  { 'min_version' : '15.7', 'max_version' : '19.012.20035', 'fixed_version' : '19.012.20036' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);