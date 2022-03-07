##
# 
##

include('compat.inc');

if (description)
{
  script_id(142467);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id(
    "CVE-2020-24426",
    "CVE-2020-24427",
    "CVE-2020-24428",
    "CVE-2020-24429",
    "CVE-2020-24430",
    "CVE-2020-24431",
    "CVE-2020-24432",
    "CVE-2020-24433",
    "CVE-2020-24434",
    "CVE-2020-24435",
    "CVE-2020-24436",
    "CVE-2020-24437",
    "CVE-2020-24438",
    "CVE-2020-24439"
  );
  script_xref(name:"IAVA", value:"2020-A-0506");

  script_name(english:"Adobe Reader <= 2017.011.30175 / 2020.001.30005 / 2020.012.20048 Multiple Vulnerabilities (APSB20-67)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior or equal to 2017.011.30175,
2020.001.30005, or 2020.012.20048. It is, therefore, affected by multiple vulnerabilities.

  - Heap-based buffer overflow potentially leading to Arbitrary Code Execution (CVE-2020-24435)

  - Improper access control potentially leading to Local privilege escalation (CVE-2020-24433)

  - Improper input validation potentially leading to Arbitrary JavaScript Execution (CVE-2020-24432)

  - Signature validation bypass potentially leading to Minimal (defense-in-depth fix) (CVE-2020-24439)

  - Signature verification bypass potentially leading to Local privilege escalation (CVE-2020-24429)

  - Improper input validation potentially leading to Information Disclosure (CVE-2020-24427)

  - Security feature bypass potentially leading to Dynamic library injection (CVE-2020-24431)

  - Out-of-bounds write potentially leading to Arbitrary Code Execution (CVE-2020-24436)

  - Out-of-bounds read potentially leading to Information Disclosure (CVE-2020-24426, CVE-2020-24434)

  - Race Condition potentially leading to Local privilege escalation (CVE-2020-24428)

  - Use-after-free potentially leading to Arbitrary Code Execution (CVE-2020-24430, CVE-2020-24437)

  - Use-after-free potentially leading to Information Disclosure (CVE-2020-24438)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-67.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30180 or 2020.001.30010 or 2020.013.20064 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Adobe Reader', win_local:TRUE);

# vcf::adobe_reader::check_version_and_report will
# properly separate tracks when checking constraints.
# x.y.30zzz = DC Classic
# x.y.20zzz = DC Continuous
constraints = [
  { 'min_version' : '17.8', 'max_version' : '17.011.30175', 'fixed_version' : '17.011.30180' },
  { 'min_version' :  '20.0', 'max_version' : '20.001.30005', 'fixed_version' : '20.001.30010' },
  { 'min_version' : '15.7', 'max_version' : '20.012.20048', 'fixed_version' : '20.013.20064' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
