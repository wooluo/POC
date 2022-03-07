
##
# 
##


include('compat.inc');

if (description)
{
  script_id(150341);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/08");

  script_cve_id(
    "CVE-2021-28551",
    "CVE-2021-28552",
    "CVE-2021-28554",
    "CVE-2021-28631",
    "CVE-2021-28632"
  );

  script_name(english:"Adobe Reader <= 2017.011.30196 / 2020.001.30025 / 2021.001.20155 Multiple Vulnerabilities (APSB21-37)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is a version prior or equal to 2017.011.30196,
2020.001.30025, or 2021.001.20155. It is, therefore, affected by multiple vulnerabilities.

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2021-28551,
    CVE-2021-28554)

  - Use After Free (CWE-416) potentially leading to Arbitrary code execution (CVE-2021-28552, CVE-2021-28631,
    CVE-2021-28632)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-37.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 2017.011.30196 / 2020.001.30025 / 2021.001.20155 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '15.7', 'max_version' : '21.001.20155', 'fixed_version' : '21.005.20148' },
  { 'min_version' : '20.1', 'max_version' : '20.001.30025', 'fixed_version' : '20.004.30005' },
  { 'min_version' : '17.8', 'max_version' : '17.011.30196', 'fixed_version' : '17.011.30197' }
];
vcf::adobe_reader::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, max_segs:3);
