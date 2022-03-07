#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126633);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/12 11:40:39");

  script_cve_id("CVE-2019-7956");
  script_bugtraq_id(109088);
  script_xref(name:"IAVA", value:"2019-A-0232");

  script_name(english:"Adobe Dreamweaver <= 18.0 / <= 19.0 DLL Hijacking Privilege Escaalation Vulnerability (APSB19-40)");
  script_summary(english:"Checks the version of Adobe Dreamweaver.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is affected by a DLL hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is a version prior or equal to 18.0 or a version
prior or equal to 19.0. It is, therefore, affected by a DLL hijacking privileges escalation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb19-40.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver 2018 Release or 2019 Release or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7956");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dreamweaver_installed.nasl");
  script_require_keys("installed_sw/Adobe Dreamweaver");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"Adobe Dreamweaver");

constraints = [
  { "fixed_version":"18.1", "fixed_display":"2018 Release"},
  { "min_version":"19.0", "fixed_version":"19.1", "fixed_display":"2019 Release" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
