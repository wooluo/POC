#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124022);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/30  6:26:38");

  script_cve_id("CVE-2019-7107");
  script_bugtraq_id(107821);
  script_xref(name:"IAVA", value:"2019-A-0105");

  script_name(english:"Adobe InDesign < 13.1.1 / 14.x < 14.0.2 Arbitrary Code Execution Vulnerability (APSB19-23)");
  script_summary(english:"Checks the Adobe InDesign version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by Arbitrary Code Execution Vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host
is prior to 13.1.1, or 14.x prior to 14.0.2. It is, therefore,
affected by an Arbitrary Code Execution vulnerability due to unsafe
hyperlink processing in the Webkit component of MacOS. An
authenticated, remote attacker can exploit this issue to cause
execution of arbitary code or the application to stop responding.");
  # https://helpx.adobe.com/security/products/indesign/apsb19-23.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
    "Upgrade to Adobe InDesign version 13.1.1 / 14.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7107");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign_cc");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

constraints = [
  { 'fixed_version' : '13.1.1' },
  { 'min_version': '14.0', 'fixed_version' : '14.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
