#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125223);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/16 11:27:08");

  script_cve_id("CVE-2019-9847");

  script_name(english:"LibreOffice < 6.1.6, 6.2.x < 6.2.3 Hyperlink Processing Vulnerability (Windows)");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a hyperlink processing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is prior to 6.1.6 or 6.2.x prior to 6.2.3. It 
is, therefore, affected by a hyperlink processing vulnerability. At attacker may exploit this issue by creating 
hyperlinks pointing to an executable on the target user's file system. This hyperlink is unconditionally launched as 
there is no judgement made on whether the target of the hyperlink is an executable file.

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://www.libreoffice.org/about-us/security/advisories/CVE-2019-9847
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 6.1.6 / 6.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9847");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'LibreOffice');

constraints = [
  {'fixed_version':'6.1.6'},
  {'min_version':'6.2.0', 'fixed_version':'6.2.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
