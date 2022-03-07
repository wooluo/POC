#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124026);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/12 14:48:49");

  script_cve_id("CVE-2019-7097");
  script_bugtraq_id(107825);
  script_xref(name:"IAVA", value:"2019-A-0104");

  script_name(english:"Adobe Dreamweaver < 19.1 Information Disclosure Vulnerability (APSB19-21)");
  script_summary(english:"Checks the version of Adobe Dreamweaver.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Dreamweaver installed on the remote Windows
host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows
host is a version prior to 19.1. It is, therefore, affected
by an information disclosure vulnerability which could lead to 
sensitive data disclosure if SMB request is subjected to a relay 
attack

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb19-21.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver 19.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7097");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");

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

constraints = [{ "fixed_version" : "19.1" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
