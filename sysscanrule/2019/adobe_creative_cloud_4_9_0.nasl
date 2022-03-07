#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127896);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16  9:12:01");

  script_cve_id(
    "CVE-2019-8063",
    "CVE-2019-7957",
    "CVE-2019-7958",
    "CVE-2019-7959"
  );
  script_xref(name:"IAVA", value:"2019-A-0295");

  script_name(english:"Adobe Creative Cloud Desktop <= 4.6.1.393 Multiple Vulnerabilities (APSB19-39)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote
Windows host is equal or prior to 4.6.1.393. It is, therefore,
affected by multiple vulnerabilities. The most critical of which allows
an attacker to perform arbitrary code execution in the context of the
current user.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb19-39.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 4.9.0.504 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7959");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Adobe Creative Cloud");

  exit(0);
}

include('vcf.inc');

app = 'Adobe Creative Cloud';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'max_version' : '4.6.1.393', 'fixed_version' : '4.9.0.504' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
