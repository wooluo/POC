#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124027);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/12 15:00:03");

  script_cve_id(
    "CVE-2019-7098",
    "CVE-2019-7099",
    "CVE-2019-7100",
    "CVE-2019-7101",
    "CVE-2019-7102",
    "CVE-2019-7103",
    "CVE-2019-7104"
  );
  script_xref(name:"IAVA", value:"2019-A-0103");

  script_name(english:"Adobe Shockwave Player <= 12.3.4.204 Multiple memory corruption vulnerabilities (APSB19-20) (Mac OS X)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser plugin that is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host contains a version of Adobe Shockwave Player that is prior or equal to 12.3.4.204. It is,
therefore, affected by multiple memory corruption vulnerabilities. A remote attacker can exploit these vulnerabilities 
to execute arbitrary code.");
  # https://helpx.adobe.com/security/products/shockwave/apsb19-20.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Shockwave Player 12.3.5.205 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7098");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:shockwave_player");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("shockwave_player_detect_macosx.nbin");
  script_require_keys("installed_sw/Shockwave Player", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');
os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

app = 'Shockwave Player';
max_ver = '12.3.4.204';
fix_ver = '12.3.5.205';

app_info = vcf::get_app_info(app:app);

constraints = [{ 'max_version' : max_ver, 'fixed_version' : fix_ver }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
