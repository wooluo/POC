##
# 
##

include('compat.inc');

if (description)
{
  script_id(141363);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2020-6557",
    "CVE-2020-15968",
    "CVE-2020-15969",
    "CVE-2020-15971",
    "CVE-2020-15972",
    "CVE-2020-15973",
    "CVE-2020-15974",
    "CVE-2020-15975",
    "CVE-2020-15977",
    "CVE-2020-15979",
    "CVE-2020-15981",
    "CVE-2020-15982",
    "CVE-2020-15985",
    "CVE-2020-15987",
    "CVE-2020-15988",
    "CVE-2020-15989",
    "CVE-2020-15990",
    "CVE-2020-15991",
    "CVE-2020-15992"
  );

  script_name(english:"Microsoft Edge (Chromium) < 86.0.622.38 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 86.0.622.38. It is, therefore, affected
by multiple vulnerabilities as referenced in the ADV200002-10-8-2020 advisory. Note that Nessus has not tested for this
issue but has instead relied only on the application's self-reported version number.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?083510ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 86.0.622.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15991");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '86.0.622.38' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
