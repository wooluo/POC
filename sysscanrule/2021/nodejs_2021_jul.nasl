
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151975);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_cve_id(
    "CVE-2021-22918",
    "CVE-2021-22921",
    "CVE-2021-23362",
    "CVE-2021-27290"
  );
  script_xref(name:"IAVB", value:"2021-B-0041");

  script_name(english:"Node.js 12.x < 12.22.2 / 14.x < 14.17.2 / 16.x < 16.4.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 12.22.2, 14.17.2, 16.4.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the July 2021 Security Releases advisory.

  - Node.js is vulnerable to out-of-bounds read in libuv's uv__idna_toascii() function which is used to
    convert strings to ASCII. This is called by Node's dns module's lookup() function and can lead to
    information disclosures or crashes. (CVE-2021-22918)

  - Node.js is vulnerable to local privilege escalation attacks under certain conditions on Windows platforms.
    More specifically, improper configuration of permissions in the installation directory allows an attacker
    to perform two different escalation attacks: PATH and DLL hijacking. (CVE-2021-22921)

  - This is a vulnerability in the ssri npm module which may be vulnerable to denial of service attacks.
    (CVE-2021-27290)

  - This is a vulnerability in the hosted-git-info npm module which may be vulnerable to denial of service
    attacks. (CVE-2021-23362)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/july-2021-security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 12.22.2 / 14.17.2 / 16.4.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_nodejs_installed.nbin", "nodejs_win_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '12.0.0', 'fixed_version' : '12.22.2' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.17.2' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.4.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
