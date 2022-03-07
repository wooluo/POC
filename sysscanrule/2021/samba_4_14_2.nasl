##
# 
##

include('compat.inc');

if (description)
{

  script_id(149699);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/19");

  script_cve_id("CVE-2020-27840", "CVE-2021-20277");

  script_name(english:"Samba 4.12.x < 4.12.14 / 4.13.x < 4.13.7 / 4.14.x < 4.14.2 Multiple DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.12.x prior to 4.12.14, 4.13.x prior to 4.13.7, or 4.14.x prior to
4.14.2.  It is, therefore, potentially affected by multiple vulnerabilities: 

  - A denial of service (DoS) vulnerability exists in the Samba AD DC LDAP server. An unauthenticated, remote
    attacker can exploit this issue, via easily crafted DNs as part of a bind request. This can cause the 
    samba server to crash and stop responding. (CVE-2020-27840)

  - A denial of service (DoS) vulnerability exists in the Samba AD DC LDAP server. An unauthenticated, remote
    attacker can exploit this issue, via easily crafted LDAP attributes that contain multiple, consecutive, 
    leading spaces. This can cause the samba server process handling the request to crash and stop responding.
    (CVE-2021-20277)

  - User-controlled LDAP filter strings against the AD DC LDAP server may crash the LDAP server. (CVE-2021-20277)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-27840.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2021-20277.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.12.14 / 4.13.7 / 4.14.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27840");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app, constraints;

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

constraints = [
  {'min_version':'4.12.0',  'fixed_version':'4.12.14'},
  {'min_version':'4.13.0', 'fixed_version':'4.13.7'},
  {'min_version':'4.14.0', 'fixed_version':'4.14.2'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
