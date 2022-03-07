##
# 
##


include('compat.inc');

if (description)
{
  script_id(149350);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2021-20254");
  script_xref(name:"IAVA", value:"2021-A-0208");

  script_name(english:"Samba 3.6.x < 4.12.15 / 4.13.x < 4.13.8 / 4.14.x < 4.14.4 Unauthorized File Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by an unauthorized file access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 3.6.x prior to 4.12.5, 4.13.x prior to 4.13.8, or 4.14.x prior to
4.14.4.  It is, therefore, potentially affected by an unauthorized file access flaw that could allow it to read data 
beyond the end of the array in the case where a negative cache entry had been added to the mapping cache. This could 
cause the calling code to return those values into the process token that stores the group membership for a user. The 
flaw can impact data confidentiality and integrity by allowing unauthorized access.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2021-20254.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.12.5 / 4.13.8 / 4.14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

constraints = [
  {'min_version':'3.6.0',  'fixed_version':'4.12.15'},
  {'min_version':'4.13.0', 'fixed_version':'4.13.8'},
  {'min_version':'4.14.0', 'fixed_version':'4.14.4'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING);
