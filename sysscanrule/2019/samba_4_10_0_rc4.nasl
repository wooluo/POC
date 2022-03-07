#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122860);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id("CVE-2019-3824");
  script_bugtraq_id(107347);

  script_name(english:"Samba 4.7.x / 4.8.x / 4.9.x < 4.9.5 / 4.10.0rc < 4.10.0rc4 LDAP Search Expression Denial of Service Vulnerability (CVE-2019-3824)");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.7.x, 4.8.x,
4.9.x < 4.9.5 or 4.10.0rc prior to 4.10.0rc4. It is, therefore,
potentially affected by a denial of service (DoS) vulnerability in
the LDAP search expression parser due to improper validation. An
authenticated, remote attacker can exploit this issue, via a crafted
LDAP search expression, to cause the LDAP server process of the Samba
Active Directory Domain Controller to stop responding.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=13773");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.9.5.html");
  script_set_attribute(attribute:"see_also", value:"https://download.samba.org/pub/samba/rc/samba-4.10.0rc4.WHATSNEW.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.9.5 / 4.10.0rc4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3824");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");
include("vcf_extras.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

# Note: versions < 4.7 are EOL
constraints = [
  {"min_version":"4.7.0", "max_version":"4.7.12", "fixed_display":"4.10.0rc4"}, # no fixed release yet
  {"min_version":"4.8.0", "max_version":"4.8.9", "fixed_display":"4.10.0rc4"}, # no fixed release yet
  {"min_version":"4.9.0", "fixed_version":"4.9.5"},
  {"min_version":"4.10.0rc0", "fixed_version":"4.10.0rc4"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
