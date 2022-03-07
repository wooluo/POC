#
# 
#

include('compat.inc');

if (description)
{
  script_id(138223);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/17");

  script_cve_id(
    "CVE-2020-10730",
    "CVE-2020-10745",
    "CVE-2020-10760",
    "CVE-2020-14303"
  );
  script_xref(name:"IAVA", value:"2020-A-0288");

  script_name(english:"Samba 4.x < 4.10.17 / 4.11.x < 4.11.11 / 4.12.x < 4.12.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.x prior to 4.10.17, 4.11.x prior to 4.11.11, or 4.12.x prior to
4.12.4.  It is, therefore, affected by multiple vulnerabilities, including the following:

  - The AD DC NBT server in Samba 4.0 will enter a CPU spin and not process further requests once it receives
    an empty (zero-length) UDP packet to port 137. (CVE-2020-14303)

  - Compression of replies to NetBIOS over TCP/IP name resolution and DNS packets (which can be supplied as
    UDP requests) can be abused to consume excessive amounts of CPU on the Samba AD DC (only).
    (CVE-2020-10745)

  - The use of the paged_results or VLV controls against the Global Catalog LDAP server on the AD DC will
    cause a use-after-free. (CVE-2020-10760)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-10730.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-10760.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-10745.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2020-14303.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/latest_news.html#4.12.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.10.17 / 4.11.11 / 4.12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'4.0.0',  'fixed_version':'4.10.17'},
  {'min_version':'4.11.0', 'fixed_version':'4.11.11'},
  {'min_version':'4.12.0', 'fixed_version':'4.12.4'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
