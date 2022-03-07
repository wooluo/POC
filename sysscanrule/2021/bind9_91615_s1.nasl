##
# 
##

include('compat.inc');

if (description)
{
  script_id(149315);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2021-25216");

  script_name(english:"ISC BIND 9.5.0 < 9.11.31 / 9.11.3-S1 < 9.11.31-S1 / 9.12.0 < 9.16.15 / 9.16.8-S1 < 9.16.15-S1 / 9.17.0 <-> 9.17.1 Buffer Overflow (CVE-2021-25216)");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ISC BIND installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the CVE-2021-25216 advisory.

  - In BIND 9.5.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.11.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.1 of the BIND
    9.17 development branch, BIND servers are vulnerable if they are running an affected version and are
    configured to use GSS-TSIG features. In a configuration which uses BIND's default settings the vulnerable
    code path is not exposed, but a server can be rendered vulnerable by explicitly setting values for the
    tkey-gssapi-keytab or tkey-gssapi-credential configuration options. Although the default configuration is
    not vulnerable, GSS-TSIG is frequently used in networks where BIND is integrated with Samba, as well as in
    mixed-server environments that combine BIND servers with Active Directory domain controllers. For servers
    that meet these conditions, the ISC SPNEGO implementation is vulnerable to various attacks, depending on
    the CPU architecture for which BIND was built: For named binaries compiled for 64-bit platforms, this flaw
    can be used to trigger a buffer over-read, leading to a server crash. For named binaries compiled for
    32-bit platforms, this flaw can be used to trigger a server crash due to a buffer overflow and possibly
    also to achieve remote code execution. We have determined that standard SPNEGO implementations are
    available in the MIT and Heimdal Kerberos libraries, which support a broad range of operating systems,
    rendering the ISC implementation unnecessary and obsolete. Therefore, to reduce the attack surface for
    BIND users, we will be removing the ISC SPNEGO implementation in the April releases of BIND 9.11 and 9.16
    (it had already been dropped from BIND 9.17). We would not normally remove something from a stable ESV
    (Extended Support Version) of BIND, but since system libraries can replace the ISC SPNEGO implementation,
    we have made an exception in this case for reasons of stability and security. (CVE-2021-25216)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/v1/docs/CVE-2021-25216");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.11.31 / 9.11.31-S1 / 9.16.15 / 9.16.15-S1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::bind::initialize();

app_info = vcf::get_app_info(app:'BIND', port:53, kb_ver:'bind/version', service:TRUE, proto:'UDP');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '9.5.0', 'max_version' : '9.11.29', 'fixed_display' : '9.11.31' },
  { 'min_version' : '9.11.3-S1', 'max_version' : '9.11.29-S1', 'fixed_display' : '9.11.31-S1' },
  { 'min_version' : '9.12.0', 'max_version' : '9.16.13', 'fixed_display' : '9.16.15' },
  { 'min_version' : '9.16.8-S1', 'max_version' : '9.16.13-S1', 'fixed_display' : '9.16.15-S1' },
  { 'min_version' : '9.17.0', 'max_version' : '9.17.1', 'fixed_display' : 'Update to the latest available stable release' }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
