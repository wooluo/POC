##
# 
##

include('compat.inc');

if (description)
{
  script_id(142489);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-16846", "CVE-2020-25592", "CVE-2020-17490");
  script_xref(name:"IAVA", value:"2020-A-0195");

  script_name(english:"SaltStack < 3002 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of SaltStack running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of SaltStack hosted on the remote server is affected by
multiple vulnerabilities:

  - eauth is not sufficiently validated when calling Salt SSH via the salt-api. Any value for 'eauth' or
    'token' will allow a user to bypass authentication and make calls to Salt SSH. (CVE-2020-25592)

  - When using the functions create_ca, create_csr, and create_self_signed_cert in the tls execution module,
    the generated keys will not be created with the correct permissions. (CVE-2020-17490)

  - A command injection vulnerability exists in Salt API. An unauthenticated, remote attacker can exploit this,
    via the use of shell injections with the Salt API using the SSH Client, to execute arbitrary commands. (CVE-2020-16846)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version");
  # https://www.saltstack.com/blog/on-november-3-2020-saltstack-publicly-disclosed-three-new-cves/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2a5e02b");
  # https://www.tenable.com/blog/cve-2020-16846-cve-2020-25592-critical-vulnerabilities-in-salt-framework-disclosed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2f8b1d8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SaltStack version referenced in the vendor security advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:saltstack:salt");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("saltstack_salt_linux_installed.nbin");
  script_require_keys("installed_sw/SaltStack Salt Master");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'SaltStack Salt Master');

constraints = [
  { 'min_version' : '2015.8', 'fixed_version' : '2015.8.10' },
  { 'min_version' : '2015.8.11', 'fixed_version' : '2015.8.13' },
  { 'min_version' : '2016.3.0', 'fixed_version' : '2016.3.4' },
  { 'min_version' : '2016.3.5', 'fixed_version' : '2016.3.6' },
  { 'min_version' : '2016.3.7', 'fixed_version' : '2016.3.8' },
  { 'min_version' : '2016.11.0', 'fixed_version' : '2016.11.3' },
  { 'min_version' : '2016.11.4', 'fixed_version' : '2016.11.6' },
  { 'min_version' : '2016.11.7', 'fixed_version' : '2016.11.10' },
  { 'min_version' : '2017.7.0', 'fixed_version' : '2017.7.4' },
  { 'min_version' : '2017.7.5', 'fixed_version' : '2017.7.8' },
  { 'min_version' : '2018.0', 'fixed_version' : '2018.3.5'},
  { 'min_version' : '2019.0', 'fixed_version' : '2019.2.5', 'fixed_display' : '2019.2.5 or 2019.2.6' },
  { 'min_version' : '3000.0', 'fixed_version' : '3000.3', 'fixed_display' : '3000.3 or 3000.4' },
  { 'min_version' : '3001.0', 'fixed_version' : '3001.1', 'fixed_display' : '3001.1 / 3001.2 / 3002 or later.' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
