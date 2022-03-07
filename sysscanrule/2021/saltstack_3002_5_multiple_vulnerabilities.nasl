##
# 
##

include('compat.inc');

if (description)
{
  script_id(148112);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284"
  );
  script_xref(name:"IAVA", value:"2021-A-0112");

  script_name(english:"SaltStack < 3002.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of SaltStack running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of SaltStack hosted on the remote server is affected by
multiple vulnerabilities:

  - The Salt-API’s SSH client is vulnerable to a shell injection by including ProxyCommand in an argument,
    or via ssh_options provided in an API request. (CVE-2021-3197)

  - The Salt-API does not have eAuth credentials for the wheel_async client. Thus, an attacker can remotely
    run any wheel modules on the master. (CVE-2021-25281)

  - eauth tokens can be used once after expiration. They can be used to run command against the salt master
   or minions. (CVE-2021-3144)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version");
  # https://saltproject.io/security_announcements/active-saltstack-cve-release-2021-feb-25/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad6e5b97");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SaltStack version referenced in the vendor security advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28243");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:saltstack:salt");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("saltstack_salt_linux_installed.nbin");
  script_require_keys("installed_sw/SaltStack Salt Master");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'SaltStack Salt Master');

# report paranoia for older versions.
if ((app_info['version'] =~ "201[5-9](\.[0-9]{1,2}){2}" ) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '3000.0', 'fixed_version' : '3000.7' , 'fixed_display' : '3000.7 / 3000.8'},
  { 'min_version' : '3001.0', 'fixed_version' : '3001.6' },
  { 'min_version' : '3002.0', 'fixed_version' : '3002.5' }

];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
