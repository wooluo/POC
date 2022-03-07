#
# 
#

include('compat.inc');

if (description)
{
  script_id(141251);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2020-6925", "CVE-2020-6926", "CVE-2020-6927");

  script_name(english:"HP Device Manager 4.x < 4.7 SP 13 / 5.x < 5.0.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A thin client device manager running on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP Device Manager installed on the remote Windows host
is 4.x prior to 4.7 SP 13 or 5.x prior to 5.0.4. It is, therefore, affected by multiple vulnerabilities:

  - A weak cipher implementation that is susceptible to dictionary attacks. (CVE-2020-6925)

  - An unauthenticated RMI object call that can allow an unauthenticated remote attacker to inject HQL that injects SQL
    that will run on the bundled PostgreSQL database. (CVE-2020-6926)

  - A local privilege escalation vulnerability in the bundled PostgreSQL database. It has a default user account
    (dm_postgres) with a trivial password (single space). This can allow a local attacker to connect to the database
    and perform SQL queries leading to code execution as SYSTEM. (CVE-2020-6927)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nickbloor.co.uk/2020/10/05/hp-device-manager-cve-2020-6925-cve-2020-6926-cve-2020-6927/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc627f7a");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/us-en/document/c06921908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Device Manager version 4.7 SP 13 or 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6926");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hp:device_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_device_manager.nbin");
  script_require_keys("installed_sw/HP Device Manager");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'HP Device Manager', win_local:TRUE);

constraints = [
  # 4.7.3630.35564 is the 4.7 SP12 (vuln) gateway version
  # 5.0.3630.38524 is the 5.0.4 (patched) gateway version
  { 'min_version':'4.0.0', 'max_version':'4.7.3630.35564', 'fixed_display':'4.7 SP13' },
  { 'min_version':'5.0.0', 'fixed_version':'5.0.3630.38524', 'fixed_display':'5.0.3630.38524 (5.0.4)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

