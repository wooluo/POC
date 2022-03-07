
##
# 
##



include('compat.inc');

if (description)
{
  script_id(151903);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/23");

  script_cve_id(
    "CVE-2017-14735",
    "CVE-2019-2897",
    "CVE-2019-5064",
    "CVE-2020-1971",
    "CVE-2020-10683"
  );
  script_xref(name:"IAVA", value:"2021-A-0328");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by multiple
vulnerabilities as referenced in the July 2021 CPU advisory.

  - Vulnerability in the StorageTek Tape Analytics SW Tool product of Oracle Systems (component: Software
    (dom4j)). The supported version that is affected is 2.3. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise StorageTek Tape Analytics SW Tool.
    Successful attacks of this vulnerability can result in takeover of StorageTek Tape Analytics SW Tool. 
    (CVE-2020-10683)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Application Service Level Mgmt (OpenCV)). The supported version that is affected is 13.4.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Enterprise Manager Base Platform. Successful attacks require human interaction from a person other than
    the attacker. Successful attacks of this vulnerability can result in takeover of Enterprise Manager Base
    Platform. (CVE-2019-5064)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Discovery Framework (OpenSSL)). The supported version that is affected is 13.4.0.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Enterprise
    Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of Enterprise Manager Base Platform. (CVE-2020-1971)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10683");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

var constraints = [
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.11', 'fixed_display': '13.4.0.11 (Patch 32436128)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
