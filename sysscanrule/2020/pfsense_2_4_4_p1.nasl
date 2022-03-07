##
# 
##

include('compat.inc');

if (description)
{
  script_id(146059);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id(
    "CVE-2018-4019",
    "CVE-2018-4020",
    "CVE-2018-4021",
    "CVE-2018-6925",
    "CVE-2018-17154",
    "CVE-2018-17155"
  );

  script_name(english:"pfSense 2.4.x < 2.4.4-p1  Multiple Vulnerabilities (SA-18_09)");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense install is a version 2.4.x prior to 2.4.4-p1. It is,
therefore, affected by multiple vulnerabilities, including the following:

   - An exploitable command injection vulnerability exists in the way Netgate pfSense CE 2.4.4-RELEASE processes the
     parameters of a specific POST request. The attacker can exploit this and gain the ability to execute arbitrary
     commands on the system. An attacker needs to be able to send authenticated POST requests to the administration web
     interface. Command injection is possible in the `powerd_normal_mode` parameter. (CVE-2018-4019)

   - An exploitable command injection vulnerability exists in the way Netgate pfSense CE 2.4.4-RELEASE processes the
     parameters of a specific POST request. The attacker can exploit this and gain the ability to execute arbitrary
     commands on the system. An attacker needs to be able to send authenticated POST requests to the administration web
     interface. Command injection is possible in the `powerd_ac_mode` POST parameter parameter. (CVE-2018-4020)

   - An exploitable command injection vulnerability exists in the way Netgate pfSense CE 2.4.4-RELEASE processes the
     parameters of a specific POST request. The attacker can exploit this and gain the ability to execute arbitrary
     commands on the system. An attacker needs to be able to send authenticated POST requests to the administration web
     interface. Command injection is possible in the `powerd_battery_mode` POST parameter. (CVE-2018-4021)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.netgate.com/assets/downloads/advisories/pfSense-SA-18_09.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a654a213");
  script_set_attribute(attribute:"see_also", value:"https://docs.netgate.com/pfsense/en/latest/releases/2-4-4-p1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.4.4-p1 or later, or apply patches as noted in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netgate:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (!get_kb_item('Host/pfSense')) audit(AUDIT_HOST_NOT, 'pfSense');

app_info = vcf::pfsense::get_app_info();
constraints = [
  {'min_version':'2.4.0', 'max_version':'2.4.4', 'fixed_version':'2.4.4-p1'}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
