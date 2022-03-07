##
# 
##

include('compat.inc');

if (description)
{
  script_id(148180);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2020-35856", "CVE-2021-3109");
  script_xref(name:"IAVA", value:"2021-A-0151");

  script_name(english:"SolarWinds Orion Platform < 2020.2.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by Multiple Vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of SolarWinds Orion Platform is prior to 2020.2.5. It is,
therefore, affected by multiple vulnerabilities:

  - A reverse tabnabbing and open redirect vulnerability was found in the custom menu item options page. This
    vulnerability requires an Orion administrator account to exploit this. (CVE-2021-3109)

  - A stored XSS vulnerability was found in the add custom tab within the customize view page. This
    vulnerability requires Orion administrator account to exploit this. (CVE-2020-35856)

  - A remote code execution vulnerability has been found via the test alert actions. An Orion authenticated
    user is required to exploit this issue via actions and JSON deserialization to execute arbitrary commands.

  - A remote code execution (RCE) vulnerability exists in the Job Scheduler. An authenticated attacker can
    exploit this issue to achieve authenticated RCE as Administrator. In order to exploit this, an attacker
    first needs to know the credentials of an unprivileged local account on the Orion Server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://documentation.solarwinds.com/en/Success_Center/orionplatform/content/release_notes/orion_platform_2020-2-5_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01e604ba");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Orion Platform 2020.2.5 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
app_info = vcf::solarwinds_orion::combined_get_app_info();

constraints = [
  { 'min_version' : '2020.0', 'fixed_version' : '2020.2.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:true});
