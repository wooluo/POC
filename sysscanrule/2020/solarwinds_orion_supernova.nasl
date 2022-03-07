##
# 
##

include('compat.inc');

if (description)
{
  script_id(144622);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-10148");
  script_xref(name:"IAVA", value:"2021-A-0001");

  script_name(english:"SolarWinds Orion Platform < 2019.4 HF6 / 2020.2 < 2020.2.1 HF2 Authentication Bypass (SUPERNOVA)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Orion Platform running on the remote host is prior
to 2019.4 HF6 or 2020.2 prior to 2020.2.1 HF 2.

It is, therefore, affected by an authentication bypass vulnerability. An
unauthenticated attacker can exploit this, via a specially crafted web
request, to bypass authentication and execute privileged actions.

Older affected versions corrected with the security patch are unable to be
verified. Enabling Paranoid Mode will include these hosts in the results.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  # https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e897a7a");
  # https://labs.sentinelone.com/solarwinds-understanding-detecting-the-supernova-webshell-trojan/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04e21e62");
  script_set_attribute(attribute:"see_also", value:"https://www.solarwinds.com/securityadvisory");
  # https://www.tenable.com/blog/solorigate-solarwinds-orion-platform-contained-a-backdoor-since-march-2020-sunburst
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ff24ea2");
  # https://support.solarwinds.com/SuccessCenter/s/article/Orion-Platform-2019-4-Hotfix-6?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?704c04b1");
  # https://support.solarwinds.com/SuccessCenter/s/article/Orion-Platform-2020-2-1-Hotfix-2?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7299ae8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Orion Platform 2019.4 HF 6, 2020.2.1 HF 2, or later.
Alternatively, apply the vendor provided security patch.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10148");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
app_info = vcf::solarwinds_orion::combined_get_app_info();

constraints = [
  { 'min_version' : '2018.2', 'fixed_version' : '2018.2 HF6' },
  { 'min_version' : '2018.4', 'fixed_version' : '2018.4 HF3' },
  { 'min_version' : '2019.2', 'fixed_version' : '2019.2 HF3' },
  { 'min_version' : '2019.4', 'fixed_version' : '2019.4 HF6'  },
  { 'min_version' : '2020.2', 'fixed_version' : '2020.2.1 HF2' }
];

# Extra constraints for paranoid mode. These couldn't be verified as
#  additional mitigation measures are required
p_constraints = [
  { 'max_version' : '2018.2', 'fixed_display' : 'Apply vendor security patch' },
  { 'equal' : '2018.2 HF6',   'fixed_display' : '2018.2 HF6 w/ security patch' },
  { 'equal' : '2018.4 HF3',   'fixed_display' : '2018.4 HF3 w/ security patch' },
  { 'equal' : '2019.2 HF3',   'fixed_display' : '2019.2 HF3 w/ security patch' }
];

matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);
p_matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:p_constraints);

if (!isnull(matching_constraint))
{
  vcf::report_results(app_info:app_info, fix:matching_constraint.fixed_version, severity:SECURITY_HOLE); 
}
else if (!isnull(p_matching_constraint))
{
  if (report_paranoia < 2)
    ::audit(AUDIT_PARANOID);
  else
    vcf::report_results(app_info:app_info, fix:p_matching_constraint.fixed_display, severity:SECURITY_HOLE);
}
else
  vcf::audit(app_info);
