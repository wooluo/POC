#TRUSTED 9e63ccfc05a96c5e7e64864c19c6f58fad09cc3b7d9383ad924a57bb6e5874f1b58a741772882ee65dfbaf4df6328edc03cb05796e22c4888e9a12ec5a7af99c52323b9fe8b56d1ac2fba638afffb7f89dfb2e04bf5231c863c1a0bda339f86ba76091c39b02f0e05d7d4c13d989089fbd5e3f957b5ce21310b9b4fab04e863878a19b35443b3a06148e1a78fd6fb33dbe1e457c85ec34e354e87ce6bcec79e7f7b4e1e39508e44d6977a611511e43e67a6dc49e44f92b9dd27b888ac3d2f12fded3056ee7b79120e8f1aaad00fb4b5371e2cff88c6c9d13c48c3106dd32acbf2f0b8ab48a8a8838ddb24fd7cbed700b69f86138ef7e619c7a16250f00e49d3c8ee31d8173b98b092e905fd0c97984f1449ae3c5774930d9be3a44d32c42afb202e51d35be08f771cde4567c90db6d1e6007b561ddcf0e56e3f4f9b08d30849a877bec17d348f997410f96fa101692f2fbad30cb9660eecd33f7028223f0b468ba7242486997e96e18939dd22d9b37552c5fb52388a6c90ed6d3b5825d49699f44362f2920f477b9345c97761fbddee477982d0f26f0e1b4903604208ce1b877514ef2cead67aae0814aa5f439d09fbca7f519099c380519b3185f2e7b4f5baaa4cfaeddeb8eff6489468fa05d70f785f941d9101ae0f2b15c19981ea713cbd9e24f531de1f95ba5c71b9b6e8a446e1a0b8ce921a80772f1c53b9dd33f948a1e
##
# 
##

include('compat.inc');

if (description)
{
  script_id(147661);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id("CVE-2020-15938");
  script_xref(name:"IAVA", value:"2021-A-0120");

  script_name(english:"Fortinet FortiOS <= 6.2.5 / 6.4 <= 6.4.2 Traffic Bypass (FG-IR-20-172)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a traffic bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior or equal to 6.2.5, or 6.4 prior to 6.4.3. It is, therefore,
affected by a traffic bypass vulnerability. When traffic other than HTTP/S (eg: SSH traffic, etc...) traverses the
FortiGate in version below 6.2.5 and below 6.4.2 on port 80/443, it is not redirected to the transparent proxy policy
for processing, as it doesn't have a valid HTTP header.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-172");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

constraints = [
  {'min_version': '0.0', 'max_version': '6.2.5', 'fixed_display' : '6.4.3' },
  {'min_version': '6.4', 'fixed_version': '6.4.3' }
];

report +=
  '\n  FortiOS is currently running a vulnerable configuration,'
  +'\n as the tunnel-non-http setting is not disabled and/or '
  +'\n unsupported-ssl is not set to block.';

workarounds = [
  {config_command:'full-configuration', config_value:'unsupported-ssl block'},
  {config_command:'full-configuration', config_value:'tunnel-non-http disable'}
];

vcf::fortios::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  workarounds:workarounds,
  report:report,
  not_equal:FALSE,
  all_required:TRUE
);
