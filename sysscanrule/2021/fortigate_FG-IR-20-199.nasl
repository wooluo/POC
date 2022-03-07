
##
# 
##



include('compat.inc');

if (description)
{
  script_id(150156);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-26092");
  script_xref(name:"IAVA", value:"2021-A-0262");

  script_name(english:"Fortinet FortiGate <= 5.6.13 / 6.0.x < 6.0.13 / 6.2.x < 6.2.8 / 6.4.x < 6.4.5 XSS (FG-IR-20-199)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a FortiOS version prior or equal to 5.6.13, 6.0.x prior to 6.0.13, 6.2.x prior to 6.2.8,
 or 6.4.x prior to 6.4.6. It is, therefore, affected by a cross-site scripting vulnerability. An unauthenticated attacker 
 may be able perform a reflected cross-site scripting attack by sending a request to the error page with malicious GET 
 parameters.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-199");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 6.0.13, 6.2.8, 6.4.6, 7.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26092");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_model();

constraints = [
  {'min_version':'0.0','max_version':'5.6.13', 'fixed_display':'Refer to vendor advisory'},
  {'min_version':'6.0.0', 'fixed_version':'6.0.13'},
  {'min_version':'6.2.0', 'fixed_version':'6.2.8'},
  {'min_version':'6.4.0', 'fixed_version':'6.4.6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
