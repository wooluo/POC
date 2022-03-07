
##
# 
##



include('compat.inc');

if (description)
{
  script_id(152231);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/05");

  script_cve_id(
    "CVE-2021-22933",
    "CVE-2021-22934",
    "CVE-2021-22935",
    "CVE-2021-22936",
    "CVE-2021-22937",
    "CVE-2021-22938"
  );

  script_name(english:"Pulse Connect Secure < 9.1R12 (SA44858)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect Secure running on the remote host is prior to
9.1R12. It is, therefore, affected by multiple vulnerabilities, including:

  - A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator to perform a file
    write via a maliciously crafted archive uploaded in the administrator web interface. (CVE-2021-22937)

  - A vulnerability in Pulse Connect Secure before 9.1R12 could allow an authenticated administrator to perform command
    injection via an unsanitized web parameter. (CVE-2021-22935)

  - A vulnerability in Pulse Connect Secure before 9.1R12 could allow a threat actor to perform a cross-site script
    attack against an authenticated administrator via an unsanitized web parameter. (CVE-2021-22936)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44858");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 9.1R12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22937");


  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

# from https://www-prev.pulsesecure.net/techpubs/pulse-connect-secure/pcs/9.1rx/
# and https://www.ivanti.com/support/product-documentation
# 9.1R11.5 is 9.1.11.13127
# 9.1R12 is 9.1.12.14139
var constraints = [
 {'fixed_version':'9.1.12.14139', 'fixed_display':'9.1R12 (9.1.12.14139)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

