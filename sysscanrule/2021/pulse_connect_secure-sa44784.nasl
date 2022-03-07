##
# 
##

include('compat.inc');

if (description)
{
  script_id(148847);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2021-22893");

  script_name(english:"Pulse Connect Secure < 9.1R11.4 (SA44784)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect Secure running on the remote host is greater than
9.0R3 and prior to 9.1R11.4. It is, therefore, affected by an authentication bypass vulnerability that can allow an
unauthenticated user to perform remote arbitrary file execution on the Pulse Connect Secure gateway.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

Note that when the advisory was published, the 9.1R11.4 update was not yet available.");
  script_set_attribute(attribute:"see_also", value:"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44784");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Connect Secure version 9.1R11.4 or later.
Note that when the advisory was published, the 9.1R11.4 update was not yet available.
Please contact the vendor for updated patch information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22893");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:pulse_connect_secure");
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

port = get_http_port(default:443);
app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

# from https://www-prev.pulsesecure.net/techpubs/pulse-connect-secure/pcs/9.1rx/
# 9.1R11.3 is 9.1.11.12173
constraints = [
 {'min_version':'9.0.3', 'max_version':'9.1.11.12173', 'fixed_display':'9.1R11.4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

