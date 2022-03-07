#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125628);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id("CVE-2019-11213");
  script_xref(name:"CERT", value:"192371");

  script_name(english:"Pulse Connect Secure Insecure Cookie Handling (SA44114)");
  script_summary(english:"Checks PPS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by an insecure cookie handling flaw.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect
Secure running on the remote host is is prior to 8.1R14, 8.3R7, or
9.0R3 and thus, is affected by an error related to handling session
cookies that allows an attacker to access session cookies and spoof
sessions.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44114
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.1R14, 8.3R7, 9.0R3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11213");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulse_secure:pulse_connect_secure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

app_info = vcf::get_app_info(app:'Pulse Connect Secure', port:443);

constraints = [
 {'min_version' : '9.0R0' , 'fixed_version' : '9.0R3'},
 {'min_version' : '8.3R0' , 'fixed_version' : '8.3R7'},
 {'min_version' : '8.1R0' , 'fixed_version' : '8.1R14'},
 # Everything else and suggest upgrade to latest
 # '8.1R0' is not a version, but is used as a ceiling
 {'min_version' : '0.0R0' , 'fixed_version' : '8.1R0', 'fixed_display' : '9.0R3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
