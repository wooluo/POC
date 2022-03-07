#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125342);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/07  9:58:29");

  script_cve_id("CVE-2018-7117", "CVE-2019-11982", "CVE-2019-11983");
  script_bugtraq_id(107857);

  script_name(english:"iLO 4 < 2.70 / iLO 5 < 1.40a Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Integrated Lights-Out (iLO).");

  script_set_attribute(attribute:"synopsis", value:
"The remote HP Integrated Lights-Out (iLO) server's web interface is affected by multiple vulnerabilities") ;
  script_set_attribute(attribute:"description", value:"According to its self-reported version, the HP Integrated
  Lights-Out server running on the remote host is prior to 2.70 / 1.40a for iLO 4 / iLO 5 respectively. It is, 
  therefore, affected by multiple vulnerabilities:
    - A cross-site scripting (XSS) vulnerability exists due to improper validation of user-supplied input before 
    returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a 
    specially crafted URL, to execute arbitrary script code in a user's browser session. (CVE-2018-7117, CVE-2019-11982)

    - A buffer overflow condition exists in the command line interface component of HPE iLO. An 
    unauthenticated, remote attacker can exploit this to cause a denial of service condition or the execution of 
    arbitrary code. (CVE-2019-11983)");
  # https://support.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-hpesbhf03917en_us
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"For HP Integrated Lights-Out 4 (iLO 4) upgrade firmware to version 
  2.70 or later. For HP Integrated Lights-Out 5 (iLO 5) upgrade firmware to version 1.40a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11983");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:integrated_lights-out_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ilo_detect.nasl");
  script_require_keys("www/ilo", "ilo/generation", "ilo/firmware");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

port = get_http_port(default:80, embedded: TRUE);
app_info = vcf::get_app_info(app:'ilo', port:port, webapp:TRUE);

constraints = [
  {'generation': '4', 'fixed_version':'2.70'},
  {'generation': '5', 'fixed_version':'1.40a'}
];

vcf::ilo::initialize();
vcf::ilo::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
