#
# (C) WebRAY Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(122347);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/20 10:36:34");

  script_cve_id("CVE-2019-1643");

  script_bugtraq_id(106702);

  script_xref(name:"CISCO-BUG-ID", value:"CSCvm81867");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190123-cpi-xss");

  script_name(english:"Cisco Prime Infrastructure Cross-Site Scripting Vulnerability (cisco-sa-20190123-cpi-xss)");
  script_summary(english:"Checks the Cisco Prime Infrastructure version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Prime Infrastructure application running on the remote
host is affected by a cross-site scripting (XSS) vulnerability 
due to improper validation of user-supplied input before 
returning it to users. 
An unauthenticated, remote attacker can exploit this, by convincing
a user to click a specially crafted URL, to execute arbitrary script
code in a user's browser session.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-cpi-xss
  script_set_attribute(attribute:"see_also", value:"");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm81867
  script_set_attribute(attribute:"see_also", value:"");

  script_set_attribute(attribute:"solution", value:
"Upgrade Cisco Prime Infrastructure to version 3.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1643");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");

  exit(0);
}

include('vcf.inc');
include('http.inc');                                                  

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);

constraints = [{'min_version':'3.2', 'fixed_version':'3.5'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
