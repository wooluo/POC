#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122717);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/08 12:52:16");

  script_cve_id("CVE-2019-3711");
  script_bugtraq_id(107210);
  script_xref(name:"IAVB", value:"2019-B-0014");

  script_name(english:"EMC RSA Authentication Manager < 8.4 P1 Insecure Credential Management (DSA-2019-038)");
  script_summary(english:"Checks the version of EMC RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an insecure
credential management vulnerability.");
  script_set_attribute(attribute:"description", value:   
"The version of EMC RSA Authentication Manager running on the remote
host is prior to 8.4 Patch 1. It is, therefore, affected by an insecure
credential management vulnerability in the operations console
components. An authenticated, remote attacker with administrator
privileges can exploit this, to obtain the value of a domain password
that another operations console administrator had set previously.");

  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2019/Mar/5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.4 Patch 1 or later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3711");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_am_detect.nbin");
  script_require_keys("installed_sw/EMC RSA Authentication Manager");
  script_require_ports("Services/www", 7004);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:7004);
app ='EMC RSA Authentication Manager';
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { 'fixed_version' : '8.4.0.1', 'fixed_display' : '8.4 Patch 1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
