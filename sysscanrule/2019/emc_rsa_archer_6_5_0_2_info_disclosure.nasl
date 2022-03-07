#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122649);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/10 17:26:26");

  script_cve_id("CVE-2019-3715", "CVE-2019-3716");
  script_bugtraq_id(107443, 107406);
  script_xref(name:"IAVB", value:"2019-B-0017");

  script_name(english:"EMC RSA Archer < 6.4.1.5 / 6.5.x < 6.5.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for the product and version in the login page.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Archer running on the remote web server is
prior to 6.4.1.5 or 6.5.x < 6.5.0.2. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists in RSA Archer
    versions, prior to 6.5 SP1 (6.5.0.1). An authenticated malicious
    local user with access to the log files may obtain user session
    information to use it in further attacks. (CVE-2019-3715)

  - An information disclosure vulnerability exists in RSA Archer
    versions, prior to 6.5 SP2 (6.5.0.2). An authenticated malicious
    local user with access to the log files may obtain the database
    connection password to use it in further attacks. (CVE-2019-3716)

Note that version 6.4 SP1 P5 (6.4.1.5) also fixed these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://community.rsa.com/docs/DOC-101227");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2019/Mar/19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Archer version 6.4.1.5 / 6.5.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3716");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_archer_egrc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_archer_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app_name = "EMC RSA Archer";
port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);

constraints = [
  # 6.5.x
  {"min_version" : "6.5.0", "fixed_version" : "6.5.200", "fixed_display" : "6.5 P2 (6.5.0.2)" },
  # All versions < 6.4.1.5 are vulnerable
  {"fixed_version" : "6.4.10500", "fixed_display" : "6.4 SP1 P5 (6.4.1.5)" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
