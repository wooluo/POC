
##
# 
##


include('compat.inc');

if (description)
{
  script_id(151646);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id("CVE-2021-35211");
  script_xref(name:"IAVA", value:"2021-A-0322");

  script_name(english:"Serv-U FTP Server <= 15.2.3 Hotfix 1 Memory Escape Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an Memory Escape vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the installed version of Serv-U is a version prior to 15.2.3 Hotfix 2. It is, therefore, 
affected memory escape vulnerability. An unauthenticated remote attacker who successfully exploited this vulnerability 
could run arbitrary code with privileges, which could then install programs; view, change, or delete data; or run 
programs on the affected system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebb78655");
  # https://support.solarwinds.com/SuccessCenter/s/article/Serv-U-15-2-3-HotFix-2?language=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a78dfac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ServU-FTP 15.2.3 Hotfix 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35211");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl");
  script_require_keys("installed_sw/Serv-U");

  exit(0);
}

include('vcf.inc');
include('ftp_func.inc');

var port = get_ftp_port(default:21);

var app_info = vcf::get_app_info(app:'Serv-U', port:port);

var constraints = [
  {'fixed_version' : '15.2.3.742' , 'fixed_display' : '15.2.3.742 HF2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
