##
# 
##

include('compat.inc');

if (description)
{
  script_id(146308);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2021-25276");

  script_name(english:"Serv-U FTP Server < 15.2.2 Hotfix 1 Arbitrary File Read/Write");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an Arbitrary File Read/Write
  vulnerability.");
  script_set_attribute(attribute:"description", value:
"In SolarWinds Serv-U before 15.2.2 Hotfix 1, there is a directory containing user profile files (that include users'
password hashes) that is world readable and writable. An unprivileged Windows user (having access to the server's
filesystem) can add an FTP user by copying a valid profile file to this directory. For example, if this profile sets
up a user with a C:\ home directory, then the attacker obtains access to read or replace arbitrary files with
LocalSystem privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/success_center/servu/Content/Release_Notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c04a9b0");
  # https://downloads.solarwinds.com/solarwinds/Release/HotFix/Serv-U-15.2.2-Hotfix-1.zip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26d4bf3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ServU-FTP 15.2.2 Hotfix 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25276");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Serv-U", "Host/OS");

  exit(0);
}

include('vcf.inc');
include('ftp_func.inc');

os = get_kb_item_or_exit('Host/OS');

if (tolower(os) !~ "windows") audit(AUDIT_OS_NOT, 'affected');

port = get_ftp_port(default:21);

app_info = vcf::get_app_info(app:'Serv-U', port:port);

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '15.2.2.583' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);