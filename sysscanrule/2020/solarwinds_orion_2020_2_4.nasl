##
# 
##

include('compat.inc');

if (description)
{
  script_id(146310);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2021-25274", "CVE-2021-25275");

  script_name(english:"SolarWinds Orion Platform < 2020.2.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by Multiple Vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of SolarWinds Orion Platform is prior to 2020.2.4. It is,
therefore, affected by multiple vulnerabilities:

  - The Collector Service in SolarWinds Orion Platform before 2020.2.4 uses MSMQ (Microsoft Message Queue) and
    doesn't set permissions on its private queues. As a result, remote unauthenticated clients can send messages to
    TCP port 1801 that the Collector Service will process. Additionally, upon processing of such messages, the
    service deserializes them in insecure manner, allowing remote arbitrary code execution as LocalSystem. (CVE-2021-25274)

  - SolarWinds Orion Platform before 2020.2.4, as used by various SolarWinds products, installs and uses a SQL
    Server backend, and stores database credentials to access this backend in a file readable by unprivileged
    users. As a result, any user having access to the filesystem can read database login details from that file,
    including the login name and its associated password. Then, the credentials can be used to get database owner access
    to the SWNetPerfMon.DB database. This gives access to the data collected by SolarWinds applications, and
    leads to admin access to the applications by inserting or changing authentication data stored in the Accounts
    table of the database. (CVE-2021-25275)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/Success_Center/orionplatform/content/release_notes/orion_platform_2020-2-4_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a457f40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Orion Platform 2020.2.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25274");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
app_info = vcf::solarwinds_orion::combined_get_app_info();

constraints = [
  { 'min_version' : '2020.0', 'fixed_version' : '2020.2.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
