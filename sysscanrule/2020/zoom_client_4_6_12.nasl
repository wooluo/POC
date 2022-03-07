#
# 
#

include('compat.inc');

if (description)
{
  script_id(139925);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/31");

  script_cve_id("CVE-2020-6109", "CVE-2020-6110");

  script_name(english:"Zoom Client < 4.6.12 Path Traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple path traversal vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Zoom Client installed on the remote host is prior to 4.6.12. It is, therefore, affected by multiple
vulnerabilities :

  - A path traversal vulnerability exists in the Zoom Client in the message processing. An unauthenticated,
    remote attacker can exploit this, by sending a specially crafted chat message to a target user or group,
    to cause an arbitrary file write, which could potentially be abused to achieve arbitrary code execution.
    (CVE-2020-6109)

  - A path traversal vulnerability exists in the Zoom Client in the message processing. An unauthenticated,
    remote attacker can exploit this, by sending a specially crafted chat message to a target user or group,
    to cause arbitrary binary planting, which could be abused to achieve arbitrary code execution.
    (CVE-2020-6110)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.zoom.us/hc/en-us/articles/201361953-New-Updates-for-Windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774d8ec7");
  script_set_attribute(attribute:"see_also", value:"https://support.zoom.us/hc/en-us/articles/201361963");
  script_set_attribute(attribute:"see_also", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-1055");
  script_set_attribute(attribute:"see_also", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2020-1056");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.6.12 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin", "macosx_zoom_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

os = get_kb_item('Host/MacOSX/Version');

app_info = NULL;
constraints = NULL;

# Windows and macOS detection get version numbers in different formats
if(isnull(os))
{
  # Windows
  get_kb_item_or_exit('SMB/Registry/Enumerated');

  constraints = [
    { 'fixed_version' : '4.6.20613.0421', 'fixed_display' : '4.6.12 (20613.0421)'}
  ];

  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
}
else
{
  # macOS
  constraints = [
    { 'fixed_version' : '4.6.12', 'fixed_display' : '4.6.12 (20615.0421)'}
  ];

  app_info = vcf::get_app_info(app:'zoom');
}

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

