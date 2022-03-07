#
# 
#

include('compat.inc');

if (description)
{
  script_id(140133);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_cve_id("CVE-2020-11500");

  script_name(english:"Zoom Client < 4.6.10 Weak Encryption");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a weak encryption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Zoom Client installed on the remote host is prior to 4.6.10. It is, therefore, affected by a weak
encryption vulnerability. Zoom Client for Meetings through 4.6.9 uses the ECB mode of AES for video and audio
encryption. Within a meeting, all participants use a single 128-bit key.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.zoom.us/hc/en-us/articles/201361953-New-Updates-for-Windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774d8ec7");
  script_set_attribute(attribute:"see_also", value:"https://support.zoom.us/hc/en-us/articles/201361963");
  # https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2da9b98");
  # https://theintercept.com/2020/04/03/zooms-encryption-is-not-suited-for-secrets-and-has-surprising-links-to-china-researchers-discover/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fedaf0c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.6.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11500");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"agent", value:"all");
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
    { 'fixed_version' : '4.6.20033.0407', 'fixed_display' : '4.6.10 (20033.0407)' }
  ];

  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
}
else
{
  # macOS
  constraints = [
    { 'fixed_version' : '4.6.10 (20041.0408)' }
  ];

  app_info = vcf::get_app_info(app:'zoom');
}

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
