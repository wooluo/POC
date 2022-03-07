##
# 
##

include('compat.inc');

if (description)
{
  script_id(146060);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id(
    "CVE-2021-21142",
    "CVE-2021-21143",
    "CVE-2021-21144",
    "CVE-2021-21145",
    "CVE-2021-21146",
    "CVE-2021-21147"
  );
  script_xref(name:"IAVA", value:"2021-A-0059");

  script_name(english:"Google Chrome < 88.0.4324.146 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 88.0.4324.146. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_02_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/02/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a97ab3be");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1169317");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1163504");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1163845");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1154965");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1161705");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1162942");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 88.0.4324.146 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'88.0.4324.146', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
