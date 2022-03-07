#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127129);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/08 16:49:58");

  script_cve_id("CVE-2019-5867", "CVE-2019-5868");
  script_xref(name:"IAVA", value:"2019-A-0280");

  script_name(english:"Google Chrome < 76.0.3809.100 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 76.0.3809.100. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2019_08_stable-channel-update-for-desktop advisory. Note that GizaNE
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/983867");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/984344");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 76.0.3809.100 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5868");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'76.0.3809.100', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
