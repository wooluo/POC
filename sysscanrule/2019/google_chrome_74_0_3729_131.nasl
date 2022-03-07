#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124460);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/24 15:26:42");

  script_cve_id(
    "CVE-2019-5824",
    "CVE-2019-5825",
    "CVE-2019-5826",
    "CVE-2019-5827"
  );

  script_name(english:"Google Chrome < 74.0.3729.131 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 74.0.3729.131. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2019_04_stable-channel-update-
for-desktop_30 advisory. Note that GizaNE has not tested for this
issue but has instead relied only on the application's self-reported
version number.");
  # https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_30.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/952406");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/948564");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 74.0.3729.131 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5825");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");
installs = get_kb_list("SMB/Google_Chrome/*");

google_chrome_check_version(installs:installs, fix:'74.0.3729.131', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
