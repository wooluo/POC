#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127120);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/12 15:23:38");

  script_cve_id(
    "CVE-2019-5850",
    "CVE-2019-5851",
    "CVE-2019-5852",
    "CVE-2019-5853",
    "CVE-2019-5854",
    "CVE-2019-5855",
    "CVE-2019-5856",
    "CVE-2019-5857",
    "CVE-2019-5858",
    "CVE-2019-5859",
    "CVE-2019-5860",
    "CVE-2019-5861",
    "CVE-2019-5862",
    "CVE-2019-5863",
    "CVE-2019-5864",
    "CVE-2019-5865"
  );

  script_name(english:"Google Chrome < 76.0.3809.87 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 76.0.3809.87. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2019_07_stable-channel-update-for-desktop_30 advisory. Note that GizaNE
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/07/stable-channel-update-for-desktop_30.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/977462");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/956947");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/976627");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/977107");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/959438");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/964245");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/943494");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/964872");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/973103");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/960209");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/936900");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/946260");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/951525");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/961237");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/966263");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/976713");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/988889");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 76.0.3809.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5853");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

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
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'76.0.3809.87', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
