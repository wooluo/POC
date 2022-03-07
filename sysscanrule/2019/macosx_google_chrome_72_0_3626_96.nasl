#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122245);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/07 13:55:32");

  script_cve_id("CVE-2019-5784");

  script_name(english:"Google Chrome < 72.0.3626.96 Vulnerability");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a
vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is
prior to 72.0.3626.96. It is, therefore, affected by a vulnerability
as noted in Google Chrome stable channel update release notes for
2019/02/06. Please refer to the release notes for additional
information. Note that GizaNE has not attempted to exploit these
issues but has instead relied only on the application's self-reported
version number.");
  # https://chromereleases.googleblog.com/2019/02/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 72.0.3626.96 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'72.0.3626.96', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
