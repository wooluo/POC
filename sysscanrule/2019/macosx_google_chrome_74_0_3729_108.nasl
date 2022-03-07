#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124278);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/10 13:04:56");

  script_cve_id(
    "CVE-2019-5805",
    "CVE-2019-5806",
    "CVE-2019-5807",
    "CVE-2019-5808",
    "CVE-2019-5809",
    "CVE-2019-5810",
    "CVE-2019-5811",
    "CVE-2019-5812",
    "CVE-2019-5813",
    "CVE-2019-5814",
    "CVE-2019-5815",
    "CVE-2019-5816",
    "CVE-2019-5817",
    "CVE-2019-5818",
    "CVE-2019-5819",
    "CVE-2019-5820",
    "CVE-2019-5821",
    "CVE-2019-5822",
    "CVE-2019-5823"
  );

  script_name(english:"Google Chrome < 74.0.3729.108 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is
prior to 74.0.3729.108. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2019_04_stable-channel-update-
for-desktop_23 advisory.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_23.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/913320");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/943087");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/945644");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/947029");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/941008");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/916838");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/771815");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/925598");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/942699");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/930057");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/930663");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/940245");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/943709");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/929962");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/919356");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/919635");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/919640");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/926105");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/930154");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 74.0.3729.108 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5805");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/25");

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

google_chrome_check_version(fix:'74.0.3729.108', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
