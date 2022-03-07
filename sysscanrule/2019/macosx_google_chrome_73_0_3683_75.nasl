#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122852);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id(
    "CVE-2019-5787",
    "CVE-2019-5788",
    "CVE-2019-5789",
    "CVE-2019-5790",
    "CVE-2019-5791",
    "CVE-2019-5792",
    "CVE-2019-5793",
    "CVE-2019-5794",
    "CVE-2019-5795",
    "CVE-2019-5796",
    "CVE-2019-5797",
    "CVE-2019-5798",
    "CVE-2019-5799",
    "CVE-2019-5800",
    "CVE-2019-5801",
    "CVE-2019-5802",
    "CVE-2019-5803",
    "CVE-2019-5804"
  );
  script_bugtraq_id(107363);

  script_name(english:"Google Chrome < 73.0.3683.75 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is
prior to 73.0.3683.75. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2019_03_stable-channel-update-
for-desktop_12 advisory.

  - Use after free in Canvas. (CVE-2019-5787)

  - Use after free in FileAPI. (CVE-2019-5788)

  - Use after free in WebMIDI. (CVE-2019-5789)

  - Heap buffer overflow in V8. (CVE-2019-5790)

  - Type confusion in V8. (CVE-2019-5791)

  - Integer overflow in PDFium. (CVE-2019-5792,
    CVE-2019-5795)

  - Excessive permissions for private API in Extensions.
    (CVE-2019-5793)

  - Security UI spoofing. (CVE-2019-5794, CVE-2019-5802)

  - Race condition in Extensions. (CVE-2019-5796)

  - Race condition in DOMStorage. (CVE-2019-5797)

  - Out of bounds read in Skia. (CVE-2019-5798)

  - CSP bypass with blob URL. (CVE-2019-5799, CVE-2019-5800)

  - Incorrect Omnibox display on iOS. (CVE-2019-5801)

  - CSP bypass with Javascript URLs'. (CVE-2019-5803)

  - Command line command injection on Windows.
    (CVE-2019-5804)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/03/stable-channel-update-for-desktop_12.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/913964");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/925864");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/921581");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/914736");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/926651");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/914983");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/937487");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/935175");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/919643");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/918861");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/916523");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/883596");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/905301");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/894228");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/921390");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/632514");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/909865");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/933004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 73.0.3683.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5790");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");

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

google_chrome_check_version(fix:'73.0.3683.75', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
