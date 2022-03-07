#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125729);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/20 14:58:24");

  script_cve_id(
    "CVE-2019-5828",
    "CVE-2019-5829",
    "CVE-2019-5830",
    "CVE-2019-5831",
    "CVE-2019-5832",
    "CVE-2019-5833",
    "CVE-2019-5834",
    "CVE-2019-5835",
    "CVE-2019-5836",
    "CVE-2019-5837",
    "CVE-2019-5838",
    "CVE-2019-5839",
    "CVE-2019-5840"
  );
  script_bugtraq_id(108578);

  script_name(english:"Google Chrome < 75.0.3770.80 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Google Chrome.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is
prior to 75.0.3770.80. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2019_06_stable-channel-update-
for-desktop advisory. Note that GizaNE has not tested for this issue
but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2019/06/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/956597");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/958533");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/665766");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/950328");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/959390");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/945067");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/962368");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/939239");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/947342");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/918293");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/893087");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/925614");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/951782");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/970244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 75.0.3770.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5828");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/05");

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

google_chrome_check_version(installs:installs, fix:'75.0.3770.80', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
