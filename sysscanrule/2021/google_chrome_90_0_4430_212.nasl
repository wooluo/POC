##
# 
##

include('compat.inc');

if (description)
{
  script_id(149412);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/12");

  script_cve_id(
    "CVE-2021-30506",
    "CVE-2021-30507",
    "CVE-2021-30508",
    "CVE-2021-30509",
    "CVE-2021-30510",
    "CVE-2021-30511",
    "CVE-2021-30512",
    "CVE-2021-30513",
    "CVE-2021-30514",
    "CVE-2021-30515",
    "CVE-2021-30516",
    "CVE-2021-30517",
    "CVE-2021-30518",
    "CVE-2021-30519",
    "CVE-2021-30520"
  );

  script_name(english:"Google Chrome < 90.0.4430.212 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 90.0.4430.212. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_05_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/05/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e7dcca1");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1180126");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1178202");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1195340");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1196309");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1197436");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1197875");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1200019");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1200490");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1200766");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1201073");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1201446");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1203122");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1203590");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1194058");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1193362");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 90.0.4430.212 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30520");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
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

google_chrome_check_version(installs:installs, fix:'90.0.4430.212', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
