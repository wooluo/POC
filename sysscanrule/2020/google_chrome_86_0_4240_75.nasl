##
# 
##

include('compat.inc');

if (description)
{
  script_id(141194);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2020-6557",
    "CVE-2020-15967",
    "CVE-2020-15968",
    "CVE-2020-15969",
    "CVE-2020-15970",
    "CVE-2020-15971",
    "CVE-2020-15972",
    "CVE-2020-15973",
    "CVE-2020-15974",
    "CVE-2020-15975",
    "CVE-2020-15976",
    "CVE-2020-15977",
    "CVE-2020-15978",
    "CVE-2020-15979",
    "CVE-2020-15980",
    "CVE-2020-15981",
    "CVE-2020-15982",
    "CVE-2020-15983",
    "CVE-2020-15984",
    "CVE-2020-15985",
    "CVE-2020-15986",
    "CVE-2020-15987",
    "CVE-2020-15988",
    "CVE-2020-15989",
    "CVE-2020-15990",
    "CVE-2020-15991",
    "CVE-2020-15992"
  );
  script_xref(name:"IAVA", value: "2020-A-0443");

  script_name(english:"Google Chrome < 86.0.4240.75 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 86.0.4240.75. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2020_10_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/10/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1039882");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1076786");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1080395");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1083278");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1092453");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1092518");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1097724");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1099276");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1100247");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1104103");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1106890");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1108299");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1108351");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1110195");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1110800");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1114062");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115901");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1116280");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1123023");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1123522");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1124659");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1126424");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1127319");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1127322");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1127774");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1133671");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1133688");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac3b0244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 86.0.4240.75 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'86.0.4240.75', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
