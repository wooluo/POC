##
# 
##

include('compat.inc');

if (description)
{
  script_id(144781);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id(
    "CVE-2020-15995",
    "CVE-2020-16043",
    "CVE-2021-21106",
    "CVE-2021-21107",
    "CVE-2021-21108",
    "CVE-2021-21109",
    "CVE-2021-21110",
    "CVE-2021-21111",
    "CVE-2021-21112",
    "CVE-2021-21113",
    "CVE-2021-21114",
    "CVE-2021-21115",
    "CVE-2021-21116"
  );
  script_xref(name:"IAVA", value:"2021-A-0006");

  script_name(english:"Google Chrome < 87.0.4280.141 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 87.0.4280.141. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_01_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c62eaf91");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1148749");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1153595");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1155426");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1152334");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1152451");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1149125");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1151298");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1155178");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1148309");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1150065");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1157790");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1157814");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1151069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 87.0.4280.141 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21106");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

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

google_chrome_check_version(installs:installs, fix:'87.0.4280.141', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
