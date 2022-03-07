##
# 
##


include('compat.inc');

if (description)
{
  script_id(149900);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id(
    "CVE-2021-21212",
    "CVE-2021-30521",
    "CVE-2021-30522",
    "CVE-2021-30523",
    "CVE-2021-30524",
    "CVE-2021-30525",
    "CVE-2021-30526",
    "CVE-2021-30527",
    "CVE-2021-30528",
    "CVE-2021-30529",
    "CVE-2021-30530",
    "CVE-2021-30531",
    "CVE-2021-30532",
    "CVE-2021-30533",
    "CVE-2021-30534",
    "CVE-2021-30535",
    "CVE-2021-30536",
    "CVE-2021-30537",
    "CVE-2021-30538",
    "CVE-2021-30539",
    "CVE-2021-30540"
  );

  script_name(english:"Google Chrome < 91.0.4472.77 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 91.0.4472.77. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_05_stable-channel-update-for-desktop_25 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/05/stable-channel-update-for-desktop_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a02fb7a");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1208721");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1176218");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1187797");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1197146");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1197888");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1198717");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1199198");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1206329");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1195278");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1201033");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115628");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1117687");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1145553");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1151507");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1194899");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1145024");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1194358");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/830101");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115045");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/971231");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1184147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 91.0.4472.77 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

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

google_chrome_check_version(installs:installs, fix:'91.0.4472.77', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
