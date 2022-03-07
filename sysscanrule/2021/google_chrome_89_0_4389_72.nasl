##
# 
##

include('compat.inc');

if (description)
{
  script_id(146948);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/04");

  script_cve_id(
    "CVE-2020-27844",
    "CVE-2021-21159",
    "CVE-2021-21160",
    "CVE-2021-21161",
    "CVE-2021-21162",
    "CVE-2021-21163",
    "CVE-2021-21164",
    "CVE-2021-21165",
    "CVE-2021-21166",
    "CVE-2021-21167",
    "CVE-2021-21168",
    "CVE-2021-21169",
    "CVE-2021-21170",
    "CVE-2021-21171",
    "CVE-2021-21172",
    "CVE-2021-21173",
    "CVE-2021-21174",
    "CVE-2021-21175",
    "CVE-2021-21176",
    "CVE-2021-21177",
    "CVE-2021-21178",
    "CVE-2021-21179",
    "CVE-2021-21180",
    "CVE-2021-21181",
    "CVE-2021-21182",
    "CVE-2021-21183",
    "CVE-2021-21184",
    "CVE-2021-21185",
    "CVE-2021-21186",
    "CVE-2021-21187",
    "CVE-2021-21188",
    "CVE-2021-21189",
    "CVE-2021-21190"
  );

  script_name(english:"Google Chrome < 89.0.4389.72 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 89.0.4389.72. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_03_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc64b00e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1171049");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1170531");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1173702");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1172054");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1111239");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1164846");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1174582");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1177465");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1161144");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1152226");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1166138");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1111646");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1152894");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1150810");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1154250");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1158010");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1146651");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1170584");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1173879");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1174186");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1174943");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1175507");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1177875");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1182767");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1049265");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1105875");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1131929");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1100748");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1153445");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1155516");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1161739");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1165392");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1166091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 89.0.4389.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27844");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/02");

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

google_chrome_check_version(installs:installs, fix:'89.0.4389.72', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
