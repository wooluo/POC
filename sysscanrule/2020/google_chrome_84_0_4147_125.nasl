#
# 
#

include('compat.inc');

if (description)
{
  script_id(139459);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id(
    "CVE-2020-6542",
    "CVE-2020-6543",
    "CVE-2020-6544",
    "CVE-2020-6545",
    "CVE-2020-6546",
    "CVE-2020-6547",
    "CVE-2020-6548",
    "CVE-2020-6549",
    "CVE-2020-6550",
    "CVE-2020-6551",
    "CVE-2020-6552",
    "CVE-2020-6553",
    "CVE-2020-6554",
    "CVE-2020-6555"
  );
  script_xref(name:"IAVA", value:"2020-A-0371");

  script_name(english:"Google Chrome < 84.0.4147.125 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 84.0.4147.125. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2020_08_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32e2f14f");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1107433");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1104046");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1108497");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1095584");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1100280");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1102153");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1103827");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1105426");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1106682");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1107815");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1108518");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1111307");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1094235");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1105202");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 84.0.4147.125 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6554");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");

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

google_chrome_check_version(installs:installs, fix:'84.0.4147.125', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

