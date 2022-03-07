#
# 
#

include('compat.inc');

if (description)
{
  script_id(140700);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id(
    "CVE-2020-15960",
    "CVE-2020-15961",
    "CVE-2020-15962",
    "CVE-2020-15963",
    "CVE-2020-15964",
    "CVE-2020-15965",
    "CVE-2020-15966"
  );
  script_xref(name:"IAVA", value:"2020-A-0436");

  script_name(english:"Google Chrome < 85.0.4183.121 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 85.0.4183.121. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2020_09_stable-channel-update-for-desktop_21 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/09/stable-channel-update-for-desktop_21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f96100fb");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1100136");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1114636");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1121836");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1113558");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1126249");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1113565");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1121414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 85.0.4183.121 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");

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

google_chrome_check_version(installs:installs, fix:'85.0.4183.121', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);


