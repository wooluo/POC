##
# 
##

include('compat.inc');

if (description)
{
  script_id(151672);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-30541",
    "CVE-2021-30559",
    "CVE-2021-30560",
    "CVE-2021-30561",
    "CVE-2021-30562",
    "CVE-2021-30563",
    "CVE-2021-30564"
  );
  script_xref(name:"IAVA", value:"2021-A-0323");

  script_name(english:"Google Chrome < 91.0.4472.164 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 91.0.4472.164. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_07_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/07/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f55982c9");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1219082");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1214842");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1219209");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1219630");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1220078");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1228407");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1221309");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 91.0.4472.164 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

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

google_chrome_check_version(installs:installs, fix:'91.0.4472.164', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
