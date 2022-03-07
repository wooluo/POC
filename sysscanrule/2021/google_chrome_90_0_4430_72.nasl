##
# 
##

include('compat.inc');

if (description)
{
  script_id(148558);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id(
    "CVE-2021-21201",
    "CVE-2021-21202",
    "CVE-2021-21203",
    "CVE-2021-21204",
    "CVE-2021-21205",
    "CVE-2021-21207",
    "CVE-2021-21208",
    "CVE-2021-21209",
    "CVE-2021-21210",
    "CVE-2021-21211",
    "CVE-2021-21212",
    "CVE-2021-21213",
    "CVE-2021-21214",
    "CVE-2021-21215",
    "CVE-2021-21216",
    "CVE-2021-21217",
    "CVE-2021-21218",
    "CVE-2021-21219",
    "CVE-2021-21221"
  );

  script_name(english:"Google Chrome < 90.0.4430.72 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 90.0.4430.72. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_04_stable-channel-update-for-desktop_14 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/04/stable-channel-update-for-desktop_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec023c8b");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1025683");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1188889");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1192054");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1189926");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1165654");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1195333");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1185732");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1039539");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1143526");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1184562");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1103119");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1145024");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1161806");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1170148");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1172533");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1173297");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1166462");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1166478");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1166972");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 90.0.4430.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");

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

google_chrome_check_version(installs:installs, fix:'90.0.4430.72', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
