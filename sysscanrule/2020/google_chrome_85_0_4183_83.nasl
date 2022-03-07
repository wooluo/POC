#
# 
#

include('compat.inc');

if (description)
{
  script_id(139794);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/28");

  script_cve_id(
    "CVE-2020-6558",
    "CVE-2020-6559",
    "CVE-2020-6560",
    "CVE-2020-6561",
    "CVE-2020-6562",
    "CVE-2020-6563",
    "CVE-2020-6564",
    "CVE-2020-6565",
    "CVE-2020-6566",
    "CVE-2020-6567",
    "CVE-2020-6568",
    "CVE-2020-6569",
    "CVE-2020-6570",
    "CVE-2020-6571"
  );
  script_xref(name:"IAVA", value:"2020-A-0388");

  script_name(english:"Google Chrome < 85.0.4183.83 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 85.0.4183.83. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2020_08_stable-channel-update-for-desktop_25 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/08/stable-channel-update-for-desktop_25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e44927e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1109120");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1116706");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1108181");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/932892");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1086845");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1104628");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/841622");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1029907");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1065264");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/937179");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1092451");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/995732");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1084699");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1085315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 85.0.4183.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

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

google_chrome_check_version(installs:installs, fix:'85.0.4183.83', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);


