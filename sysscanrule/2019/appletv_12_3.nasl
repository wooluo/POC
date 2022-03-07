#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125148);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/29 10:47:07");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-8560",
    "CVE-2019-8568",
    "CVE-2019-8571",
    "CVE-2019-8574",
    "CVE-2019-8576",
    "CVE-2019-8577",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8585",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8591",
    "CVE-2019-8593",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8598",
    "CVE-2019-8600",
    "CVE-2019-8601",
    "CVE-2019-8602",
    "CVE-2019-8605",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8620",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8628",
    "CVE-2019-8637"
  );
  script_xref(name:"APPLE-SA", value:"HT210120");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-05-09");

  script_name(english:"Apple TV < 12.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 12.3. It is therefore affected by multiple vulnerabilities
as described in the HT210120 security advisory:

  - Multiple unspecified command execution vulnerabilities exist that
    allow an attacker to execute arbitrary commands, sometimes with
    kernel privileges.(CVE-2019-8593, CVE-2019-8585, CVE-2019-8605,
    CVE-2019-8600, CVE-2019-8574)
    
  - Multiple elevation of privilege vulnerabilities exist due to
    improper memory handling. An application can exploit this to gain
    elevated privileges. (CVE-2019-6237
    CVE-2019-8571, CVE-2019-8583, CVE-2019-8584, CVE-2019-8586,
    CVE-2019-8587, CVE-2019-8594, CVE-2019-8595, CVE-2019-8596,
    CVE-2019-8597, CVE-2019-8601, CVE-2019-8608)
    
  - An un disclosed elevation of privilege vulnerability exist due to
  improper memory handling. An application can exploit this to gain
  elevated privileges. (CVE-2019-8602)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210120");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8605");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include("audit.inc");
include("appletv_func.inc");

url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

# https://en.wikipedia.org/wiki/TvOS
# 4th gen model "5,3" and 5th gen model "6,2" share same build
fixed_build = '16M153';
tvos_ver = '12.3';

# determine gen from the model
gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  affected_gen   : make_list(4, 5),
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
