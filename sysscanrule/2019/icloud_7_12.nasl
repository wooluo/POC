#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125878);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/18 10:31:32");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-8571",
    "CVE-2019-8577",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8598",
    "CVE-2019-8600",
    "CVE-2019-8602",  
    "CVE-2019-8601",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8628"
);
  script_bugtraq_id(
  108491,
  108497
);
  

  script_name(english:"Apple iCloud < 7.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of iCloud.");

  script_set_attribute(attribute:"synopsis", value:
"An iCloud softare installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the iCloud application installed on the remote Windows host is prior to
7.12. It is, therefore, affected by multiple vulnerabilities:

  - An arbitrary code execution vulnerability exists in SQLite & 
    WebKit due to maliciously crafted content. An unauthenticated, 
    remote attacker can exploit this to execute arbitrary code. 
    (CVE-2019-8600, CVE-2019-6237, CVE-2019-8571, CVE-2019-8583,
     CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594,
     CVE-2019-8595, CVE-2019-8596, CVE-2019-8597, CVE-2019-8601,
     CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611,
     CVE-2019-8615, CVE-2019-8619, CVE-2019-8622, CVE-2019-8623,
     CVE-2019-8628)

  - An privilege escalation vulnerability exists in SQLite due to 
    an input validation and memory corruption issue. An 
    unauthenticated, remote attacker can exploit this to execute 
    arbitrary code. (CVE-2019-8577, CVE-2019-8602)

  - An arbitrary memory read vulnerability exists in SQLite due to 
    improper input validation. An unauthenticated, remote attacker
    can exploit this to read restricted memory. (CVE-2019-8598)
 ");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210125");

  script_set_attribute(attribute:"solution", value:
"Upgrade to iCloud version 7.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8577");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:icloud_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("icloud_installed.nasl");
  script_require_keys("installed_sw/iCloud");

  exit(0);
}

include('vcf.inc');

app = 'iCloud';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{'fixed_version' : '7.12'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
