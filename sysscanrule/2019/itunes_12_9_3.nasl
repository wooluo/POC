#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121473);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id(
    "CVE-2019-6212",
    "CVE-2019-6215",
    "CVE-2019-6216",
    "CVE-2019-6217",
    "CVE-2019-6221",
    "CVE-2019-6226",
    "CVE-2019-6227",
    "CVE-2019-6229",
    "CVE-2019-6233",
    "CVE-2019-6234",
    "CVE-2019-6235",
    "CVE-2018-20346",
    "CVE-2018-20505",
    "CVE-2018-20506"
  );
  script_bugtraq_id(
    106323,
    106691,
    106694,
    106696,
    106698,
    106699,
    106724
  );

  script_xref(name: "APPLE-SA", value: "APPLE-SA-2019-1-24-1");

  script_name(english:"Apple iTunes < 12.9.3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on remote host is affected by multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.9.3. It is, therefore, affected by multiple vulnerabilities
as referenced in the HT209450 advisory:

  - Multiple vulnerabilities exist due to input processing
    flaws in the WebKit component. An attacker may be able
    to leverage one of these vulnerability, by providing
    maliciously crafted web content, to execute arbitrary
    code on the host. (CVE-2019-6212, CVE-2019-6215,
    CVE-2019-6216, CVE-2019-6217, CVE-2019-6226,
    CVE-2019-6227, CVE-2019-6233, CVE-2019-6234)

  - A universal cross-site scripting vulnerability exists in
    the WebKit component. An attacker may be able to leverage
    this vulnerability, by providing maliciously crafted web
    content, to execute arbitrary script code in the security
    context of any site. (CVE-2019-6229)

  - A memory corruption vulnerability exists in the
    AppleKeyStore component. An attacker may be able to
    leverage this vulnerability to allow a process to
    circumvent sandbox restrictions. (CVE-2019-6235)

  - An out-of-bounds read vulnerability exists in the
    Core Media component. An attacker may be able to leverage
    this vulnerability to allow a malicious application to
    elevate its privileges. (CVE-2019-6221)

  - Multiple memory corruption issues exist in the SQLite
    component. An attacker may be able to leverage these
    vulnerabilities, by executing a malicious SQL query, to
    execute arbitrary code on the host. (CVE-2018-20346,
    CVE-2018-20505, CVE-2018-20506)


Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209450");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6212");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}
include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);
constraints = [{"fixed_version":"12.9.3"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
