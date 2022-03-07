#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127914);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20  9:15:32");

  script_cve_id(
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8685",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-13118"
  );
  script_bugtraq_id(
    109323,
    109328,
    109329
  );

  script_name(english:"Apple iCloud 7.x < 7.13 / 10.x < 10.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of iCloud.");

  script_set_attribute(attribute:"synopsis", value:
"An iCloud software installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the iCloud application installed on the remote Windows host is 7.x prior to 7.13 or 10.x
prior to 10.6. It is, therefore, affected by multiple vulnerabilities:

  - Multiple arbitrary code execution vulnerabilities exist with in the WebKit due to improper handling of maliciously
    crafted content. An unauthenticated, remote attacker can exploit this to execute arbitrary code. (CVE-2019-8644,
    CVE-2019-8666, CVE-2019-8669, CVE-2019-8671, CVE-2019-8672, CVE-2019-8673, CVE-2019-8676, CVE-2019-8677,
    CVE-2019-8678, CVE-2019-8679, CVE-2019-8680, CVE-2019-8681, CVE-2019-8683, CVE-2019-8684, CVE-2019-8685,
    CVE-2019-8686, CVE-2019-8687, CVE-2019-8688, CVE-2019-8689)

  - A cross-site scripting (XSS) vulnerability exists with in the WebKit due to improper handling synchronous page loads.
    An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to
    execute arbitrary script code in a user's browser session. (CVE-2019-8649)

  - A cross-site scripting (XSS) vulnerability exists with in the WebKit due to improper validation of user-supplied
    input before returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to
    click a specially crafted URL, to execute arbitrary script code in a user's browser session. (CVE-2019-8658)

  - A cross-site scripting (XSS) vulnerability exists with in the WebKit due to improper handling of document loads. An
    unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute
    arbitrary script code in a user's browser session. (CVE-2019-8690)

  - An information disclosure vulnerability exists in the included libxslt library due to improper input validation. An
    unauthenticated, remote attacker can exploit this, to disclose potentially sensitive information. (CVE-2019-13118)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210357");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iCloud version 7.13, 10.6, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8644");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

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

constraints = [
  {'min_version' : '7.0',  'fixed_version' : '7.13'},
  {'min_version' : '10.0', 'fixed_version' : '10.6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
