#
# (C) WebRAY Network Security, Inc.`
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-05.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(122193);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/21 11:53:46");

  script_cve_id("CVE-2018-18335", "CVE-2018-18356", "CVE-2019-5785");
  script_xref(name: "MFSA", value: "2019-05");

  script_name(english:"Mozilla Firefox ESR < 60.5.1");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X
host is prior to 60.5.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-05 advisory.

  - A use-after-free vulnerability in the Skia library can
    occur when creating a path, leading to a potentially
    exploitable crash. (CVE-2018-18356)

  - An integer overflow vulnerability in the Skia library
    can occur after specific transform operations, leading
    to a potentially exploitable crash. (CVE-2019-5785)

  - A buffer overflow vulnerability in the Skia library can
    occur with Canvas 2D acceleration on macOS. This issue
    was addressed by disabling Canvas 2D acceleration in
    Firefox ESR. *Note: this does not affect other
    versions and platforms where Canvas 2D acceleration is
    already disabled by default.* (CVE-2018-18335)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-05/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525433");
  # https://bugzilla.mozilla.org/show_bug.cgi?id=https://googleprojectzero.blogspot.com/2019/02/the-curious-case-of-convexity-confusion.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525815");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18335");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'60.5.1', severity:SECURITY_WARNING);
