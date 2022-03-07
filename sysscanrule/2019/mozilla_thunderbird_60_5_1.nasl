#
# (C) WebRAY Network Security, Inc.`
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-06.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(122402);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/07 12:34:17");

  script_cve_id(
    "CVE-2018-18335",
    "CVE-2018-18356",
    "CVE-2018-18509",
    "CVE-2019-5785"
  );
  script_xref(name: "MFSA", value: "2019-06");

  script_name(english:"Mozilla Thunderbird < 60.5.1");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is
prior to 60.5.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-06 advisory.

  - A buffer overflow vulnerability in the Skia library can
    occur with Canvas 2D acceleration on macOS. This issue
    was addressed by disabling Canvas 2D acceleration in
    Firefox ESR. *Note: this does not affect other
    versions and platforms where Canvas 2D acceleration is
    already disabled by default. (CVE-2018-18335)

  - A use-after-free vulnerability in the Skia library can
    occur when creating a path, leading to a potentially
    exploitable crash. (CVE-2018-18356)

  - A flaw during verification of certain S/MIME signatures
    causes emails to be shown in Thunderbird as having a
    valid digital signature, even if the shown message
    contents aren't covered by the signature. The flaw
    allows an attacker to reuse a valid S/MIME signature to
    craft an email message with arbitrary content.
    (CVE-2018-18509)

  - An integer overflow vulnerability in the Skia library
    can occur after specific transform operations, leading
    to a potentially exploitable crash. (CVE-2019-5785)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-06/");
  # https://googleprojectzero.blogspot.com/2019/02/the-curious-case-of-convexity-confusion.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18335");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'60.5.1', severity:SECURITY_WARNING);
