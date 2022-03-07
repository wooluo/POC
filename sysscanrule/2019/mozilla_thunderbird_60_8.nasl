#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-23.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(126704);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/16  7:34:11");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-11709",
    "CVE-2019-11711",
    "CVE-2019-11712",
    "CVE-2019-11713",
    "CVE-2019-11715",
    "CVE-2019-11717",
    "CVE-2019-11719",
    "CVE-2019-11729",
    "CVE-2019-11730"
  );
  script_xref(name: "MFSA", value: "2019-23");

  script_name(english:"Mozilla Thunderbird < 60.8");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 60.8. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-23 advisory.

  - As part of his winning Pwn2Own entry, Niklas Baumstark
    demonstrated a sandbox escape by installing a malicious
    language pack and then opening a browser feature that
    used the compromised translation. (CVE-2019-9811)

  - When an inner window is reused, it does not consider the
    use of document.domain for cross-origin
    protections. If pages on different subdomains ever
    cooperatively use document.domain, then
    either page can abuse this to inject script into
    arbitrary pages on the other subdomain, even those that
    did not use document.domain to relax their
    origin security. (CVE-2019-11711)

  - POST requests made by NPAPI plugins, such as Flash, that
    receive a status 308 redirect response can bypass CORS
    requirements. This can allow an attacker to perform
    Cross-Site Request Forgery (CSRF) attacks.
    (CVE-2019-11712)

  - A use-after-free vulnerability can occur in HTTP/2 when
    a cached HTTP/2 stream is closed while still in use,
    resulting in a potentially exploitable crash.
    (CVE-2019-11713)

  - Empty or malformed p256-ECDH public keys may trigger a
    segmentation fault due values being improperly sanitized
    before being copied into memory and used.
    (CVE-2019-11729)

  - Due to an error while parsing page content, it is
    possible for properly sanitized user input to be
    misinterpreted and lead to XSS hazards on web sites in
    certain circumstances. (CVE-2019-11715)

  - A vulnerability exists where the caret (^) character
    is improperly escaped constructing some URIs due to it
    being used as a separator, allowing for possible
    spoofing of origin attributes. (CVE-2019-11717)

  - When importing a curve25519 private key in PKCS#8format
    with leading 0x00 bytes, it is possible to trigger an
    out-of-bounds read in the Network Security Services
    (NSS) library. This could lead to information
    disclosure. (CVE-2019-11719)

  - A vulnerability exists where if a user opens a locally
    saved HTML file, this file can use file:
    URIs to access other files in the same directory or sub-
    directories if the names are known or guessed. The Fetch
    API can then be used to read the contents of any files
    stored in these directories and they may uploaded to a
    server. Luigi Gubello demonstrated that in combination
    with a popular Android messaging app, if a malicious
    HTML attachment is sent to a user and they opened that
    attachment in Firefox, due to that app's predictable
    pattern for locally-saved file names, it is possible to
    read attachments the victim received from other
    correspondents. (CVE-2019-11730)

  - Mozilla developers and community members Andreea Pavel,
    Christian Holler, Honza Bambas, Jason Kratzer, and Jeff
    Gilbert reported memory safety bugs present in Firefox
    67, Firefox ESR 60.7, and Thunderbird 60.7. Some of
    these bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could
    be exploited to run arbitrary code. (CVE-2019-11709)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-23/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11713");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/16");

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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'60.8', xss:TRUE, severity:SECURITY_HOLE);
