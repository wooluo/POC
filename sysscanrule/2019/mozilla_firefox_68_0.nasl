#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-21.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(126622);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/11 16:50:50");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-11709",
    "CVE-2019-11710",
    "CVE-2019-11711",
    "CVE-2019-11712",
    "CVE-2019-11713",
    "CVE-2019-11714",
    "CVE-2019-11715",
    "CVE-2019-11716",
    "CVE-2019-11717",
    "CVE-2019-11718",
    "CVE-2019-11719",
    "CVE-2019-11720",
    "CVE-2019-11721",
    "CVE-2019-11723",
    "CVE-2019-11724",
    "CVE-2019-11725",
    "CVE-2019-11727",
    "CVE-2019-11728",
    "CVE-2019-11729",
    "CVE-2019-11730"
  );
  script_bugtraq_id(
    109081,
    109083,
    109084,
    109085,
    109086,
    109087
  );
  script_xref(name: "MFSA", value: "2019-21");
  script_xref(name: "IAVA", value: "2019-A-0231");

  script_name(english:"Mozilla Firefox < 68.0");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 68.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-21 advisory.

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

  - Necko can access a child on the wrong thread during UDP
    connections, resulting in a potentially exploitable
    crash in some instances. (CVE-2019-11714)

  - Empty or malformed p256-ECDH public keys may trigger a
    segmentation fault due values being improperly sanitized
    before being copied into memory and used.
    (CVE-2019-11729)

  - Due to an error while parsing page content, it is
    possible for properly sanitized user input to be
    misinterpreted and lead to XSS hazards on web sites in
    certain circumstances. (CVE-2019-11715)

  - Until explicitly accessed by script,
    window.globalThis is not enumerable and, as
    a result, is not visible to code such as
    Object.getOwnPropertyNames(window). Sites
    that deploy a sandboxing that depends on enumerating and
    freezing access to the window object may miss this,
    allowing their sandboxes to be bypassed.
    (CVE-2019-11716)

  - A vulnerability exists where the caret (^) character
    is improperly escaped constructing some URIs due to it
    being used as a separator, allowing for possible
    spoofing of origin attributes. (CVE-2019-11717)

  - Activity Stream can display content from sent from the
    Snippet Service website. This content is written to
    innerHTML on the Activity Stream page
    without sanitization, allowing for a potential access to
    other information available to the Activity Stream, such
    as browsing history, if the Snipper Service were
    compromised. (CVE-2019-11718)

  - When importing a curve25519 private key in PKCS#8format
    with leading 0x00 bytes, it is possible to trigger an
    out-of-bounds read in the Network Security Services
    (NSS) library. This could lead to information
    disclosure. (CVE-2019-11719)

  - Some unicode characters are incorrectly treated as
    whitespace during the parsing of web content instead of
    triggering parsing errors. This allows malicious code to
    then be processed, evading cross-site scripting (XSS)
    filtering. (CVE-2019-11720)

  - The unicode latin 'kra' character can be used to spoof a
    standard 'k' character in the addressbar. This allows
    for domain spoofing attacks as do not display as
    punycode text, allowing for user confusion.
    (CVE-2019-11721)

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

  - A vulnerability exists during the installation of add-
    ons where the initial fetch ignored the origin
    attributes of the browsing context. This could leak
    cookies in private browsing mode or across different
    containers for people who use the Firefox Multi-
    Account Containers Web Extension. (CVE-2019-11723)

  - Application permissions give additional remote
    troubleshooting permission to the site
    input.mozilla.org, which has been retired and now
    redirects to another site. This additional permission is
    unnecessary and is a potential vector for malicious
    attacks. (CVE-2019-11724)

  - When a user navigates to site marked as unsafe by the
    Safebrowsing API, warning messages are displayed and
    navigation is interrupted but resources from the same
    site loaded through websockets are not blocked, leading
    to the loading of unsafe resources and bypassing
    safebrowsing protections. (CVE-2019-11725)

  - A vulnerability exists where it possible to force
    Network Security Services (NSS) to sign
    CertificateVerify with PKCS#1 v1.5
    signatures when those are the only ones advertised by
    server in CertificateRequest in TLS 1.3.
    PKCS#1 v1.5 signatures should not be used for TLS 1.3
    messages. (CVE-2019-11727)

  - The HTTP Alternative Services header, Alt-
    Svc, can be used by a malicious site to scan all
    TCP ports of any host that the accessible to a user when
    web content is loaded. (CVE-2019-11728)

  - Mozilla developers and community members Andr Bargull,
    Christian Holler, Natalia Csoregi, Raul Gurzau, Daniel
    Varga, Jon Coppeard, Marcia Knous, Gary Kwong, Randell
    Jesup, David Bolter, Jeff Gilbert, and Deian Stefan
    reported memory safety bugs present in Firefox 67. Some
    of these bugs showed evidence of memory corruption and
    we presume that with enough effort that some of these
    could be exploited to run arbitrary code.
    (CVE-2019-11710)

  - Mozilla developers and community members Andreea Pavel,
    Christian Holler, Honza Bambas, Jason Kratzer, and Jeff
    Gilbert reported memory safety bugs present in Firefox
    67 and Firefox ESR 60.7. Some of these bugs showed
    evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to
    run arbitrary code. (CVE-2019-11709)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-21/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 68.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11709");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'68.0', xss:TRUE, severity:SECURITY_HOLE);
