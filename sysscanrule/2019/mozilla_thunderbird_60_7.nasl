#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-15.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(125359);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id(
    "CVE-2018-18511",
    "CVE-2019-5798",
    "CVE-2019-7317",
    "CVE-2019-9797",
    "CVE-2019-9800",
    "CVE-2019-9815",
    "CVE-2019-9816",
    "CVE-2019-9817",
    "CVE-2019-9818",
    "CVE-2019-9819",
    "CVE-2019-9820",
    "CVE-2019-11691",
    "CVE-2019-11692",
    "CVE-2019-11693",
    "CVE-2019-11694",
    "CVE-2019-11698"
  );
  script_bugtraq_id(
    107009,
    107363,
    107486,
    108098,
    108418
  );
  script_xref(name:"MFSA", value:"2019-15");

  script_name(english:"Mozilla Thunderbird < 60.7");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is
prior to 60.7. It is, therefore, affected by multiple vulnerabilities
as referenced in the mfsa2019-15 advisory.

  - If hyperthreading is not disabled, a timing attack
    vulnerability exists, similar to previous Spectre
    attacks. Apple has shipped macOS 10.14.5 with an option
    to disable hyperthreading in applications running
    untrusted code in a thread through a new sysctl. Firefox
    now makes use of it on the main thread and any worker
    threads. Note: users need to update to macOS 10.14.5
    in order to take advantage of this change.
    (CVE-2019-9815)

  - A possible vulnerability exists where type confusion can
    occur when manipulating JavaScript objects in object
    groups, allowing for the bypassing of security checks
    within these groups. Note: this vulnerability has
    only been demonstrated with UnboxedObjects,
    which are disabled by default on all supported releases.
    (CVE-2019-9816)

  - Images from a different domain can be read using a
    canvas object in some circumstances. This could be used
    to steal image data from a different site in violation
    of same-origin policy. (CVE-2019-9817)

  - A race condition is present in the crash generation
    server used to generate data for the crash reporter.
    This issue can lead to a use-after-free in the main
    process, resulting in a potentially exploitable crash
    and a sandbox escape. Note: this vulnerability only
    affects Windows. Other operating systems are unaffected.
    (CVE-2019-9818)

  - A vulnerability where a JavaScript compartment mismatch
    can occur while working with the fetch API,
    resulting in a potentially exploitable crash.
    (CVE-2019-9819)

  - A use-after-free vulnerability can occur in the chrome
    event handler when it is freed while still in use. This
    results in a potentially exploitable crash.
    (CVE-2019-9820)

  - A use-after-free vulnerability can occur when working
    with XMLHttpRequest (XHR) in an event loop,
    causing the XHR main thread to be called after it has
    been freed. This results in a potentially exploitable
    crash. (CVE-2019-11691)

  - A use-after-free vulnerability can occur when listeners
    are removed from the event listener manager while still
    in use, resulting in a potentially exploitable crash.
    (CVE-2019-11692)

  - The bufferdata function in WebGL is
    vulnerable to a buffer overflow with specific graphics
    drivers on Linux. This could result in malicious content
    freezing a tab or triggering a potentially exploitable
    crash. Note: this issue only occurs on Linux. Other
    operating systems are unaffected. (CVE-2019-11693)

  - A use-after-free vulnerability was discovered in the
    pngimagefree function in the libpng
    library. This could lead to denial of service or a
    potentially exploitable crash when a malformed image is
    processed. (CVE-2019-7317)

  - Cross-origin images can be read in violation of the
    same-origin policy by exporting an image after using
    createImageBitmap to read the image and
    then rendering the resulting bitmap image within a
    canvas element. (CVE-2019-9797)

  - Cross-origin images can be read from a
    canvas element in violation of the same-
    origin policy using the
    transferFromImageBitmap method.
    (CVE-2018-18511)

  - A vulnerability exists in the Windows sandbox where an
    uninitialized value in memory can be leaked to a
    renderer from a broker when making a call to access an
    otherwise unavailable file. This results in the
    potential leaking of information stored at that memory
    location. Note: this issue only occurs on Windows.
    Other operating systems are unaffected. (CVE-2019-11694)

  - If a crafted hyperlink is dragged and dropped to the
    bookmark bar or sidebar and the resulting bookmark is
    subsequently dragged and dropped into the web content
    area, an arbitrary query of a user's browser history can
    be run and transmitted to the content page via
    drop event data. This allows for the theft
    of browser history by a malicious site. (CVE-2019-11698)

  - An out-of-bounds read can occur in the Skia library
    during path transformations. This could result in the
    exposure of data stored in memory. (CVE-2019-5798)

  - Mozilla developers and community members Olli Pettay,
    Bogdan Tara, Jan de Mooij, Jason Kratzer, Jan Varga,
    Gary Kwong, Tim Guan-tin Chien, Tyson Smith, Ronald
    Crane, and Ted Campbell reported memory safety bugs
    present in Firefox 66, Firefox ESR 60.6, and Thunderbird
    60.6. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort that
    some of these could be exploited to run arbitrary code.
    (CVE-2019-9800)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-15/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9800");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");

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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'60.7', severity:SECURITY_HOLE);
