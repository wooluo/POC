#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-07.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(122947);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/24 15:26:42");

  script_cve_id(
    "CVE-2019-9788",
    "CVE-2019-9789",
    "CVE-2019-9790",
    "CVE-2019-9791",
    "CVE-2019-9792",
    "CVE-2019-9793",
    "CVE-2019-9794",
    "CVE-2019-9795",
    "CVE-2019-9796",
    "CVE-2019-9797",
    "CVE-2019-9798",
    "CVE-2019-9799",
    "CVE-2019-9801",
    "CVE-2019-9802",
    "CVE-2019-9803",
    "CVE-2019-9804",
    "CVE-2019-9805",
    "CVE-2019-9806",
    "CVE-2019-9807",
    "CVE-2019-9808",
    "CVE-2019-9809"
  );
  script_xref(name: "MFSA", value: "2019-07");

  script_name(english:"Mozilla Firefox < 66.0");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote macOS or Mac OS X host
is prior to 66.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-07 advisory.

  - A use-after-free vulnerability can occur when a raw
    pointer to a DOM element on a page is obtained using
    JavaScript and the element is then removed while still
    in use. This results in a potentially exploitable crash.
    (CVE-2019-9790)

  - The type inference system allows the compilation of
    functions that can cause type confusions between
    arbitrary objects when compiled through the IonMonkey
    just-in-time (JIT) compiler and when the constructor
    function is entered through on-stack replacement (OSR).
    This allows for possible arbitrary reading and writing
    of objects during an exploitable crash. (CVE-2019-9791)

  - The IonMonkey just-in-time (JIT) compiler can leak an
    internal JSOPTIMIZEDOUT magic value to the
    running script during a bailout. This magic value can
    then be used by JavaScript to achieve memory corruption,
    which results in a potentially exploitable crash.
    (CVE-2019-9792)

  - A mechanism was discovered that removes some bounds
    checking for string, array, or typed array accesses if
    Spectre mitigations have been disabled. This
    vulnerability could allow an attacker to create an
    arbitrary value in compiled JavaScript, for which the
    range analysis will infer a fully controlled, incorrect
    range in circumstances where users have explicitly
    disabled Spectre mitigations.  Note: Spectre
    mitigations are currently enabled for all users by
    default settings. (CVE-2019-9793)

  - A vulnerability was discovered where specific command
    line arguments are not properly discarded during Firefox
    invocation as a shell handler for URLs. This could be
    used to retrieve and execute files whose location is
    supplied through these command line arguments if Firefox
    is configured as the default URI handler for a given URI
    scheme in third party applications and these
    applications insufficiently sanitize URL data. 
    Note: This issue only affects Windows operating systems.
    Other operating systems are unaffected. (CVE-2019-9794)

  - A vulnerability where type-confusion in the IonMonkey
    just-in-time (JIT) compiler could potentially be used by
    malicious JavaScript to trigger a potentially
    exploitable crash. (CVE-2019-9795)

  - A use-after-free vulnerability can occur when the SMIL
    animation controller incorrectly registers with the
    refresh driver twice when only a single registration is
    expected. When a registration is later freed with the
    removal of the animation controller element, the refresh
    driver incorrectly leaves a dangling pointer to the
    driver's observer array. (CVE-2019-9796)

  - Cross-origin images can be read in violation of the
    same-origin policy by exporting an image after using
    createImageBitmap to read the image and
    then rendering the resulting bitmap image within a
    canvas element. (CVE-2019-9797)

  - On Android systems, Firefox can load a library from
    APITRACELIB, which is writable by all users
    and applications. This could allow malicious third party
    applications to execute a man-in-the-middle attack if a
    malicious code was written to that location and loaded.
     Note: This issue only affects Android. Other
    operating systems are unaffected. (CVE-2019-9798)

  - Insufficient bounds checking of data during inter-
    process communication might allow a compromised content
    process to be able to read memory from the parent
    process under certain conditions. (CVE-2019-9799)

  - Firefox will accept any registered Program ID as an
    external protocol handler and offer to launch this local
    application when given a matching URL on Windows
    operating systems. This should only happen if the
    program has specifically registered itself as a URL
    Handler in the Windows registry.  Note: This issue
    only affects Windows operating systems. Other operating
    systems are unaffected. (CVE-2019-9801)

  - If a Sandbox content process is compromised, it can
    initiate an FTP download which will then use a child
    process to render the downloaded data. The downloaded
    data can then be passed to the Chrome process with an
    arbitrary file length supplied by an attacker, bypassing
    sandbox protections and allow for a potential memory
    read of adjacent data from the privileged Chrome
    process, which may include sensitive data.
    (CVE-2019-9802)

  - The Upgrade-Insecure-Requests (UIR) specification states
    that if UIR is enabled through Content Security Policy
    (CSP), navigation to a same-origin URL must be upgraded
    to HTTPS. Firefox will incorrectly navigate to an HTTP
    URL rather than perform the security upgrade requested
    by the CSP in some circumstances, allowing for potential
    man-in-the-middle attacks on the linked resources.
    (CVE-2019-9803)

  - In Firefox Developer Tools it is possible that pasting
    the result of the 'Copy as cURL'  command into a command
    shell on macOS will cause the execution of unintended
    additional bash script commands if the URL was
    maliciously crafted. This is the result of an issue with
    the native version of Bash on macOS.  Note: This
    issue only affects macOS. Other operating systems are
    unaffected. (CVE-2019-9804)

  - A latent vulnerability exists in the Prio library where
    data may be read from uninitialized memory for some
    functions, leading to potential memory corruption.
    (CVE-2019-9805)

  - A vulnerability exists during authorization prompting
    for FTP transaction where successive modal prompts are
    displayed and cannot be immediately dismissed. This
    allows for a denial of service (DOS) attack.
    (CVE-2019-9806)

  - When arbitrary text is sent over an FTP connection and a
    page reload is initiated, it is possible to create a
    modal alert message with this text as the content. This
    could potentially be used for social engineering
    attacks. (CVE-2019-9807)

  - If the source for resources on a page is through an FTP
    connection, it is possible to trigger a series of modal
    alert messages for these resources through invalid
    credentials or locations. These messages cannot be
    immediately dismissed, allowing for a denial of service
    (DOS) attack. (CVE-2019-9809)

  - If WebRTC permission is requested from documents with
    data: or blob: URLs, the permission notifications do not
    properly display the originating domain. The
    notification states Unknown origin as the requestee,
    leading to user confusion about which site is asking for
    this permission. (CVE-2019-9808)

  - Mozilla developers and community members Dragana
    Damjanovic, Emilio Cobos lvarez, Henri Sivonen, Narcis
    Beleuzu, Julian Seward, Marcia Knous, Gary Kwong, Tyson
    Smith, Yaron Tausky, Ronald Crane, and Andr Bargull
    reported memory safety bugs present in Firefox 65. Some
    of these bugs showed evidence of memory corruption and
    we presume that with enough effort that some of these
    could be exploited to run arbitrary code.
    (CVE-2019-9789)

  - Mozilla developers and community members Bob Clary,
    Chun-Min Chang, Aral Yaman, Andreea Pavel, Jonathan Kew,
    Gary Kwong, Alex Gaynor, Masayuki Nakano, and Anne van
    Kesteren reported memory safety bugs present in Firefox
    65 and Firefox ESR 60.5. Some of these bugs showed
    evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to
    run arbitrary code. (CVE-2019-9788)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-07/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 66.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9790");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (is_esr) exit(0, 'The Mozilla Firefox installation is in the ESR branch.');

mozilla_check_version(version:version, path:path, product:'firefox', esr:FALSE, fix:'66.0', severity:SECURITY_HOLE);
