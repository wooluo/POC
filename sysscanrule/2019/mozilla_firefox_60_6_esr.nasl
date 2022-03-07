#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-08.
# The text itself is copyright (C) Mozilla Foundation.

include("compat.inc");

if (description)
{
  script_id(122950);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id(
    "CVE-2018-18506",
    "CVE-2019-9788",
    "CVE-2019-9790",
    "CVE-2019-9791",
    "CVE-2019-9792",
    "CVE-2019-9793",
    "CVE-2019-9794",
    "CVE-2019-9795",
    "CVE-2019-9796",
    "CVE-2019-9801"
  );
  script_xref(name: "MFSA", value: "2019-08");

  script_name(english:"Mozilla Firefox ESR < 60.6");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is
prior to 60.6. It is, therefore, affected by multiple vulnerabilities
as referenced in the mfsa2019-08 advisory.

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

  - Firefox will accept any registered Program ID as an
    external protocol handler and offer to launch this local
    application when given a matching URL on Windows
    operating systems. This should only happen if the
    program has specifically registered itself as a URL
    Handler in the Windows registry.  Note: This issue
    only affects Windows operating systems. Other operating
    systems are unaffected. (CVE-2019-9801)

  - When proxy auto-detection is enabled, if a web server
    serves a Proxy Auto-Configuration (PAC) file or if a PAC
    file is loaded locally, this PAC file can specify that
    requests to the localhost are to be sent through the
    proxy to another server. This behavior is disallowed by
    default when a proxy is manually configured, but when
    enabled could allow for attacks on services and tools
    that bind to the localhost for networked behavior if
    they are accessed through browsing. (CVE-2018-18506)

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
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-08/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9790");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'60.6', min:'60.0.0', severity:SECURITY_HOLE);
