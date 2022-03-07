## 
# 
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-03.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(145465);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2021-23953",
    "CVE-2021-23954",
    "CVE-2021-23955",
    "CVE-2021-23956",
    "CVE-2021-23957",
    "CVE-2021-23958",
    "CVE-2021-23959",
    "CVE-2021-23960",
    "CVE-2021-23961",
    "CVE-2021-23962",
    "CVE-2021-23963",
    "CVE-2021-23964",
    "CVE-2021-23965"
  );

  script_name(english:"Mozilla Firefox < 85.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 85.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-03 advisory.

  - If a user clicked into a specifically crafted PDF, the PDF reader could be confused into leaking cross-
    origin information, when said information is served as chunked data. (CVE-2021-23953)

  - Using the new logical assignment operators in a JavaScript switch statement could have caused a type
    confusion, leading to a memory corruption and a potentially exploitable crash. (CVE-2021-23954)

  - The browser could have been confused into transferring a pointer lock state into another tab, which could
    have lead to clickjacking attacks. (CVE-2021-23955)

  - An ambiguous file picker design could have confused users who intended to select and upload a single file
    into uploading a whole directory. This was addressed by adding a new prompt. (CVE-2021-23956)

  - Navigations through the Android-specific `intent` URL scheme could have been misused to escape iframe
    sandbox.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.
    (CVE-2021-23957)

  - The browser could have been confused into transferring a screen sharing state into another tab, which
    would leak unintended information. (CVE-2021-23958)

  - An XSS bug in internal error pages could have led to various spoofing attacks, including other error pages
    and the address bar.Note: This issue only affected Firefox for Android. Other operating systems are
    unaffected. (CVE-2021-23959)

  - Performing garbage collection on re-declared JavaScript variables resulted in a user-after-poison, and a
    potentially exploitable crash. (CVE-2021-23960)

  - Further techniques that built on the slipstream research combined with a malicious webpage could have
    exposed both an internal network's hosts as well as services running on the user's local machine.
    (CVE-2021-23961)

  - Incorrect use of the RowCountChanged method could have led to a user-after-poison and a
    potentially exploitable crash. (CVE-2021-23962)

  - When sharing geolocation during an active WebRTC share, Firefox could have reset the webRTC sharing state
    in the user interface, leading to loss of control over the currently granted permission (CVE-2021-23963)

  - Mozilla developers Andrew McCreight, Tyson Smith, Jesse Schwartzentruber, Jon Coppeard, Byron Campen,
    Andr Bargull, Steve Fink, Jason Kratzer, Christian Holler, Alexis Beingessner reported memory safety bugs
    present in Firefox 84 and Firefox ESR 78.6. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2021-23964)

  - Mozilla developers Sebastian Hengst, Christian Holler, Tyson Smith reported memory safety bugs present in
    Firefox 84. Some of these bugs showed evidence of memory corruption and we presume that with enough effort
    some of these could have been exploited to run arbitrary code. (CVE-2021-23965)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-03/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 85.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'85.0', xss:TRUE, severity:SECURITY_HOLE);
