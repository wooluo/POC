## 
# 
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-10.
# The text itself is copyright (C) Mozilla Foundation.
## 

include('compat.inc');

if (description)
{
  script_id(148014);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id(
    "CVE-2021-23981",
    "CVE-2021-23982",
    "CVE-2021-23983",
    "CVE-2021-23984",
    "CVE-2021-23985",
    "CVE-2021-23986",
    "CVE-2021-23987",
    "CVE-2021-23988"
  );

  script_name(english:"Mozilla Firefox < 87.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 87.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-10 advisory.

  - A texture upload of a Pixel Buffer Object could have confused the WebGL code to skip binding the buffer
    used to unpack it, resulting in memory corruption and a potentially exploitable information leak or crash.
    (CVE-2021-23981)

  - Using techniques that built on the slipstream research, a malicious webpage could have scanned both an
    internal network's hosts as well as services running on the user's local machine utilizing WebRTC
    connections. (CVE-2021-23982)

  - By causing a transition on a parent node by removing a CSS rule, an invalid property for a marker could
    have been applied, resulting in memory corruption and a potentially exploitable crash. (CVE-2021-23983)

  - A malicious extension could have opened a popup window lacking an address bar. The title of the popup
    lacking an address bar should not be fully controllable, but in this situation was. This could have been
    used to spoof a website and attempt to trick the user into providing credentials. (CVE-2021-23984)

  - If an attacker is able to alter specific about:config values (for example malware running on the user's
    computer), the Devtools remote debugging feature could have been enabled in a way that was unnoticable to
    the user. This would have allowed a remote attacker (able to make a direct network connection to the
    victim) to monitor the user's browsing activity and (plaintext) network traffic. This was addressed by
    providing a visual cue when Devtools has an open network socket. (CVE-2021-23985)

  - A malicious extension with the 'search' permission could have installed a new search engine whose favicon
    referenced a cross-origin URL.  The response to this cross-origin request could have been read by the
    extension, allowing a same-origin policy bypass by the extension, which should not have cross-origin
    permissions.  This cross-origin request was made without cookies, so the sensitive information disclosed
    by the violation was limited to local-network resources or resources that perform IP-based authentication.
    (CVE-2021-23986)

  - Mozilla developers and community members Matthew Gregan, Tyson Smith, Julien Wajsberg, and Alexis
    Beingessner reported memory safety bugs present in Firefox 86 and Firefox ESR 78.8. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2021-23987)

  - Mozilla developers Tyson Smith and Christian Holler reported memory safety bugs present in Firefox 86.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. (CVE-2021-23988)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-10/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 87.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23987");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'87.0', severity:SECURITY_HOLE);
