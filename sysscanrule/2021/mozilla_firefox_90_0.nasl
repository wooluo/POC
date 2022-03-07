
## 
# 
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-28.
# The text itself is copyright (C) Mozilla Foundation.
##



include('compat.inc');

if (description)
{
  script_id(151571);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-29970",
    "CVE-2021-29971",
    "CVE-2021-29972",
    "CVE-2021-29973",
    "CVE-2021-29974",
    "CVE-2021-29975",
    "CVE-2021-29976",
    "CVE-2021-29977",
    "CVE-2021-30547"
  );
  script_xref(name:"IAVA", value:"2021-A-0293-S");
  script_xref(name:"IAVA", value:"2021-A-0309");

  script_name(english:"Mozilla Firefox < 90.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 90.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-28 advisory.

  - A malicious webpage could have triggered a use-after-free, memory corruption, and a potentially
    exploitable crash. This bug only affected Firefox when accessibility was enabled. (CVE-2021-29970)

  - If a user had granted a permission to a webpage and saved that grant, any webpage running on the same host
    - irrespective of scheme or port - would be granted that permission.This bug only affects Firefox for
    Android. Other operating systems are unaffected. (CVE-2021-29971)

  - An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially
    exploitable crash. (CVE-2021-30547)

  - A user-after-free vulnerability was found via testing, and traced to an out-of-date Cairo library.
    Updating the library resolved the issue, and may have remediated other, unknown security vulnerabilities
    as well. (CVE-2021-29972)

  - Password autofill was enabled without user interaction on insecure websites on Firefox for Android. This
    was corrected to require user interaction with the page before a user's password would be entered by the
    browser's autofill functionality.This bug only affects Firefox for Android. Other operating systems
    are unaffected. (CVE-2021-29973)

  - When network partitioning was enabled, e.g. as a result of Enhanced Tracking Protection settings, a TLS
    error page would allow the user to override an error on a domain which had specified HTTP Strict Transport
    Security (which implies that the error should not be override-able.) This issue did not affect the network
    connections, and they were correctly upgraded to HTTPS automatically. (CVE-2021-29974)

  - Through a series of DOM manipulations, a message, over which the attacker had control of the text but not
    HTML or formatting, could be overlaid on top of another domain (with the new domain correctly shown in the
    address bar) resulting in possible user confusion. (CVE-2021-29975)

  - Mozilla developers Emil Ghitta, Tyson Smith, Valentin Gosu, Olli Pettay, and Randell Jesup reported memory
    safety bugs present in Firefox 89 and Firefox ESR 78.11. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code. (CVE-2021-29976)

  - Mozilla developers Andrew McCreight, Tyson Smith, Christian Holler, and Gabriele Svelto reported memory
    safety bugs present in Firefox 89. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code. (CVE-2021-29977)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-28/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 90.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29977");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'90.0', severity:SECURITY_HOLE);
