## 
# 
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-16.
# The text itself is copyright (C) Mozilla Foundation.
## 

include('compat.inc');

if (description)
{
  script_id(148767);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2021-23994",
    "CVE-2021-23995",
    "CVE-2021-23996",
    "CVE-2021-23997",
    "CVE-2021-23998",
    "CVE-2021-23999",
    "CVE-2021-24000",
    "CVE-2021-24001",
    "CVE-2021-24002",
    "CVE-2021-29944",
    "CVE-2021-29945",
    "CVE-2021-29946",
    "CVE-2021-29947"
  );

  script_name(english:"Mozilla Firefox < 88.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 88.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-16 advisory.

  - A WebGL framebuffer was not initialized early enough, resulting in memory corruption and an out of bound
    write. (CVE-2021-23994)

  - When Responsive Design Mode was enabled, it used references to objects that were previously freed. We
    presume that with enough effort this could have been exploited to run arbitrary code. (CVE-2021-23995)

  - By utilizing 3D CSS in conjunction with Javascript, content could have been rendered outside the webpage's
    viewport, resulting in a spoofing attack that could have been used for phishing or other attacks on a
    user. (CVE-2021-23996)

  - Due to unexpected data type conversions, a use-after-free could have occurred when interacting with the
    font cache. We presume that with enough effort this could have been exploited to run arbitrary code.
    (CVE-2021-23997)

  - Through complicated navigations with new windows, an HTTP page could have inherited a secure lock icon
    from an HTTPS page. (CVE-2021-23998)

  - If a Blob URL was loaded through some unusual user interaction, it could have been loaded by the System
    Principal and granted additional privileges that should not be granted to web content. (CVE-2021-23999)

  - A race condition with requestPointerLock() and setTimeout() could have resulted
    in a user interacting with one tab when they believed they were on a separate tab. In conjunction with
    certain elements (such as <input type=file>) this could have led to an attack where a
    user was confused about the origin of the webpage and potentially disclosed information they did not
    intend to. (CVE-2021-24000)

  - A compromised content process could have performed session history manipulations it should not have been
    able to due to testing infrastructure that was not restricted to testing-only configurations.
    (CVE-2021-24001)

  - When a user clicked on an FTP URL containing encoded newline characters (%0A and %0D), the newlines would
    have been interpreted as such and allowed arbitrary commands to be sent to the FTP server.
    (CVE-2021-24002)

  - The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and
    result in a crash. Note: This issue only affected x86-32 platforms. Other platforms are unaffected.
    (CVE-2021-29945)

  - Lack of escaping allowed HTML injection when a webpage was viewed in Reader View. While a Content Security
    Policy prevents direct code execution, HTML injection is still possible.Note: This issue only affected
    Firefox for Android. Other operating systems are unaffected. (CVE-2021-29944)

  - Ports that were written as an integer overflow above the bounds of a 16-bit integer could have bypassed
    port blocking restrictions when used in the Alt-Svc header. (CVE-2021-29946)

  - Mozilla developers and community members Ryan VanderMeulen, Sean Feng, Tyson Smith, Julian Seward,
    Christian Holler reported memory safety bugs present in Firefox 87. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. (CVE-2021-29947)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-16/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 88.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");

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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'88.0', severity:SECURITY_HOLE);
