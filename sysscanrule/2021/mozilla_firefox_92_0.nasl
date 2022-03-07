
## 
# 
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-38.
# The text itself is copyright (C) Mozilla Foundation.
##


include('compat.inc');

if (description)
{
  script_id(153089);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id(
    "CVE-2021-29993",
    "CVE-2021-38491",
    "CVE-2021-38492",
    "CVE-2021-38493",
    "CVE-2021-38494"
  );
  script_xref(name:"IAVA", value:"2021-A-0405");

  script_name(english:"Mozilla Firefox < 92.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 92.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2021-38 advisory.

  - Firefox for Android allowed navigations through the `intent://` protocol, which could be used to cause
    crashes and UI spoofs. This bug only affects Firefox for Android. Other operating systems are
    unaffected. (CVE-2021-29993)

  - Mixed-content checks were unable to analyze opaque origins which led to some mixed content being loaded.
    (CVE-2021-38491)

  - When delegating navigations to the operating system, Firefox would accept the `mk` scheme which might
    allow attackers to launch pages and execute scripts in Internet Explorer in unprivileged mode. This
    bug only affects Firefox for Windows. Other operating systems are unaffected. (CVE-2021-38492)

  - Mozilla developers Gabriele Svelto and Tyson Smith reported memory safety bugs present in Firefox 91 and
    Firefox ESR 78.13. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. (CVE-2021-38493)

  - Mozilla developers Christian Holler and Lars T Hansen reported memory safety bugs present in Firefox 91.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. (CVE-2021-38494)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-38/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 92.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/07");

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

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'92.0', severity:SECURITY_HOLE);
