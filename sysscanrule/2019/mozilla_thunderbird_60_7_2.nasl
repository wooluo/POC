#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-20.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(126218);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/28 10:05:54");

  script_cve_id("CVE-2019-11707", "CVE-2019-11708");
  script_bugtraq_id(108810, 108835);
  script_xref(name:"MFSA", value:"2019-20");
  script_xref(name: "IAVA", value: "2019-A-0211");

  script_name(english:"Mozilla Thunderbird < 60.7.2");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 60.7.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2019-20 advisory.

  - A denial of service (DoS) vulnerability exists in the Arrays.pop component due to a type confusion vulnerability. 
    An unauthenticated, remote attacker can exploit this issue, by manipulating JavaScript objects, to cause the 
    application to stop responding (CVE-2019-11707).

  - A remote command execution vulnerability exists in Thunderbird's Prompt:Open IPC component due to insufficient 
    validation of user-supplied data. An unauthenticated, remote attacker can exploit this to escape a child process' 
    sandbox and execute arbitrary commands with the priviliges of the user running the main Thunderbird process
    (CVE-2019-11708).

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2019-20/
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mozilla Thunderbird version 60.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11707");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'60.7.2', severity:SECURITY_HOLE);
