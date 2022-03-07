#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127114);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id("CVE-2019-9848", "CVE-2019-9849");
  script_bugtraq_id(109374);
  script_xref(name:"IAVB", value:"2019-B-0067");

  script_name(english:"LibreOffice < 6.2.5 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is
prior to 6.2.5. It is, therefore, affected by multiple
vulnerabilities :

  - An arbitrary script execution vulnerability exists due
    to a flaw allowing event-based execution of python
    scripts within a document. Note, LibreLogo must be
    installed for this vulnerability to be exploitable.
    LibreLogo is frequently bundled with LibreOffice.
    (CVE-2019-9848)

  - An information disclosure vulnerability exists due to how
    bullet graphics are handled when in 'stealth mode'. An
    unauthenticated, remote, attacker could utilize this
    vulnerability to cause LibreOffice to perform remote
    requests when they would typically not be permitted.
    (CVE-2019-9849)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2019-9848/
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2019-9849/
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 6.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9848");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'LibreOffice');

constraints = [{'fixed_version':'6.2.5'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
