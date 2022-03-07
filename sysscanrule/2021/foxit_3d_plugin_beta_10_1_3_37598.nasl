##
# 
##

include('compat.inc');

if (description)
{
  script_id(148136);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/02");

  script_cve_id(
    "CVE-2021-27261",
    "CVE-2021-27262",
    "CVE-2021-27263",
    "CVE-2021-27264",
    "CVE-2021-27265",
    "CVE-2021-27266",
    "CVE-2021-27267",
    "CVE-2021-27268",
    "CVE-2021-27269",
    "CVE-2021-27271"
  );
  script_xref(name:"IAVA", value:"2021-A-0143");

  script_name(english:"Foxit 3D Plugin Beta < 10.1.3.37598 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a Foxit plugin installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Foxit 3D plugin installed on the remote Windows host is prior to 10.1.3.37598. It is, therefore,
affected by multiple vulnerabilities that could lead to a crash, sensitive information disclosure, or remote code
execution, as follows:

  - A flaw in the handling of U3D objects in PDF files allows remote attackers to execute arbitrary code due
    to a lack of proper validation of user-supplied data. (CVE-2021-27269)

  - Out-of-bounds read, use-after-free, and memory corruption vulnerabilities that allow attackers to execute
    remote code or disclose sensitive information due to a parse error. (CVE-2021-27261, CVE-2021-27262,
    CVE-2021-27263, CVE-2021-27264, CVE-2021-27265, CVE-2021-27266, CVE-2021-27267, CVE-2021-27268,
    CVE-2021-27271).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit 3D Plugin Beta 10.1.3.37598 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:foxitsoftware:u3dbrowser_plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:3d");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_u3dbrowser_plugin_win_installed.nbin");
  script_require_keys("installed_sw/Foxit U3DBrowser Plugin");

  exit(0);
}

include('vcf.inc');

app_name = 'Foxit U3DBrowser Plugin';

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

constraints = [
  { 'max_version' : '10.1.1.37576', 'fixed_display' : '10.1.3.37598' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
