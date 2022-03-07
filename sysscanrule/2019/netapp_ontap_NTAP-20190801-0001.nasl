#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(127136);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 15:23:38");

  script_cve_id("CVE-2019-5493", "CVE-2019-5501", "CVE-2019-5502");
  script_xref(name:"IAVB", value:"2019-B-0069");

  script_name(english:"NetApp Data ONTAP (7-Mode) < 8.2.5P3 Multiple Vulnerabilities (ntap-20190801-0001)(ntap-20190801-0002)(ntap-20190802-0002)");
  script_summary(english:"Checks the version of ONTAP.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of NetApp Data ONTAP running on the remote host is prior to 8.2.5P3. It is, therefore, affected
by multiple vulnerabilities:
  - An information disclosure vulnerability exists in NetApp Data ONTAP. An unauthenticated, remote attacker
    can exploit this to disclose potentially sensitive information (CVE-2019-5493, CVE-2019-5501).

  - A weak cryptography vulnerability exists in the SMB component of NetApp Data ONTAP. An unauthenticated, remote
    attacker can exploit this to disclose potentially sensitive information or add / modify of the application's data
    (CVE-2019-5502).

Note that GizaNE has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.netapp.com/advisory/ntap-20190801-0001/
  script_set_attribute(attribute:"see_also", value:"");
  # https://security.netapp.com/advisory/ntap-20190801-0002/
  script_set_attribute(attribute:"see_also", value:"");
  # https://security.netapp.com/advisory/ntap-20190802-0002/
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to NetApp Data ONTAP version 8.2.5P3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value: "CVE-2019-5493");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:netapp:data_ontap");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("netapp_ontap_detect.nbin");
  script_require_keys("Host/NetApp/ONTAP/display_version", "Host/NetApp/ONTAP/version", "Host/NetApp/ONTAP/mode");

  exit(0);
}

include('vcf.inc');

app_name = 'NetApp ONTAP';
mode = get_kb_item('Host/NetApp/ONTAP/mode');

if (!mode) audit(AUDIT_OS_CONF_NOT_VULN, app_name);

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/NetApp/ONTAP/display_version');

constraints = [
  {'fixed_version':'8.2.5P3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
