# 

include('compat.inc');

if (description)
{
  script_id(148255);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2021-21975", "CVE-2021-21983");
  script_xref(name:"VMSA", value:"2021-0004");

  script_name(english:"VMware vRealize Operations Manager 7.5.x / 8.x Multiple Vulnerabilities (VMSA-2021-0004)");

  script_set_attribute(attribute:"synopsis", value:
"VMware vRealize Operations running on the remote host is affected by a Server Side
Request Forgery and Arbitrary File Write vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) Manager running on the remote web server is 7.5.x prior to
7.5.0.17771878, 8.0.0 prior to 8.0.1.17771851, or 8.1.0 prior to 8.1.1.17772462 or 8.2.0 prior to 8.2.0.17771778 or
8.3.0 prior to 8.3.0.17787340. It is, therefore, affected by a multiple vulnerablities. 

  - A malicious actor with network access to the vRealize Operations Manager API can perform a Server Side
    request Forgery attack to steal administrative credentials. (CVE-2021-21975)

  - An authenticated malicious actor with network access to the vRealize Operations Manager API can write
    files to arbitrary locations on the underlying photon operating system.(CVE-2021-21983)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Operations Manager version
7.5.0.17771878, 8.0.1.17771851, 8.1.1.17772462, 8.2.0.17771778, 8.3.0.17787340 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");
  script_require_keys("installed_sw/vRealize Operations Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'vRealize Operations Manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  {'min_version':'7.5.0', 'fixed_version':'7.5.0.17771878'},
  {'min_version':'8.0.0', 'fixed_version':'8.0.1.17771851'}, # For 8.0.0, 8.0.1
  {'min_version':'8.1.0', 'fixed_version':'8.1.1.17772462'}, # For 8.1.0, 8.1.1
  {'min_version':'8.2.0', 'fixed_version':'8.2.0.17771778'},
  {'min_version':'8.3.0', 'fixed_version':'8.3.0.17787340'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
