##
# 
##

include('compat.inc');

if (description)
{
  script_id(146826);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/26");

  script_cve_id("CVE-2021-21972", "CVE-2021-21973");
  script_xref(name:"IAVA", value:"2021-A-0109");

  script_name(english:"VMware vCenter Server 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2021-0002)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5 U3n, 6.7 prior to 6.7 U3l or 7.0
prior to 7.0 U1c. It is, therefore, affected by multiple vulnerabilities, as follows:

  - The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious
    actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the
    underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7
    before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).
    (CVE-2021-21972)

  - The vSphere Client (HTML5) contains an SSRF (Server Side Request Forgery) vulnerability due to improper validation
    of URLs in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue by
    sending a POST request to vCenter Server plugin leading to information disclosure. This affects: VMware vCenter
    Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2
    and 3.x before 3.10.1.2). (CVE-2021-21973)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number. Nessus has also not tested for the presence of a workaround.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0002.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5 U3n, 6.7 U3l, 7.0 U1c or later or apply the workaround mentioned in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21973");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

fixes = make_array(
  '6.5', '17590285', # 6.5 U3n
  '6.7', '17138064', # 6.7 U3l
  '7.0', '17327517'  # 7.0 U1c
);

port = get_kb_item_or_exit('Host/VMware/vCenter');
version = get_kb_item_or_exit('Host/VMware/version');
release = get_kb_item_or_exit('Host/VMware/release');

# Extract and verify the build number
build = ereg_replace(pattern:"^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$", string:release, replace:"\1");
if (build !~ "^[0-9]+$") audit(AUDIT_UNKNOWN_BUILD, 'VMware vCenter 6.5 / 6.7 / 7.0');

match = pregmatch(pattern:"^VMware vCenter ([0-9]+\.[0-9]+).*$", string:version);
if (isnull(match)) audit(AUDIT_OS_NOT, 'VMware vCenter 6.5 / 6.7 / 7.0');

ver = match[1];
if (ver !~ "^(7\.0|6\.(5|7))$") audit(AUDIT_OS_NOT, 'VMware vCenter 6.5 / 6.7 / 7.0');

fixed_build = int(fixes[ver]);
if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

release = release - 'VMware vCenter Server ';
if (build >= fixed_build)
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = '\n  VMware vCenter version    : ' + ver +
         '\n  Installed build           : ' + build +
         '\n  Fixed build               : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
