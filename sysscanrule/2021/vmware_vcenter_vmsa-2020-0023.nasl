include('compat.inc');

if (description)
{
  script_id(150982);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/25");

  script_cve_id("CVE-2020-3994");
  script_xref(name:"VMSA", value:"2020-0023");
  script_xref(name:"IAVA", value:"2020-A-0468");

  script_name(english:"VMware vCenter Server 6.5 / 6.7 Session Hijack (VMSA-2020-0023)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host is affected by a session hijack vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is 6.5 prior to 6.5u3k or 6.7 prior to 6.7u3. It is,
therefore, affected by a session hijack vulnerability in the vCenter Server Appliance. Management Interface update
function due to a lack of certificate validation. A malicious actor with network positioning between vCenter Server and
an update repository may be able to perform a session hijack when the vCenter Server Appliance Management Interface is
used to download vCenter updates.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0023.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.5u3k, 6.7u3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3994");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

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

var fixes = make_array(
  '6.5', '16613358',
  '6.7', '14367737'
);

var port = get_kb_item_or_exit('Host/VMware/vCenter');
var version = get_kb_item_or_exit('Host/VMware/version');
var release = get_kb_item_or_exit('Host/VMware/release');

# Extract and verify the build number
var build = ereg_replace(pattern:"^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$", string:release, replace:"\1");
if (build !~ "^[0-9]+$") audit(AUDIT_UNKNOWN_BUILD, 'VMware vCenter 6.5 / 6.7');

var match = pregmatch(pattern:"^VMware vCenter ([0-9]+\.[0-9]+).*$", string:version);
if (isnull(match)) audit(AUDIT_OS_NOT, 'VMware vCenter 6.5 / 6.7');

var ver = match[1];
if (ver !~ "^6\.(5|7)$") audit(AUDIT_OS_NOT, 'VMware vCenter 6.5 / 6.7');

var fixed_build = int(fixes[ver]);
if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

release = release - 'VMware vCenter Server ';
if (build >= fixed_build) 
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

var report = '\n  VMware vCenter version    : ' + ver +
         '\n  Installed build           : ' + build +
         '\n  Fixed build               : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);


