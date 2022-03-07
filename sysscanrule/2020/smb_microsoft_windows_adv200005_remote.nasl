#
# 
#

include('compat.inc');

if (description)
{
  script_id(134421);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/12");

  script_cve_id("CVE-2020-0796");

  script_name(english:"Microsoft Windows SMBv3 Compression RCE (ADV200005)(CVE-2020-0796)(Remote)");
  script_summary(english:"Checks the Windows version and mitigative measures.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is using a vulnerable version of SMB.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in Microsoft Server Message Block
3.1.1 (SMBv3) protocol due to how it handles a maliciously crafted compressed
data packet. An unauthenticated, remote attacker can exploit this to bypass
authentication and execute arbitrary commands.

Note, the plugin checks if SMB 3.1.1 with compression is enabled. It does not
currently verify the vulnerability itself.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?736703d3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has provided additional details and guidance in the ADV200005 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0796");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_dialects_enabled.nasl");
  script_require_keys("SMB/smb_dialect/3.1.1", "Settings/ParanoidReport");

  script_require_ports(139, 445);

  exit(0);
}
include('audit.inc');
include('global_settings.inc');
include('smb_func.inc');
include('misc_func.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = kb_smb_transport();

if (get_kb_item('SMB/smb_dialect/3.1.1/compression'))
{
  report = 'we were able to detect SMB 3.1.1 with compression enabled using a specially crafted packet.\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
