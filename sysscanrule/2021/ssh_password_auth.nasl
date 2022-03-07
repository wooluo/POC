#
# 
#

include("compat.inc");

if (description)
{
  script_id(149334);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_name(english:"SSH Password Authentication Accepted");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host accepts password authentication.");
  script_set_attribute(attribute:"description", value:
"The SSH server on the remote host accepts password authentication.");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc4252#section-8");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

var kb_list = get_kb_list("SSH/supportedauth/*");
if (isnull(kb_list))
  audit(AUDIT_NOT_DETECT, "An SSH server supporting authentication");

# we are branching on the port here
var kb_item = branch(keys(kb_list));

var supported_auths = kb_list[kb_item];
port = kb_item - 'SSH/supportedauth/';
port = int(port);
var supported_auth_list = split(supported_auths, sep:',', keep:FALSE);

if (contains_element(var:supported_auth_list, value:'password'))
  security_report_v4(port:port, severity:SECURITY_NOTE);
else
  audit(AUDIT_NOT_DETECT, "An SSH server accepting password authentication", port);

