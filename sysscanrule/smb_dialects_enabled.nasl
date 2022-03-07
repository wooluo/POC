#
# (C) WebRAY, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106716);
  script_version("1.2");
  script_cvs_date("Date: 2018/07/16 12:23:24");

  script_name(english:"Microsoft Windows SMB2 Dialects Supported (remote check)");
  script_summary(english:"Checks which dialects of SMB2 are enabled on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain information about the dialects of SMB2 available
on the remote host.");
  script_set_attribute(attribute:"description", value:
"GizaNE was able to obtain the set of SMB2 dialects running on the remote
host by sending an authentication request to port 139 or 445.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2018 and is owned by WebRAy, Inc.");

  script_require_ports(139,445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# the port scanner ran and determined the SMB transport port isn't open
if (!get_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port);
}

all_smb_dialects = mklist(
                      SMB_DIALECT_0202,  # SMB 2.0.2: Windows 2008 SMB2 version.
                      SMB_DIALECT_0210,  # SMB 2.1:   Windows 7 SMB2 version.
                      0x222,  # SMB2_22: Early Windows 8 SMB2 version.
                      0x224,  # SMB2_24: Windows 8 beta SMB2 version.
                      SMB_DIALECT_0300,  # SMB 3.0:   Windows 8 SMB3 version. (mostly the same as SMB2_24)
                      SMB_DIALECT_0302,  # SMB 3.0.2: Windows 8.1 SMB3 version.
                      0x310,  # SMB3_10: early Windows 10 technical preview SMB3 version.
                      SMB_DIALECT_0311   # SMB 3.1.1: Windows 10 technical preview SMB3 version (maybe final)
                    );

header =              "_version_  _introduced in windows version_";
all_smb_dialect_names = mklist(
                      "2.0.2      Windows 2008  ",  # SMB 2.0.2: Windows 2008 SMB2 version.
                      "2.1        Windows 7     ",  # SMB 2.1:   Windows 7 SMB2 version.
                      "2.2.2      Windows 8 Beta",  # SMB2_22: Early Windows 8 SMB2 version.
                      "2.2.4      Windows 8 Beta",  # SMB2_24: Windows 8 beta SMB2 version.
                      "3.0        Windows 8     ",  # SMB 3.0:   Windows 8 SMB3 version. (mostly the same as SMB2_24)
                      "3.0.2      Windows 8.1   ",  # SMB 3.0.2: Windows 8.1 SMB3 version.
                      "3.1        Windows 10    ",  # SMB3_10: early Windows 10 technical preview SMB3 version.
                      "3.1.1      Windows 10    "   # SMB 3.1.1: Windows 10 technical preview SMB3 version (maybe final)
                    );

valid = NULL;
invalid = NULL;
foreach idx (keys(all_smb_dialects))
{
  smb_dialect = all_smb_dialects[idx];
  smb_dialect_name = all_smb_dialect_names[idx];
  if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  smb3_available = FALSE;
  if (smb_dialect == 0x310 || smb_dialect == SMB_DIALECT_0311)
  {
    smb3_available = TRUE;
  }
  ret = smb2_negotiate_protocol(smb_dialects: mklist(smb_dialect), smb3_available: smb3_available);
  dialect_chosen = ret[2];
  if (!isnull(ret) && dialect_chosen == smb_dialect)
  {
    valid += '\t'+smb_dialect_name+'\n';
  }
  else
  {
    invalid += '\t'+smb_dialect_name+'\n';
  }
  NetUseDel();
}

report = NULL;
if ( !isnull(valid) )
{
  report += '\nThe remote host supports the following SMB dialects :\n' + '\t' + header + '\n' + valid;
}

if ( !isnull(invalid) )
{
  report += '\nThe remote host does NOT support the following SMB dialects :\n' + '\t' + header + '\n' + invalid;

}
if ( !isnull(report) )
{
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else audit(AUDIT_NOT_DETECT, 'SMB');
