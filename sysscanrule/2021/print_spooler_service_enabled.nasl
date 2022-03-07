
##
# 
##


include('compat.inc');

if (description)
{
  script_id(151440);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/07");

  script_name(english:"Microsoft Windows Print Spooler Service Enabled");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Windows Print Spooler service on the remote host is enabled.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Windows Print Spooler service (spoolsv.exe) on the remote host is enabled.");
  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fc5df24");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_services_params.nasl");
  script_require_keys("SMB/svc/Spooler/startuptype");

  exit(0);
}

include('smb_func.inc');

var startup_type = get_kb_item_or_exit('SMB/svc/Spooler/startuptype');

if (startup_type == SERVICE_DISABLED)
  exit(0, 'The Microsoft Windows Print Spooler service on the remote host is disabled.');

var port = kb_smb_transport();

security_note(port:port, extra:'The Microsoft Windows Print Spooler service on the remote host is enabled.');

