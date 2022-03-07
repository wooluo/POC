
include("compat.inc");

if (description)
{
  script_id(51799302);
  script_version("1.17");

  script_name(english:"incaseformat Detection");
  script_summary(english:"Checks incaseformat.");
  script_set_attribute(attribute:"description", value:"Checks incaseformat.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

name = "incaseformat";

# All of the currently know registry paths
regkeys = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\msfsa");

# All of the current known executable names
exes = make_list("\tsay.exe", "\ttry.exe");
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# check HideFileExt
# hklm1 = registry_hive_connect(hive:HKEY_CURRENT_USER, exit_on_fail:TRUE);
# regkeys1 = "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt";
# hid = get_registry_value(handle:hklm1, item:regkeys1);

vuln = 0;
found = 0;
paths = make_list();
foreach key (regkeys)
{
  path = get_registry_value(handle:hklm, item:key);
   
  if (path)
  {
    if (ereg(string:path, pattern:"[cC]:"))
    {
	  foreach file (exes){
		if(file >< path){
			vuln = file;
		}
	  }
      matches = eregmatch(string:path, pattern:"^(.*)\\");
      if (!isnull(matches))
        path = matches[1];
    }

    paths = make_list(paths, path);
    found++;
  }
  else
    continue;
}

if (! found)
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, name);
}


foreach path (list_uniq(paths))
{
    if(vuln){
        file = path + vuln;
        security_hole(port:port,data:file);
    }
}

RegCloseKey(handle:hklm);
close_registry();

