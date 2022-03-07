include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

function get_weblogic_install(exit_if_unknown_ver)
{
	app_name = "Oracle WebLogic Server";
	insts = get_kb_list("installed_sw/Oracle WebLogic Server/*/version");
	if(!empty_or_null(insts))
	{

		install = get_single_install(app_name:app_name, exit_if_unknown_ver:FALSE);
		if(install)
		{
			return install;
		}
	}

	install["Oracle Home"] = "";
	install["path"] = "";

	port = get_service(svc:'t3', default:7001, exit_on_fail:FALSE);
	install["port"] = port;
	version = get_kb_item("t3/" + port + "/version");
	if(!isnull(version))
	{
	  	install["version"] = version;
		return install;
	}

    insts = get_kb_list("www/weblogic/*/version");
	if(empty_or_null(insts) && exit_if_unknown_ver)
	{
		audit(AUDIT_SERVICE_VER_FAIL, app_name, port);
	}

	keys = keys(insts);
	key = keys[0];
	install["version"] = insts[key];

	return install;
}
