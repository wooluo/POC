#TRUSTED 26be814af99dc7c5942938e169016509f1b8819e34deb6b14e26ceccfdcd2f0a84025c6ea9a1d724a7808d79bfc3d3374d1c366a01cb78b184395d6627324e253bfdae4a0bf9e6cd6ae04cfc2ab1ade9fb55004a32b76dadcbe321398647190daf4e401e7147b85ce5e856cd61d5587d410a97e0cf23584e44124ab1486d6a442da8c64b1a6d31079bc650dceba8f6df9c68c5f8c473ed1efba31baf99d26df5ac3fa1c91ef9fc21cd93e2e3037f673c6c3ee4ee5a2106f4fc49868a9e5977eed44ee96a3cef7357502fcef91ba74f22d2b46440edad1e51661f6df419b634866d51bb14e2a78bf1c55ae05d63c102b4306842299e54491026be6af8654403c57496889b761d74b32006294a0ab05f27e5efe5a186e75a5b8769c0c60432b428697b6d9a1b8e543a18374ad9634caf46e2d12752c6c51e0356bd9f8fc91bc5cef67ae68e841013acdc7c8272fc2e4fb8bacf5076f4a27fae809b8f2ccb593ad7e8dbbc6985ee734f54564571f7d88c3cc4e719145765dcf86f9b156f8d3d6f0666b6cc62052ac803843c33f23c5fbfb1138aa5e7faeb4572b6149a03e0e06ac46e386047dbc74f6f3491bac69735a38cf99f08e993d50a1b2e8ccd44c57fbc01938aeba344b78aa08b8ec29217640765fb6a7975733964942d736c58f0f5c4e905997c4e6bbfef210a175566a780344b5c9b2ad23ce44be38137a16f1b5ce0fb
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.4
###

include("junos.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func_nlib.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

##
# Determines if the output returned is an error or a valid result
#
# @return TRUE  if the output appears valid
#         FALSE if the output appears to be an error or invalid
##
function junos_check_result()
{
  local_var buf;
  buf = _FCT_ANON_ARGS[0];

  if (isnull(buf)) return FALSE;
  if ("syntax error, expecting <command>" >< buf) return FALSE;
  if ("unknown command" >< buf) return FALSE;

  return TRUE;
}

##
# Checks if the statement is deactivated or disabled
#
# @param string  buf       return buffer from Junos command
# @param string  pattern   to check for configuration
# @param boolean multiline OPTIONAL pass to preg (default: TRUE) 
#
# @return TRUE  if the configuration is enabled
#         FALSE if the configuration is not found or disabled
##
function junos_check_config(buf, pattern, multiline)
{
  local_var statements, lines, line;
  local_var deactivate_pat, disable_pat, matches;

  if (isnull(pattern))
  {
    err_print("junos_check_config: 'pattern' must be specified");
    exit(1);
  }

  if (isnull(multiline)) multiline = TRUE;

  statements = pgrep(string:buf, pattern:pattern);
  if (statements == '')
    return FALSE;

  lines = split(statements, sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    # Look for deactivated statement in the config
    deactivate_pat = str_replace(string:line, find:"set", replace:"deactivate", count:1);
    if (preg(string:buf, pattern:deactivate_pat, multiline:TRUE)) continue;

    # Look for disable statement in the matching statements
    if (line =~ " disable$") continue;

    disable_pat = "^" + line +  " disable$";
    if (preg(string:statements, pattern:disable_pat, multiline:TRUE)) continue;

    return TRUE; # Statement was found not deactivated or disabled
  }

  return FALSE;
}

##
# Checks if the specified KB item exists.
#   If it does, simply return the output stored in the KB item.
#   If it doesn't, execute the specified command and store the output in the KB item.
#
# @param string  cmd the command to gather the KB item info
#
# @param string  kb      OPTIONAL KB item to check
# @param boolean no_more OPTIONAL do not paginate command output (default: TRUE)
#
# @remark 'kb' should only be specified for commands with special characters or
#         where the KB deviates from the command in some way
#
# @return output from executed command
#         FALSE  if local checks is not enabled
#         NULL   if there were any errors
##
function junos_command_kb_item(cmd, kb, no_more)
{
  local_var shell, buf;

  if (!get_kb_item("Host/local_checks_enabled")) return FALSE;

  if (isnull(cmd))
  {
    err_print("junos_command_kb_item: 'cmd' must be specified");
    exit(1);
  }

  shell = get_kb_item("Host/Juniper/JUNOS/shell");

  if (isnull(no_more)) no_more = TRUE;

  # Replace whitespaces with underscores and remove forward slashes for KB
  if (isnull(kb))
  {
    kb = str_replace(string:cmd, find:" ", replace:"_");
    kb = str_replace(string:kb, find:"/", replace:"");
    kb = "Host/Juniper/JUNOS/Config/" + kb;
  }
  # Add the 'no-more' display filter to not use pagination (enabled by default) 
  if (no_more && "| no-more" >!< cmd)
    cmd += " | no-more";

  # Return the command output if we already know it
  buf = get_kb_item("Secret/"+kb);
  if("GizaNE failed to run command" >< buf) return NULL;
  if (!isnull(buf)) return buf;

  # Issue specified command
  if (shell)
  {
    if (islocalhost())
    {
      if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
      info_t = INFO_LOCAL;
    }
    else
    {
      info_t = INFO_SSH;
      if (!ssh_open_connection()) exit(1, "Failed to open an SSH connection.");
    }

    if ("|" >< cmd) cmd = str_replace(string:cmd, find:"|", replace:"\|");
    buf = info_send_cmd(cmd:'cli ' + cmd);
    if (info_t == INFO_SSH) ssh_close_connection();
  }
  else
  {
    if (!ssh_open_connection()) exit(1, "Failed to open an SSH connection.");
    buf = ssh_cmd(cmd:cmd + '\r\n', nosudo:TRUE, nosh:TRUE);
    ssh_close_connection();
  }

  if (junos_check_result(buf))
  {
    set_kb_item(name:"Secret/"+kb, value:buf); # set KB item for future use
    return buf;
  }
  else return NULL;
}

##
# Returns a message that the configuration was not checked
#
# @anonparam TRUE  if configuration was not checked
#            FALSE if configuration was checked
# @param     boolean display generic caveat message (no reason in message)
# @return NULL if local checks are enabled and FALSE is passed
#         caveat string if local checks are not enabled or TRUE is passed
##
function junos_caveat(generic)
{
  # Configuration was checked
  if (get_kb_item("Host/local_checks_enabled") && !_FCT_ANON_ARGS[0]) return NULL;

  # Generic message
  if (!isnull(generic) && generic)
    return
      '\nNote that GizaNE has not tested for this issue or the host ' +
      '\nconfiguration instead it has instead relied only on the ' +
      '\napplication\'s self-reported version number.\n';

  # Configuration was not checked because...
  #  local checks are not enabled
  if (!get_kb_item("Host/local_checks_enabled"))
    return
      '\nNote that GizaNE has not tested for this issue or the host ' +
      '\nconfiguration because local checks are not enabled. Instead, ' +
      '\nGizaNE has relied only on the application\'s self-reported ' +
      '\nversion number.\n';
  #  an error occurred
  else
    return
      '\nNote that GizaNE has not tested for this issue or the host ' +
      '\nconfiguration because an error occurred while attempting to test. ' +
      '\nInstead, GizaNE has relied only on the application\'s self-reported ' +
      '\nversion number.\n';
}

##
# Reports and, if relevant, sets PCI KB(s) and include caveat message in report
#
# @param ver      string  installed version
# @param fix      string  fixed version
# @param override boolean display caveat message
# @param severity integer report severity SECURITY_(NOTE, WARNING, HOLE)
# @param model    string  OPTIONAL detected model
# @param xss      boolean OPTIONAL set XSS KB item
# @param xsrf     boolean OPTIONAL set XSRF KB item
# @param sqli     boolean OPTIONAL set SQLi KB item
#
# @return This function has no return values
##
function junos_report(ver, fix, override, severity, model, xss, xsrf, sqli)
{
  local_var port, extra;

  port = 0;  
  extra = NULL;

  if (xss)  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (xsrf) set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (sqli) set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
    extra = get_report(ver:ver, fix:fix, model:model) + junos_caveat(override);
  else
    extra = junos_caveat(override);

  security_report_v4(port:port, extra:extra, severity:severity);
}
