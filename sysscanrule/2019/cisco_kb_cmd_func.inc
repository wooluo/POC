#TRUSTED 22ad232b6b8844c952e1402cfb9fa070f9640514133eb35a996666ffae5006a4b7723cd20354a3ea33d7bab4e72d5e48c35b0446ed49e54933ef75acdc5a8337ae0b4e79250d1bf0569cd51e511b2cde9bec32293f3a02fc6a54099fdcd83375a774aaeca6ba7ac1673bd0eb54ec7b8b543a5a3198f5be5a8f0bffa916c76b6dcfd1ba48e79a277c61fef6c348a775f0d0ad272a093f33df63501fb31135d0126263fe8b641c1afcd955e4677c3a831e1645fe1605988935eb5eedacc09a663a4f9565aa2ca96ed4b073f021551d4539f56e9992f10a954c7477cd69490362889f948aa30677b3a8a84beb742ed0f402ea26a8c46228ff9a3b618fc6f4c76dcbfd018c0fcd1064c6b12793b7088c5dc5c6ea5843d930e0a0ec67db5e1da6dde4a9f24507494c682ed6a230ac41e68a2d988c0db883edc2d30368756c2be1c73834fba9e5fd2c56d130ac157ffbeafeaaa3e97dc372b658217f24fca6180579e975a883540466d0be5f503ad54d11aa7b9f846111c4382cda8e44d6bc718c07b7e441e24af30ae9e5abafa6b4705a5f6ad47e0c090f4238eedcf262a6d18021a16c5d40b389ec6caeefc965f1158ca36f317a9ad232238cea37107eed9b96ce328428455216e144e78a611952cd71e7f5dc51c6fbd9f845ffda86b9d65dd54c69d4c2f337f2b1a04cf6f86c901658d2f9dd7d4509bec69d9c6c410b7e14f69c0e
#
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.14
###

include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("misc_func_nlib.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

##
# Attempt to determine if the enable password is required
#
# @return 1 is yes, 0 if no
##
function cisco_needs_enable()
{
  local_var buf, prompt;

  buf = _FCT_ANON_ARGS[0];

  # if local checks are not enabled, then there is no need for enable
  if (!get_kb_item("Host/local_checks_enabled")) return 0;

  # if buf is empty/blank then assume enable is NOT needed
  if (!buf) return 0;

  # check for various error messages used to identify when level 15
  # privs are needed
  # 
  # error message for IOS XR
  if ("% This command is not authorized" >< buf) return 1;
  # error message for IOS, ASA
  if ("ERROR: Command authorization failed" >< buf) return 1;
  # error message for IOS XE
  #if ((get_kb_item("Host/Cisco/IOS-XE") && ("" >< buf)) return 1;
  # error message for NX-OS
  #if ((get_kb_item("Host/Cisco/NX-OS") && ("" >< buf)) return 1;
  # error message for IPS
  #if ((get_kb_item("Host/Cisco/IPS") && ("" >< buf)) return 1;
  # error message for WLC
  #if ((get_kb_item("Host/Cisco/WLC") && ("" >< buf)) return 1;
  # error message for NAM
  #if ((get_kb_item("Host/Cisco/NAM") && ("" >< buf)) return 1;
  # error message for CNU-OS
  #if ((get_kb_item("Host/Cisco/CNU-OS") && ("" >< buf)) return 1;
  # error message for CUC
  #if ((get_kb_item("Host/Cisco/CUC") && ("" >< buf)) return 1;

  # Check the command prompt to see if 'enable' was successful.
  prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
  if (
    !isnull(prompt) && 
    preg(pattern:"#[ \t]*$", string:prompt)
  ) return 0;

  if ("% Invalid input detected at " >< buf ) return 1;

  return 0;
}

##
# Determines if the buf returned is an error or a valid result
#
# @return 1 is good, 0 if bad/error
##
function check_cisco_result()
{
  local_var buf;
  buf = _FCT_ANON_ARGS[0];

  if (!buf) return 0;
  if (cisco_needs_enable(buf)) return 0;
  if ("% This command is not authorized" >< buf) return 0;
  if ("% Invalid input" >< buf) return 0;
  if ("ERROR: " >< buf) return 0;

  return 1;
}

##
# Handles emulating derivatives of the 'show run' command.
#     Pulls show running-config/show running-config all output from the
#     stored KB item, handles scoping the command (show running-config $scope)
#     and output modifiers (show running-config | include $regex)
#
# @param cmd The command to emulate
#
# @return emulated command results
#             output of command
#             empty string if there is no output
#             NULL if there was an error, or show run was not initially collected
##
function cisco_running_config_cmd(cmd)
{
  var running_config, running_config_all, matches, ret, config_category, include_str;

  var cmd_logger = new("sshlib::cmd_logger");

  running_config = get_kb_item('Secret/Host/Cisco/Config/show_running-config');
  running_config_all = get_kb_item('Secret/Host/Cisco/Config/show_running-config_all');

  if(isnull(cmd) || (empty_or_null(running_config) && empty_or_null(running_config_all)))
    return NULL;

  var dbg_name = SCRIPT_NAME+'.'+FUNCTION_NAME+'.log';

  /*
     matches[0] = base show run/show running-config command
     matches[1] = all
     matches[2] = config context, after the base command but before | - this is treated
                    as a regex with ^ prepended. Checks for top-level context items, then
                    all following lines that are indented are included in the context
     matches[3] = any output modifiers after | - this is treated as a regex and passed
                    directry to preg
   */
  matches = pregmatch(pattern:"^ *show run(?:ning(?:[ -]config)?)? *(all)? *([^|]+)? *(?:\| *include +(.*))?$", string:cmd);
  if(isnull(matches))
  {
    return NULL;
  }
  else if(len(matches) == 1)
  {
    cmd_logger.add(cmd:cmd, response:running_config, emulated:TRUE);
    return running_config;
  }
  else if(!isnull(matches[0]) && !isnull(matches[1]) && isnull(matches[2]) && isnull(matches[3]))
  {
    cmd_logger.add(cmd:cmd, response:running_config_all, emulated:TRUE);
    return running_config_all;
  }


  if(matches[1])
    running_config = running_config_all;

  if(empty_or_null(running_config))
    return NULL;

  config_category = matches[2];
  include_str = matches[3];

  if(isnull(running_config))
    return NULL;

  if(!isnull(config_category))
  {
    var line, search, found;
    search = '^' + config_category;
    found = FALSE;
    ret = '';
    foreach line (split(running_config, sep:'\n', keep:TRUE))
    {
      if(!found && preg(pattern:search, string:line, icase:TRUE))
      {
        found = TRUE;
        ret += line;
        continue;
      }
      else if(found && leading_spaces(str:line) > 0)
      {
        ret += line;
        continue;
      }
      # Back at the top level, but this line may be for the same 
      # Setting. Reset found and check again.
      found = FALSE;
      if(preg(pattern:search, string:line, icase:TRUE))
      {
        found = TRUE;
        ret += line;
      }
    }
    if(!isnull(include_str))
    {
      ret = pgrep(pattern:include_str, string:ret, icase:TRUE);
    }
  }
  else if(!isnull(include_str))
    ret = pgrep(pattern:include_str, string:running_config, icase:TRUE);

  cmd_logger.add(cmd:cmd, response:ret, emulated:TRUE);

  return ret;
}


##
# Returns the number of leading spaces in a string
#
# @param str string to test
#
# @return the number of leading spaces
##
function leading_spaces(str)
{
  var ret = 0;

  while(ret < strlen(str) && str[ret] == ' ') ret++;

  return ret;
}

##
# Checks to see if the requested kb_item exists.
#         If so, simply return the kb_item.
#         If not, then collect the data and set the kb_item.
#
# @anonparam kb_item The kb_item to check
#
# @anonparam cmd The cmd to gather the kb_item info
#
# @anonparam flag The flag to indicate whether or not to exit on unknown error
#                 1 = exit, 0 = continue as normal
#
# @return the value stored in the kb_item or gathered via
#         the cmd, or
#         NULL if there were any errors
##
function cisco_command_kb_item()
{
  local_var kb_item, cmd;
  local_var buf;
  local_var flag;

  # get parameters
  kb_item = "Secret/"+_FCT_ANON_ARGS[0];
  cmd = _FCT_ANON_ARGS[1];
  flag = 0;
  if ( _FCT_ANON_ARGS[2] ) flag = _FCT_ANON_ARGS[2];

  # if no kb_item is specified, return
  if (!kb_item)
    return NULL;

  buf = cisco_running_config_cmd(cmd:cmd);
  if (!isnull(buf))
    return buf;


  # immediately return the command output if we already know it
  buf = get_kb_item(kb_item);
  if (buf)
  {
    return buf;
  }

  # if no command is specified, return
  if (!cmd)
    return NULL;

  # setup ssh tunnel
  sock_g = ssh_open_connection();
  if (! sock_g) exit(1, "ssh_open_connection() failed.");

  # issue command
  buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
  ssh_close_connection();

  if (buf) 
  {
    # set kb item for future use
    set_kb_item(name:kb_item , value:buf );
  }
  if (buf && flag && !cisco_needs_enable(buf))
    exit(1, 'ERROR executing ['+cmd+'] = '+substr(buf,0,160));
  return buf;
}

##
# Determines if a Cisco device is a switch
#
# @return TRUE if it is known to be a switch OR paranoid > 2
##
function cisco_is_switch()
{
  if(report_paranoia > 2)  return TRUE;
  return get_kb_item('Host/Cisco/device_type') == 'switch';
}

##
# Determines if a Cisco device is a router
#
# @return TRUE if it is known to be a router OR paranoid > 2
##
function cisco_is_router()
{
  if(report_paranoia > 2)  return TRUE;
  return get_kb_item('Host/Cisco/device_type') == 'router';
}

##
# Examines sections of the Cisco running-config for the specified regular
# expression by using '!' as the default delimiter.
#
# @param string      config        'show running-config' or similar output 
# @param string      section_regex section(s) to look for via a PCRE   
# @param list|string config_regex  list of configs or single config to look for via PCREs
# @param string      delimiter     OPTIONAL end boundary for the section (default: '!')
#
# @return TRUE  if all config_regex(es) are found in the section(s) found by
#               using section_regex
#         FALSE otherwise
##
function cisco_check_sections(config, section_regex, config_regex, delimiter)
{
  local_var matches, match, found, config_regexes;
  local_var str, idx_end;

  if (empty_or_null(config))
  {
    err_print("cisco_check_sections: 'config' must be specified.");
    exit(1);
  }

  if (empty_or_null(section_regex))
  {
    err_print("cisco_check_sections: 'section_regex' must be specified.");
    exit(1);
  }

  if (empty_or_null(config_regex))
  {
    err_print("cisco_check_sections: 'config_regex' must be specified.");
    exit(1);
  }

  # Make a list always
  config_regexes = config_regex;
  if (typeof(config_regexes) != 'array')
    config_regexes = make_list(config_regexes);


  if (isnull(delimiter)) delimiter = "!";

  matches = egrep(pattern:section_regex, string:config);
  if (!empty_or_null(matches))
  {
    matches = split(matches, keep:FALSE);
    foreach match (matches)
    {
      found = 0;
      str = strstr(config, match);
      idx_end = stridx(str, delimiter);
      str = substr(str, 0, idx_end);

      foreach config_regex (config_regexes)
      {
        if (preg(string:str, pattern:config_regex, multiline:TRUE))
          found++;
      }

      if (found == len(config_regexes))
        return TRUE;
    }
  }
  return FALSE;
}
