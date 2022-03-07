#TRUSTED 4b65c9e00cf7ee2397e2b5fc46cc271233c16f5bf1a945ba9d9bb70e978bea8f7774ed686245a82be1275cbac75079c6c4b96a5ce9375d1eb7aa4f5728945800230fc8ea9f10c9724ec360122884ca31bb80ef09788aa23add23692fec7f035c3aceb6728f4437a8f190fe16d5e6d4f10b45f95d5ed9b29f0beb9f154bf1ea02a44c7dd32927fa8e52ac115dd283fefddc894b925be044bca4dd071ff11bed6b1172ece94e8aff4cb399ec1f8545f9880b1907a8c2c3cbda7ec110b03d47c0a2662edf5a154d52420265e18f0183ecf63190343ff37a91a140beb842b12a247f0eb115a8365bffa21a60b307d671860af01d80d827fa92692f3490d1ef94515ab7c66affe0f0b9b91a70cce14f0d621969519cf3ce95cfd2ec87e5b4a9b40528618b9cf0941876e019576fb2fd891a2dd9de18baebf4da5c09be9172c1842a0fb6cbdab745b3bcbfea50dedc26e51663cb745bbec4b853fd01a2a7db9c273480aff976f073937ada06c796efc2d2bd841ce161be68c1294d3fffee8c26f21fd5c9d1fa96e67fdfa954d9d97ba3f38cbc99d9148daccbd54dbda1899981d91d423253103d878a22b33859813ed510bd22f6bd386bf3a7fba44b1379fba3463e00c902f7d30f63eb7452f47d0689735bdd30a912b0fc878a5fa6d684441b1919a8b18e3c342bc48cf309f808fe45cfe2de6e3014751bebf50b5a27314e1cd01570
#------------------------------------------------------------------------------
#
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# sh_commands_find.inc
#
# Revision: 1.5
#
# @include misc_func.inc
# @include hostlevel_func.inc
# @include ssh_func.inc
# @include telnet_func.inc

include("spad_log_func.inc");
include("lists.inc");

include("command_builder.inc");

namespace sh_commands_find
{
  automount_running = NULL;

  has_user_filepath_exclusions = NULL;
  has_user_filesystem_exclusions = NULL;
  user_filepath_exclusions = make_list();
  user_filesystem_exclusions = make_list();

  log_name = "sh_commands_find-inc.log";

  # Some OS have limited filesystems available for fstype
  if (get_kb_item("Host/AIX/version"))
  {
    default_filesystem_exclusions = make_list('nfs');
  }
  else if (get_kb_item("Host/HP-UX/version"))
  {
    default_filesystem_exclusions = make_list('nfs', 'cifs');
  }
  else
  {
    default_filesystem_exclusions = make_list('nfs', 'cifs', 'smbfs', 'afs', 'sysfs', 'proc' ,'panfs');
  }

  # Initialize find command using command builder
  find_builder = new("command_builder::command", "find");

  find_builder.set_default_timeout(240);

  find_builder.set_default_stderr_to_dev_null(TRUE);

  find_builder.set_positionals_at_beginning(TRUE);

  find_builder.add_positional_argument(@command_builder::validate_no_injection,
                                       has_many: TRUE,
                                       quote_value: TRUE);

  find_builder.add_named_argument('-maxdepth',
                                  @command_builder::validate_int,
                                  host_check:{"cmd" : "find " + rand_str(length:20) + " -maxdepth 2>&1",
                                  "validate_func" : @find_option_exists});
  find_builder.add_named_argument('-mindepth',
                                  @command_builder::validate_int,
                                  host_check:{"cmd" : "find " + rand_str(length:20) + " -mindepth 2>&1",
                                  "validate_func" : @find_option_exists});
  find_builder.add_named_argument('-path',
                                  @command_builder::validate_no_injection,
                                  quote_value: TRUE,
                                  host_check:{"cmd" : "find " + rand_str(length:20) + " -path 2>&1",
                                  "validate_func" : @find_option_exists});

  find_builder.add_named_argument('-name',
                                  @command_builder::validate_no_injection,
                                  quote_value: TRUE);
  find_builder.add_named_argument('-exec',
                                  @validate_exec);
  find_builder.add_named_argument('-type',
                                  @validate_type);
  find_builder.add_named_argument('-fstype',
                                  @validate_fstype);

  find_builder.add_named_argument('-size',
                                  @validate_size);
  find_builder.add_named_argument('-perm',
                                  @validate_perm);

  find_builder.add_named_argument('-xautofs',
                                  value: FALSE,
                                  host_check:{"cmd" : "find " + rand_str(length:20) + " -xautofs 2>&1",
                                  "validate_func" : @find_option_exists});

  find_builder.add_named_argument('-nogroup', value: FALSE);
  find_builder.add_named_argument('-nouser', value: FALSE);
  find_builder.add_named_argument('-xdev', value: FALSE);
  find_builder.add_named_argument('-follow', value: FALSE);
  find_builder.add_named_argument('-prune', value: FALSE);
  find_builder.add_named_argument('-print', value: FALSE);
  find_builder.add_named_argument('-a', value: FALSE);
  find_builder.add_named_argument('-o', value: FALSE);
  find_builder.add_named_argument('!', value: FALSE);
  find_builder.add_named_argument('\\(', value: FALSE);
  find_builder.add_named_argument('\\)', value: FALSE);


  ##
  # Initialize find requirements
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return list list[0] is return status, list[1] is error message
  #              or result of command
  ##
  function init_find(cache_only)
  {
    var init_kb = "Host/sh_commands_find/cmd_init";

    if (isnull(cache_only)) cache_only = FALSE;

    if (cache_only && !get_kb_item(init_kb))
    {
      return [sh_commands::CMD_FAIL, "sh_commands_find not initialized. Add command_builder_init.nasl as a script dependency."];
    }

    find_builder.init_cmd(cache_only:cache_only);

    var init_result = command_builder::init_cmd_runner(cache_only:cache_only);
    if (init_result[0] == sh_commands::CMD_FAIL)
    {
      return init_result;
    }

    if(isnull(automount_running)) is_automount_running(cache_only:cache_only);
    if(isnull(has_user_filepath_exclusions)) get_user_filepath_exclusions(cache_only:cache_only);
    if(isnull(has_user_filesystem_exclusions)) get_user_filesystem_exclusions(cache_only:cache_only);

    if (!cache_only)
    {
      replace_kb_item(name:init_kb, value:TRUE);
    }

    return [sh_commands::CMD_OK, ""];
  }

  ##
  # Builds filepath exclude arguments
  # @param  exclude_paths List of paths to exclude if -path option is available.
  # @param  as_string If TRUE return output of find_builder.generate_command() instead of unvalidated array. Default FALSE.
  #
  # @return list with first value status and second defaults to unvalidated array of arguments. If as_string TRUE return result of find_builder.generate_command()
  ##
  function filepath_exclude_argument_helper(exclude_paths, as_string)
  {
    local_var exclude_list, i;

    if (isnull(exclude_paths)) exclude_paths = [];

    var init_result = init_find(cache_only:TRUE);

    if (init_result[0] == sh_commands::CMD_FAIL)
    {
      return init_result;
    }

    exclude_list = [];

    # Can only exclude paths if path option exists
    if (find_builder.named_argument_exists_on_host('-path'))
    {
      if (has_user_filepath_exclusions)
      {
        # Merge user supplied and arguement exclusions removing duplicates
        exclude_paths = collib::remove_duplicates(make_list(exclude_paths, user_filepath_exclusions));
      }

      # Example : ! \( -path '/tmp' -prune -o -path '/etc' -prune \)
      for (i = 0; i < max_index(exclude_paths); ++i)
      {
        if (i > 0)
        {
          exclude_list = make_list(exclude_list, '-o');
        }

        exclude_list = make_list(exclude_list, '-path', exclude_paths[i], '-prune');
      }
    }
    else
    {
      spad_log(message:"Host doesn't support -path named argument can't do path exclusions.", name:log_name);
      if (has_user_filepath_exclusions)
      {
        return [sh_commands::CMD_FAIL, 'User supplied filepath exclusions found. Host does not support -path cannot continue.'];
      }
    }

    if (max_index(exclude_list) > 0)
    {
      exclude_list = make_list('!', '\\(', exclude_list, '\\)');
    }

    if (as_string)
    {
      return find_builder.generate_command(args:exclude_list, named_only:TRUE);
    }

    return [sh_commands::CMD_OK, exclude_list];
  }

  ##
  # Builds filesystem type exclude arguments
  # @param  fstype_exclusions  List of fstypes allowed to be excluded by find command
  # @param  as_string If TRUE return output of find_builder.generate_command() instead of unvalidated array. Default FALSE.
  #
  # @return list with first value status and second defaults to unvalidated array of arguments. If as_string TRUE return result of find_builder.generate_command()
  ##
  function filesystem_exclude_argument_helper(fstype_exclusions, as_string)
  {
    local_var arg_list, i;

    if (empty_or_null(fstype_exclusions)) fstype_exclusions = default_filesystem_exclusions;
    if (isnull(as_string)) as_string = FALSE;

    var init_result = init_find(cache_only:TRUE);

    if (init_result[0] == sh_commands::CMD_FAIL)
    {
      return init_result;
    }

    # If there are user filesystem exclusions merge them in removing duplicates
    if (has_user_filesystem_exclusions)
    {
      fstype_exclusions = collib::remove_duplicates(make_list(fstype_exclusions, user_filesystem_exclusions));
    }

    # Example: ! \( -fstype nfs -prune -o -fstype cifs -prune \)
    arg_list = [];

    for(i = 0; i < max_index(fstype_exclusions); ++i)
    {
      if (i > 0)
      {
        arg_list = make_list(arg_list, '-o');
      }

      arg_list = make_list(arg_list, '-fstype', fstype_exclusions[i], '-prune');
    }

    if (max_index(arg_list) > 0)
    {
      arg_list = make_list('!', '\\(', arg_list, '\\)');
    }

    if (as_string)
    {
      return find_builder.generate_command(args:arg_list, named_only:TRUE);
    }

    return [sh_commands::CMD_OK, arg_list];
  }

  ##
  # Check if there are user supplied filepath exclusions
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return NULL
  ##
  function get_user_filepath_exclusions(cache_only)
  {
    local_var data, user_pref, paths, path, exclusions, kb_name, kb_value;

    if (isnull(cache_only)) cache_only = FALSE;

    kb_name = 'Host/sh_commands_find/user_filepath_exclusions';

    kb_value = get_kb_item(kb_name);
    if(!isnull(kb_value))
    {
      if (kb_value)
      {
        has_user_filepath_exclusions = TRUE;
        user_filepath_exclusions = split(kb_value, keep:FALSE);
      }
      else
      {
        has_user_filepath_exclusions = FALSE;
      }

      return;
    }

    if (cache_only)
    {
      has_user_filepath_exclusions = FALSE;
      return;
    }

    spad_log(message:'Checking for user supplied filepath exclusions for find command.', name:log_name);
    has_user_filepath_exclusions = FALSE;
    data = NULL;
    user_pref = 'sh_commands_find[file]:Filepath Exclusions';
    if (get_preference(user_pref))
    {
      data = get_preference_file_content(user_pref);
    }

    if (isnull(data) || strlen(data) < 1)
    {
      spad_log(message:'No user supplied filepath exclusions found.', name:log_name);
      replace_kb_item(name:kb_name, value:FALSE);

      return;
    }
    else
    {
      spad_log(message:'User supplied filepath exclusions :\n' + data, name:log_name);
    }

    exclusions = make_list();
    paths = split(data, keep:FALSE);
    foreach path (paths)
    {
      # Do validation before caching to KB
      if (command_builder::validate_no_injection(path))
      {
        exclusions = make_list(exclusions, path);
      }
      else
      {
        spad_log(message:'Invalid user supplied path: ' + path, name:log_name);
      }
    }

    if (max_index(exclusions) > 0)
    {
      has_user_filepath_exclusions = TRUE;
      user_filepath_exclusions = exclusions;
      kb_value = join(exclusions, sep:'\n');
      replace_kb_item(name:kb_name, value:kb_value);
      spad_log(message:'Validated user supplied filepath exclusions\n' + kb_value, name:log_name);
    }
    else
    {
      replace_kb_item(name:kb_name, value:FALSE);
      spad_log(message:'No valid user supplied filepath exclusions found.', name:log_name);
    }
  }

  ##
  # Check if there are user supplied filesystem exclusions
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return NULL
  ##
  function get_user_filesystem_exclusions(cache_only)
  {
    local_var data, user_pref, filesystems, filesystem, exclusions, kb_name, kb_value;

    if (isnull(cache_only)) cache_only = FALSE;

    kb_name = 'Host/sh_commands_find/user_filesystem_exclusions';

    kb_value = get_kb_item(kb_name);
    if(!isnull(kb_value))
    {
      if (kb_value)
      {
        has_user_filesystem_exclusions = TRUE;
        user_filesystem_exclusions = split(kb_value, keep:FALSE);
      }
      else
      {
        has_user_filesystem_exclusions = FALSE;
      }

      return;
    }

    if (cache_only)
    {
      has_user_filesystem_exclusions = FALSE;
      return;
    }

    spad_log(message:'Checking for user supplied filesystem exclusions for find command.', name:log_name);
    has_user_filesystem_exclusions = FALSE;
    data = NULL;
    user_pref = 'sh_commands_find[file]:Filesystem Exclusions';
    if (get_preference(user_pref))
    {
      data = get_preference_file_content(user_pref);
    }

    if (isnull(data) || strlen(data) < 1)
    {
      spad_log(message:'No user supplied filesystem exclusions found.', name:log_name);
      replace_kb_item(name:kb_name, value:FALSE);

      return;
    }
    else
    {
      spad_log(message:'User supplied filesystem exclusions :\n' + data, name:log_name);
    }

    exclusions = make_list();
    filesystems = split(data, keep:FALSE);
    foreach filesystem (filesystems)
    {
      # Do validation before caching to KB
      if (validate_fstype(filesystem))
      {
        exclusions = make_list(exclusions, filesystem);
      }
      else
      {
        spad_log(message:'Invalid user supplied filesystem: ' + filesystem, name:log_name);
      }
    }

    if (max_index(exclusions) > 0)
    {
      has_user_filesystem_exclusions = TRUE;
      user_filesystem_exclusions = exclusions;
      kb_value = join(exclusions, sep:'\n');
      replace_kb_item(name:kb_name, value:kb_value);
      spad_log(message:'Validated user supplied filesystem exclusions\n' + kb_value, name:log_name);
    }
    else
    {
      replace_kb_item(name:kb_name, value:FALSE);
      spad_log(message:'No valid user supplied filesystem exclusions found.', name:log_name);
    }
  }

  ##
  # Check if automount process is running on the host.
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return NULL
  ##
  function is_automount_running(cache_only)
  {
    var buf, kb_name, cmd;

    if (isnull(cache_only)) cache_only = FALSE;

    kb_name = "Host/sh_commands_find/automount_running";

    # check cache
    automount_running = get_kb_item(kb_name);
    if(!isnull(automount_running))
    {
      return NULL;
    }

    automount_running = FALSE;

    if (cache_only)
    {
      # In the case of the automount service error on the side of caution
      # with no cached result even though we would error out before running
      # find anyway.
      automount_running = TRUE;
    }
    else
    {
      cmd = 'ps -aef';
      spad_log(message:'automount check cmd : "' + cmd + '".', name:log_name);
      buf = info_send_cmd(cmd:cmd);
      spad_log(message:'automount check return : ' + buf, name:log_name);
      if (buf && 'automount' >< buf)
      {
        spad_log(message:'Automount appears to be running on host.', name:log_name);
        automount_running = TRUE;
      }
      else
      {
        spad_log(message:'Automount does not appear to be running on host.', name:log_name);
      }

      # cache finding
      replace_kb_item(name:kb_name, value:automount_running);
    }

    return NULL;
  }

  ##
  # Validate value is valid for find -exec. This only accepts
  # a whitelisted set of commands. Additional commands must be
  # added as needed.
  #
  # @anonparam -exec value
  #
  # @return TRUE if valid. FALSE if invalid.
  ##
  function validate_exec()
  {
      var cmd = _FCT_ANON_ARGS[0];

      if (isnull(cmd)) return FALSE;

      var find_exec_whitelist = ["unzip -v '{}' \;",
                                 "unzip -l '{}' \;",
                                 "ls -l '{}' \;",
                                 "ls -lnd '{}' \;",
                                 "file '{}' \;",
                                 "file --mime '{}' \;"
                                 ];

      if (collib::contains(list:find_exec_whitelist, item:cmd) ||
          # Allow grep with a path containing no bad chars
          cmd =~ '^grep -il "/([A-Za-z0-9_\\-]+/?)+" \'\\{\\}\' \\\\;$')
      {
        return TRUE;
      }

      return FALSE;
  }

  ##
  # Validate value is valid for find -type
  #
  # @anonparam -type value
  #
  # @return TRUE if valid. FALSE if invalid.
  ##
  function validate_type()
  {
    var type = _FCT_ANON_ARGS[0];

    if (isnull(type) || type !~ "^[bcdpflsD]$")
    {
      return FALSE;
    }

    return TRUE;
  }

  ##
  # Validate value is valid for find -size
  #
  # @anonparam -size value
  #
  # @return TRUE if valid. FALSE if invalid.
  ##
  function validate_size()
  {
    var size = _FCT_ANON_ARGS[0];

    if (isnull(size) || size !~ "^\d+[ckMGTP]?$")
    {
      return FALSE;
    }

    return TRUE;
  }

  ##
  # Validate value is valid for find -perm
  #
  # @anonparam -perm value
  #
  # @return TRUE if valid. FALSE if invalid.
  ##
  function validate_perm()
  {
    var perm = _FCT_ANON_ARGS[0];
    if (isnull(perm) || perm !~ "^[-+]?[0-9A-Za-z+=,]+$")
    {
      return FALSE;
    }

    return TRUE;
  }

  ##
  # Validate value is valid for find -fstype
  #
  # @anonparam value
  #
  # @return TRUE if valid FALSE if invalid.
  ##
  function validate_fstype()
  {
    var value = _FCT_ANON_ARGS[0];

    if (isnull(value) || value !~ "^[0-9A-Za-z\.]+$")
    {
      return FALSE;
    }

    return TRUE;
  }

  ##
  # Check find output to determine if the option is supported.
  #
  # @anonparam output of find command
  #
  # @return TRUE if has option. FALSE if the option is missing.
  ##
  function find_option_exists()
  {
    local_var buf;

    buf = _FCT_ANON_ARGS[0];

    if(!empty_or_null(buf) &&
       ('bad option' >< buf ||
       'unknown predicate' >< buf ||
       'illegal option' >< buf ||
       'unknown primary or operator' >< buf ||
       'is not a valid option' >< buf))
    {
      return FALSE;
    }

    return TRUE;
  }
}

namespace sh_commands
{
  ##
  # Find command for unix systems.
  #
  # @anonparam Each anon parameter is a argument to the command.
  # @param  args Optional named argument so an array can be passed instead of through anonparam.
  # @param  fstype_exclusions list of fstype to exclude. Defaults to library list of fstypes. (optional)
  # @param  exclude_paths list of paths to exclude. Are only used if -path is supported. (optional)
  # @param  timeout Override default timeout (optional)
  # @param  run If TRUE command is ran if FALSE command is validated and returned as a string.
  #             Defaults TRUE;
  #
  # @return list list[0] is return status, list[1] is one of the following.
  #               On error list[1] is the error message.
  #               On run is TRUE it is the ouput of the command.
  #               On run is FALSE it is a validated command string.
  #
  # @remark This function looks for user supplied path and fstype exclusions and includes
  #         them as part of the final command.
  ##
  function find(args, fstype_exclusions, exclude_paths, timeout, run)
  {
    var i, final_args, tmp_args, status, err, buf;

    var xautofs_found = FALSE;
    var tenb_fstype_exclusions_found = FALSE;
    var tenb_path_exclusions_found = FALSE;
    var multi_cmd = FALSE;

    if (isnull(run)) run = TRUE;

    if (isnull(args) && !isnull(_FCT_ANON_ARGS))
    {
      args = _FCT_ANON_ARGS;
    }
    else if(isnull(args))
    {
      args = [];
    }

    var init_result = sh_commands_find::init_find(cache_only:TRUE);

    if (init_result[0] == sh_commands::CMD_FAIL)
    {
      return init_result;
    }

    # Only run find without -xautofs if automount is running when running thorough tests
    if (!sh_commands_find::find_builder.named_argument_exists_on_host("-xautofs") &&
        sh_commands_find::automount_running &&
        !thorough_tests)
    {
      status = sh_commands::CMD_FAIL;
      err = "The remote filesystem uses autofs and find doesn't support -xautofs. Enable thorough tests to override.";
      spad_log(message:'sh_commands::find() returned status "' + status + '" and value string "' + err + '".');
      return [status, err];
    }

    final_args = [];
    for (i = 0; i < max_index(args); ++i)
    {
      # If -exec is used then the command must be ran with multi_cmd set so timeout
      # is handled correctly.
      if (args[i] == "-exec")
      {
        multi_cmd = TRUE;
      }

      if (args[i] == "-xautofs")
      {
        xautofs_found = TRUE;
        # automount isn't running so remove -xautofs if it isn't supported.
        if (!sh_commands_find::find_builder.named_argument_exists_on_host("-xautofs"))
        {
          spad_log(message:'sh_commands::find() : -xautofs not supported on host removing from command.');
          continue;
        }

        tmp_args = args[i];
      }
      else if (args[i] == "-tenb_fstype_exclusions")
      {
        tenb_fstype_exclusions_found = TRUE;
        tmp_args = sh_commands_find::filesystem_exclude_argument_helper(fstype_exclusions:fstype_exclusions);
        if (tmp_args[0])
        {
          tmp_args = tmp_args[1];
        }
        else
        {
          return tmp_args;
        }
      }
      else if (args[i] == "-tenb_path_exclusions")
      {
        tenb_path_exclusions_found = TRUE;
        tmp_args = sh_commands_find::filepath_exclude_argument_helper(exclude_paths:exclude_paths);
        if (tmp_args[0])
        {
          tmp_args = tmp_args[1];
        }
        else
        {
          return tmp_args;
        }
      }
      else
      {
        tmp_args = args[i];
      }

      final_args = make_list(final_args, tmp_args);
    }

    # Make -xautofs is a required argument.
    if (!xautofs_found)
    {
      status = sh_commands::CMD_FAIL;
      err = "Find must have -xautofs.";
      spad_log(message:'sh_commands::find() returned status "' + status + '" and value string "' + err + '".');
      return [status, err];
    }

    # Make -tenb_fstype_exclusions is a required argument.
    if (!tenb_fstype_exclusions_found)
    {
      status = sh_commands::CMD_FAIL;
      err = "Find must have -tenb_fstype_exclusions.";
      spad_log(message:'sh_commands::find() returned status "' + status + '" and value string "' + err + '".');
      return [status, err];
    }

    # Make -tenb_path_exclusions a required argument.
    if (!tenb_path_exclusions_found)
    {
      status = sh_commands::CMD_FAIL;
      err = "Find must have -tenb_path_exclusions.";
      spad_log(message:'sh_commands::find() returned status "' + status + '" and value string "' + err + '".');
      return [status, err];
    }

    var cmd = sh_commands_find::find_builder.generate_command(args:final_args);
    if (!run)
    {
      spad_log(message:'sh_commands::find() as string returned status "' + cmd[0] + '" and value string "' + cmd[1] + '".');
      return cmd;
    }
    
    if (cmd[0] != sh_commands::CMD_OK)
    {
      spad_log(message:'sh_commands::find() ran returned status "' + cmd[0] + '" and value string "' + cmd[1] + '".');
      return cmd;
    }
    spad_log(message:'sh_commands::find() ran command string : "' + cmd[1] + '".');
    buf = sh_commands_find::find_builder.run(cmd:cmd[1], timeout:timeout, multi_cmd:multi_cmd);
    spad_log(message:'sh_commands::find() ran returned status "' + buf[0] + '" and value string "' + buf[1] + '".');
    return buf;
  }
}
