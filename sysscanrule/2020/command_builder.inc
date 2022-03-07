#TRUSTED 9bcd284ad4de46b599068223d84f9b3ecce808cd9e4c7be4115415eb470fa7926c7f4f710f2dd3dff79a91b2e37c6df48f47e32a7e0e298f3f796cb33584551defa58776798ba161cdc3f327cd449e5644e8318d93c9d9cd0a1d42dd0f2d0606f1ef269419bd23989c3565ce84b38a31d7752c529ec5879238657be13fa752736f65d90358049f01d679c6c4b9dffadc1f2d6fc6783d2b810000cff18c29d08545d4d8707b7638bfc4e6b2c1b9fd08094692eea4792d095ee9009a91853bd22b3c83416e26bc1d4fb341f1e49833f860b9f43e8f86e07d1ad9c647ba253d5d2e3a4ebce2088168e170b8791901d9885edf00ba6845e2926ad213af3b49f06488629428ebee6231e2d6cddb659b9ec79d0ee98f780dbb4b84d58e343179f8199e4a7bf73cf7d6c7566354d54895c8975eebc260af25e3b16f30ae70d82985aa2af93527b7c256b4d121b30cd747b5dc5ee50309e8cb88dbe0960a397c7477ac095f1e4e4eab4a13c5d28261e5f5f76cb34730c3377c92bd4ec319937c95e093937dc0e54ddc0a28b08d29eef139872c092eec5aa75b8ee11ff17ff8fe52bfc902b48fcac8d12ce1084424ba10db9e47461b3a0a77c11ac3e13ea6e5d49b189b78d88458bd93f2d43e306c17914d26527d65c211eb0c6abeddda25064e2dd08039958902a695329ce0dc90594182a259b0215dee3cb623a2b2121dd7ea9f15824c
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
# command_builder.inc
#
# Revision: 1.5

include("spad_log_func.inc");

namespace command_builder
{
  var timeout_exists = NULL;
  var perl_exists = NULL;

  object command
  {
    var cmd_name = "";
    # A list of arrays representing positonal arguments
    var positional = [];
    # An array of arrays representing named arguments
    var named = {};
    var cmd_initialized = FALSE;
    var default_timeout = NULL;
    var default_stderr_to_dev_null = FALSE;
    var positionals_have_has_many = FALSE;
    var positionals_beginning = FALSE;
    var positionals_end = FALSE;
    var cmd_exists = FALSE;
    var cmd_exists_check = {};
    var log_name = "";

    ##
    # command initializer
    #
    # @anonparam command
    #
    # @return NULL
    ##
    function command()
    {
      cmd_name = _FCT_ANON_ARGS[0];
      # Default command exists host check
      # If the command doesn't exit will need a custom check
      cmd_exists_check["cmd"] = 'type ' + cmd_name + ' 2>&1';
      cmd_exists_check["validate_func"] = @validate_command_exists;

      log_name = 'command_builder-inc-' + cmd_name + '.log';
    }

    ##
    # Checks if command exists on host. Uses default command check
    # unless otherwise specfied through set_command_exists_host_check().
    #
    # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
    #
    # @return NULL
    ##
    function host_check_command_exists(cache_only)
    {
      if (isnull(cache_only)) cache_only = FALSE;

      var kb_name = "Host/command_builder/" + cmd_name;

      # check cache
      cmd_exists = get_kb_item(kb_name);

      if(isnull(cmd_exists) && !cache_only)
      {
        spad_log(message:'Command exists check ran : "' + cmd_exists_check["cmd"] + '".', name:log_name);
        var buf = info_send_cmd(cmd:cmd_exists_check["cmd"]);
        spad_log(message:'Command exists check returned : "' + buf + '".', name:log_name);
        cmd_exists = cmd_exists_check["validate_func"](tolower(buf));

        # cache finding
        replace_kb_item(name:kb_name, value:cmd_exists);
      }
    }

    ##
    # Checks if named arguments with host_check values are available on host.
    #
    # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
    #
    # @return NULL
    ##
    function host_check_named_arguments(cache_only)
    {
      var arg, buf, option_exists, kb_name;

      if (isnull(cache_only)) cache_only = FALSE;

      foreach arg (keys(named))
      {
        if (isnull(named[arg]["host_check"]["cmd"])) continue;

        kb_name = "Host/command_builder/" + cmd_name + "/" + arg;

        # check cache
        option_exists = get_kb_item(kb_name);
        if(!isnull(option_exists))
        {
          named[arg]["host_check"]["exists"] = option_exists;
          continue;
        }
        else if(!cache_only)
        {
          spad_log(message:'Command named argument "' + arg + '" check ran "' + named[arg]["host_check"]["cmd"] + '".', name:log_name);
          buf = info_send_cmd(cmd:named[arg]["host_check"]["cmd"]);
          spad_log(message:'Command named argument "' + arg + '" check returned "' + buf + '".', name:log_name);
          buf = tolower(buf);

          option_exists = named[arg]["host_check"]["validate_func"](buf);

          named[arg]["host_check"]["exists"] = option_exists;

          # cache finding
          replace_kb_item(name:kb_name, value:option_exists);
        }
      }
    }

    ##
    # Generate command string for positional argument.
    #
    # @anonparam Index of positional.
    # @anonparam Value to validate.
    # @param position Can be used instead of index anonparam.
    # @param value can be used instead of value anonparam.
    #
    # @return list list[0] status and list[1] positional command string
    #              or error message on fail.
    ##
    function generate_positional_cmd_string(position, value)
    {
      if (isnull(position)) position = _FCT_ANON_ARGS[0];
      if (isnull(value)) value = _FCT_ANON_ARGS[1];

      var cmd = "";

      if (positional_argument_validate_value(position, value))
      {
        cmd += " ";
        if (positional_argument_value_is_quoted(position))
        {
          cmd += "'" + value + "'";
        }
        else
        {
          cmd += value;
        }
      }
      else
      {
        return [sh_commands::CMD_FAIL, 'Positional argument "' + value + '" failed validation for positional ' + position + '.'];
      }

      return [sh_commands::CMD_OK, cmd];
    }

    ##
    # Perform command checks against host.
    #
    # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
    #
    # @return NULL
    ##
    public function init_cmd(cache_only)
    {
      if (isnull(cache_only)) cache_only = FALSE;

      if (!cmd_initialized)
      {
        host_check_command_exists(cache_only:cache_only);
        host_check_named_arguments(cache_only:cache_only);
        cmd_initialized = TRUE;
      }
    }

    ##
    # Check command is available on host.
    #
    # @return TRUE if it is and FALSE if not.
    ##
    public function command_exists_on_host()
    {
      init_cmd(cache_only:TRUE);
      return cmd_exists;
    }

    ##
    # Check if named argument is defined for command.
    #
    # @anonparam Name of argument.
    # @param name Can be used instead of name anonparam.
    #
    # @return TRUE if it is and FALSE if not.
    ##
    public function named_argument_is_available(name)
    {
      if (isnull(name)) name = _FCT_ANON_ARGS[0];

      if (isnull(named[name]))
      {
        return FALSE;
      }

      return TRUE;
    }

    ##
    # Check if named argument is available on host.
    #
    # @anonparam Name of argument.
    # @param name Can be used instead of name anonparam.
    #
    # @return TRUE if it is and FALSE if not.
    ##
    public function named_argument_exists_on_host(name)
    {
      if (isnull(name)) name = _FCT_ANON_ARGS[0];

      init_cmd(cache_only:TRUE);

      if (named_argument_is_available(name) && !isnull(named[name]["host_check"]["exists"]))
      {
        return named[name]["host_check"]["exists"];
      }

      # If there is no host check always exists
      return TRUE;
    }

    ##
    # Check if named argument has a value.
    #
    # @anonparam Name of argument.
    # @param name Can be used instead of name anonparam.
    #
    # @return TRUE if does and FALSE if not.
    ##
    public function named_argument_has_value(name)
    {
      if (isnull(name)) name = _FCT_ANON_ARGS[0];

      if (!named_argument_is_available(name) || !named[name]["value"])
      {
        return FALSE;
      }

      return TRUE;
    }

    ##
    # Check if named argument should be quoted.
    #
    # @anonparam Name of argument.
    # @param name Can be used instead of name anonparam.
    #
    # @return TRUE if needs quoted and FALSE if not.
    ##
    public function named_argument_value_is_quoted(name)
    {
      if (isnull(name)) name = _FCT_ANON_ARGS[0];

      if (!named_argument_is_available(name) || !named[name]["quote_value"])
      {
        return FALSE;
      }

      return TRUE;
    }

    ##
    # Run the named argument's validate function against value.
    #
    # @anonparam Name of argument
    # @anonparam Value to validate.
    # @param name Can be used instead of name anonparam.
    # @param value can be used instead of value anonparam.
    #
    # @return TRUE if validates and FALSE if invalid.
    ##
    public function named_argument_validate_value(name, value)
    {
      if (isnull(name)) name = _FCT_ANON_ARGS[0];
      if (isnull(value)) value = _FCT_ANON_ARGS[1];

      if (!named_argument_is_available(name) ||
          !named_argument_has_value(name) ||
          !named[name]["validate_func"](value))
      {
        return FALSE;
      }

      return TRUE;
    }

    ##
    # Check if position is in range of positional arguments.
    #
    # @anonparam Index of positional.
    # @param position Can be used instead of index anonparam.
    #
    # @return TRUE if is a valid index and FALSE if not.
    ##
    public function positional_argument_is_available(position)
    {
      if (isnull(position)) position = _FCT_ANON_ARGS[0];

      return position < max_index(positional);
    }

    ##
    # Check if positional should be quoted.
    #
    # @anonparam Index of positional.
    # @param position Can be used instead of index anonparam.
    #
    # @return TRUE if needs quoted and FALSE if not.
    ##
    public function positional_argument_value_is_quoted(position)
    {
      if (isnull(position)) position = _FCT_ANON_ARGS[0];

      if (!positional_argument_is_available(position) ||
          !positional[position]["quote_value"])
      {
        return FALSE;
      }

      return TRUE;
    }

    ##
    # Run the positional argument's validate function against value.
    #
    # @anonparam Index of positional.
    # @anonparam Value to validate.
    # @param position Can be used instead of index anonparam.
    # @param value can be used instead of value anonparam.
    #
    # @return TRUE if validates and FALSE if invalid.
    ##
    public function positional_argument_validate_value(position, value)
    {
      if (isnull(position)) position = _FCT_ANON_ARGS[0];
      if (isnull(value)) value = _FCT_ANON_ARGS[1];

      if (!positional_argument_is_available(position) ||
          !positional[position]["validate_func"](value))
      {
        return FALSE;
      }

      return TRUE;
    }

    ##
    # Overrides default method used to check if command exists on host.
    #
    # @anonparam Command string to execute on host to see if command exists.
    # @anonparam Function reference to see if command exists. Function takes anonparam
    #            of the cmd output. Returns TRUE if exists and FALSE if doesn't.
    # @param cmd Can be used instead of anonparam.
    # @param validate_func can be used instead of anonparam.
    #
    # @return NULL
    ##
    public function set_command_exists_host_check(cmd, validate_func)
    {
      if (isnull(cmd)) cmd = _FCT_ANON_ARGS[0];
      if (isnull(validate_func)) validate_func = _FCT_ANON_ARGS[1];

      if (isnull(cmd)) spad_log_and_exit(exit_level:1, exit_msg:'set_command_exists_host_check() must have argument cmd.', name:log_name);
      if (isnull(validate_func) || typeof(validate_func) != 'function')
      {
        spad_log_and_exit(exit_level:1, exit_msg:'set_command_exists_host_check() must have argument validate_func and it must be a function reference.', name:log_name);
      }

      cmd_exists_check["cmd"] = cmd;
      cmd_exists_check["validate_func"] = validate_func;
    }

    ##
    # Set default timeout setting.
    #
    # @anonparam Number of seconds for default timeout.
    # @param timeout Can be used instead of anonparam
    #
    # @return NULL
    ##
    public function set_default_timeout(timeout)
    {
      if (isnull(timeout)) timeout = _FCT_ANON_ARGS[0];

      default_timeout = timeout;
    }

    ##
    # Get value of default timeout setting.
    #
    # @return Default timeout value in seconds.
    ##
    public function get_default_timeout()
    {
      return default_timeout;
    }

    ##
    # Set default value of stderr to /dev/null setting.
    #
    # @anonparam TRUE or FALSE
    # @param stderr_to_dev_null Can be used instead of anonparam
    #
    # @return NULL
    ##
    public function set_default_stderr_to_dev_null(stderr_to_dev_null)
    {
      if (isnull(stderr_to_dev_null)) stderr_to_dev_null = _FCT_ANON_ARGS[0];

      default_stderr_to_dev_null = stderr_to_dev_null;
    }

    ##
    # Get value of default stderr to /dev/null setting.
    #
    # @return TRUE or FALSE
    ##
    public function get_default_stderr_to_dev_null()
    {
      return default_stderr_to_dev_null;
    }

    ##
    # Set positionals to only be allowed at the beginning.
    #
    # @anonparam TRUE or FALSE
    #
    # @return NULL
    ##
    public function set_positionals_at_beginning()
    {
      if (_FCT_ANON_ARGS[0])
      {
        positionals_end = FALSE;
        positionals_beginning = TRUE;
      }
      else
      {
        positionals_beginning = FALSE;
      }
    }

    ##
    # Set positionals to only be allowed at the end.
    #
    # @anonparam TRUE or FALSE
    #
    # @return NULL
    ##
    public function set_positionals_at_end()
    {
      if (_FCT_ANON_ARGS[0])
      {
        positionals_beginning = FALSE;
        positionals_end = TRUE;
      }
      else
      {
        positionals_end = FALSE;
      }
    }

    ##
    # Adds a positional argument to the command definition.
    #
    # @anonparam Function reference for value validation function.
    #            Function takes anonparam for value and returns TRUE if valid and FALSE if invalid.
    # @param  validate_func Can be used to pass value validation function instead of anonparam.
    # @param  quote_value If TRUE automatically quotes value with single quotes in command string.
    #                     Defaults to FALSE.
    # @param  has_many Allowed only if positionals are set to beginning or end.
    #                  If TRUE allows last positional to consume additional optional positionals.
    #                  Defaults to FALSE. 
    #
    # @return TRUE or exit with error.
    ##
    public function add_positional_argument(validate_func, quote_value, has_many)
    {
      if (isnull(validate_func)) validate_func = _FCT_ANON_ARGS[0];
      if (isnull(quote_value)) quote_value = FALSE;
      if (isnull(has_many)) has_many = FALSE;
      
      if (typeof(validate_func) != 'function')
      {
        spad_log_and_exit(exit_level:1, exit_msg:'add_positional_argument() validate_func must be of function reference.', name:log_name);
      }

      if (has_many)
      {
        if (positionals_have_has_many)
        {
          spad_log_and_exit(exit_level:1, exit_msg:'add_positional_argument() can only have one has_many.', name:log_name);
        }

        if (!positionals_beginning && !positionals_end)
        {
          spad_log_and_exit(exit_level:1, exit_msg:'add_positional_argument() can only have has_many if positionals are set to the beginning or end.', name:log_name);
        }

        positionals_have_has_many = TRUE;
      }
      else
      {
        if (positionals_have_has_many)
        {
          spad_log_and_exit(exit_level:1, exit_msg:'add_positional_argument() has a has_many and it must be the last positional.', name:log_name);
        }
      }

      positional[max_index(positional)] = {"validate_func": validate_func,
                                           "quote_value": quote_value,
                                           "has_many": has_many};
    }

    ##
    # Adds a named argument to the command definition.
    #
    # @anonparam Name of named argument.
    # @anonparam Function reference for value validation function if argument takes a value.
    #            Required only if param value is TRUE.
    #            Function takes single anonparam of value and return TRUE if valid
    #            and FALSE if invalid.
    # @param  name Can be used to pass the name of the named argument instead of anonparam
    # @param  validate_func Can be used to pass value validation function instead of anonparam.            
    # @param  host_check Array containing cmd and validate_func keys. 
    #                    cmd key's value is the command to run on the host to see if named arg exists.
    #                    validate_func key's value is a function reference that checks the output of
    #                    cmd to see if named argument exists. Fuction takes single anonparam of command
    #                    output and returns TRUE if exists FALSE if is doesn't.
    # @param  value Named argument has value if TRUE and doesn't if FALSE.
    #               Defaults to TRUE.
    # @param  quote_value If TRUE automatically quotes value with single quotes in command string.
    #                     Defaults to FALSE.
    #
    # @return TRUE or exit with error.
    ##
    public function add_named_argument(name, validate_func, host_check, value, quote_value)
    {
      if (isnull(name)) name = _FCT_ANON_ARGS[0];
      if (isnull(quote_value)) quote_value = FALSE;

      if (isnull(name)) 
      {
        spad_log_and_exit(exit_level:1, exit_msg:'add_named_argument() must have an argument name.', name:log_name);
      }

      if(named_argument_is_available(name))
      {
        spad_log_and_exit(exit_level:1, exit_msg:'add_named_argument() name has already been defined.', name:log_name);
      }

      if (isnull(value)) value = TRUE;
      if (value)
      {
        if (isnull(validate_func)) validate_func = _FCT_ANON_ARGS[1];
        if (isnull(validate_func) || typeof(validate_func) != 'function')
        {
          spad_log_and_exit(exit_level:1, exit_msg:'add_named_argument() has a value so validate_func must be a function reference.', name:log_name);
        }
      }

      if (!(!isnull(host_check) &&
            !isnull(host_check["cmd"]) &&
            !isnull(host_check["validate_func"]) &&
            typeof(host_check["validate_func"]) == 'function'))
      {
        host_check = {};
      }

      named[name] = {"value" : value,
                     "quote_value" : quote_value,
                     "validate_func" : validate_func,
                     "host_check" : host_check};
      return TRUE;
    }

    ##
    # Validates command and returns string to execute on the host.
    #
    # @anonparam Each anon parameter is a argument to the command.
    # @param  args Optional named argument to allow an array can be passed instead of through anonparam.
    # @param  named_only If TRUE then expects only named arguments and no positional arguments.
    #                    Useful for partial argument lists.
    #
    # @return list list[0] is return status, list[1] is error message
    #              or validated command string.
    ##
    public function generate_command(args, named_only)
    {
      var cmd, err, name, pos_cmd;

      init_cmd(cache_only:TRUE);

      if(!command_exists_on_host()) return [sh_commands::CMD_FAIL, cmd_name + " command doesn't exist on host."];

      if (isnull(args) && !isnull(_FCT_ANON_ARGS))
      {
        args = _FCT_ANON_ARGS;
      }
      else if(isnull(args))
      {
        args = [];
      }

      if (isnull(named_only)) named_only = FALSE;

      if (!named_only)
      {
        cmd = cmd_name;
      }
      else
      {
        cmd = "";
      }

      if (!named_only && max_index(positional) > max_index(args))
      {
        err = 'Expected ' + max_index(positional) + ' positional argument(s), but recieved ' + max_index(args) + '.';
        return [sh_commands::CMD_FAIL, err];
      }

      var i = 0;
      var positional_index = -1;

      # Positionals forced to the beginning
      if (!named_only && positionals_beginning)
      {
        for (; i < max_index(args); ++i)
        {
          if (!positionals_have_has_many && i == max_index(positional))
          {
            break;
          }
          else if(i < max_index(positional))
          {
            positional_index = i;
          }
          else
          {
            if (named_argument_is_available(args[i]))
            {
              break;
            }
          }

          pos_cmd = generate_positional_cmd_string(positional_index, args[i]);
          if (pos_cmd[0] == sh_commands::CMD_OK)
          {
            cmd += pos_cmd[1];
          }
          else
          {
            return pos_cmd;
          }
        }
      }
      
      for (; i < max_index(args); ++i)
      {
        if (!named_argument_is_available(args[i]))
        {
          if (!named_only &&
              !positionals_beginning &&
              !positionals_end &&
              positional_index < max_index(positional)-1)
          {
            # Positionals mixed
            ++positional_index;
            pos_cmd = generate_positional_cmd_string(positional_index, args[i]);
            if (pos_cmd[0] == sh_commands::CMD_OK)
            {
              cmd += pos_cmd[1];
            }
            else
            {
              return pos_cmd;
            }

            continue;
          }
          else
          {
            if (!named_only && positionals_end)
            {
              break;
            }
            else
            {
              err = 'Unknown named argument "' + args[i] + '".';
              return [sh_commands::CMD_FAIL, err];  
            }
          }
        }

        # Named argument
        if (!named_argument_exists_on_host(args[i]))
        {
          err = 'Named argument "' + args[i] + '" is unavailable on the host.';
          return [sh_commands::CMD_FAIL, err];
        }

        if (named_argument_has_value(args[i]))
        {
          name = args[i];
          ++i;
          if (named_argument_validate_value(name, args[i]))
          {
            cmd += " " + name + " ";
            if (named_argument_value_is_quoted(name))
            {
              cmd += "'" + args[i] + "'";
            }
            else
            {
              cmd += args[i];
            }
          }
          else
          {
            err = 'Named argument "' + name + '" has a invalid value "' + args[i] + '".';
            return [sh_commands::CMD_FAIL, err];
          }
        }
        else
        {
          cmd += " " + args[i];
        }
      }

      # Positionals forced at end
      if (!named_only && positionals_end)
      {
        # Track where i started so we can subtract that
        # from i to get current positional
        var count_at_end = i;
        for (; i < max_index(args); ++i)
        {
          if (!positionals_have_has_many && (i - count_at_end) == max_index(positional))
          {
            if ((i+1) <= max_index(args))
            {
              err = 'Expected ' + max_index(positional) + ' positional argument(s) at the end.';
              return [sh_commands::CMD_FAIL, err];
            }

            break;
          }
          else if((i - count_at_end) < max_index(positional))
          {
            positional_index = i - count_at_end;
          }

          pos_cmd = generate_positional_cmd_string(positional_index, args[i]);
          if (pos_cmd[0] == sh_commands::CMD_OK)
          {
            cmd += pos_cmd[1];
          }
          else
          {
            return pos_cmd;
          }
        }
      }

      if (!named_only && positional_index+1 < max_index(positional))
      {
        err = 'Expected ' + max_index(positional) + ' positional argument(s), but recieved ' + (positional_index + 1) + '.';
        return [sh_commands::CMD_FAIL, err];
      }

      return [sh_commands::CMD_OK, cmd];
    }

    ##
    # Runs command on host with timeout capabilities using command's default.
    # Also uses default for stderr to /dev/null setting on command.
    # Does not validate command. This is a helper function for running
    # already validated commands and shouldn't be used directly by plugins.
    #
    # @param  cmd  Command string to execute on host.
    # @param  timeout  Timeout parameter for command.
    #                  Default's to command's default setting.
    # @param  stderr_to_dev_null If TRUE redirects stderr to /dev/null on host.
    #                            Defaults to command's default setting.
    # @param  multi_cmd Set to TRUE if wrapping a series of piped commands. Defaults FALSE.
    #
    # @return list list[0] is return status, list[1] is error message
    #              or result of command
    ##
    public function run(cmd, timeout, stderr_to_dev_null, multi_cmd)
    {
      if (isnull(timeout)) timeout = default_timeout;
      if (isnull(stderr_to_dev_null)) stderr_to_dev_null = default_stderr_to_dev_null;

      return command_builder::run(cmd:cmd, timeout:timeout, stderr_to_dev_null:stderr_to_dev_null, multi_cmd:multi_cmd);
    }
  }

  
  ##
  # Initializes general command runner requirments.
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return list list[0] is return status, list[1] is error message
  #              or result of command
  ##
  function init_cmd_runner(cache_only)
  {
    var init_kb = "Host/command_builder/run_init";

    if (isnull(cache_only)) cache_only = FALSE;

    if (cache_only && !get_kb_item(init_kb))
    {
      return [sh_commands::CMD_FAIL, "command_builder not initialized. Add command_builder_init.nasl as a script dependency."];
    }

    if(isnull(timeout_exists)) does_timeout_exist(cache_only:cache_only);
    if(isnull(perl_exists)) does_perl_exist(cache_only:cache_only);

    if (!cache_only)
    {
      replace_kb_item(name:init_kb, value:TRUE);
    }

    return [sh_commands::CMD_OK, ""];
  }

  ##
  # Wraps command in host local timeout
  #
  # @param  cmd  Command string to execute on host.
  # @param  timeout  Timeout in seconds.
  # @param  multi_cmd Set to TRUE if wrapping a series of piped commands. Defaults FALSE.
  #
  # @return command with timeout wrapper added.
  ##
  function add_command_timeout(cmd, timeout, multi_cmd)
  {
    if (isnull(multi_cmd)) multi_cmd = FALSE;

    var init_result = init_cmd_runner(cache_only:TRUE);

    if (init_result[0] == sh_commands::CMD_FAIL)
    {
      return init_result;
    }

    # Needs wrapped by sh to give all commands one parent process
    if (multi_cmd)
    {
      cmd = str_replace(string:cmd, find:'"', replace:'\\"');
      cmd = str_replace(string:cmd, find:'$', replace:'\\$');
      cmd = 'sh -c "' + cmd + '"';
    }

    if (timeout_exists)
    {
      # Allows returns a status value
      # Extra newline before status needed to determine truncated output.
      cmd = 'timeout -s9 ' + timeout + 's ' + cmd + '; RET=$?; echo; echo "$RET"';
    }
    else if(perl_exists)
    {
      # A perl stand in for the timeout command.
      cmd = 'timeout(){ perl -e \'$SIG{CHLD} = "IGNORE";$pid = fork;if($pid == 0){setpgrp;shift;system @ARGV;exit;}$i = 0;$t = shift;while($i < $t){if(kill(0, $pid)){sleep 1;$i++;}else{exit 0;}}kill -9, getpgrp($pid);print "\\nTERMINATED\\n";\' "$@"; } ; timeout ' + timeout + '  ' + cmd + ';';
    }
    else if(isnull(get_kb_item(sshlib::SSH_LIB_KB_PREFIX + get_kb_connection_id(remote_host:kb_ssh_host(), remote_port:kb_ssh_transport()) + "/escalation_type")))
    {
      # No pivilage escalation type is being used. Shell timeout fallback is ok in this case.
      # Last 2>/dev/null is needed for kill command doesn't redirect cmd's stderr
      # Only adds TERMINATED if times out.
      # Extra newline before needed to determine truncated output.
      cmd = cmd + ' & NFP=$! ; sw(){ to="' +
              timeout +
              '" ; (( i = to )) ; while (( i > 0 )) ; do kill -0 $NFP || exit 0 ;' +
              ' sleep 1 ; (( i -= 1 )) ; done ; ';
      if (multi_cmd)
      {
        # Enumerates all child processes and kills al of them
        cmd += 'ps -ef | awk "\\$3 == $NFP { print \\$2}" | xargs -I % kill %';
      }
      else
      {
        cmd += 'kill $NFP';
      }

      cmd += ' ; echo; echo "TERMINATED" ; } ; sw "$to" 2>/dev/null';
    }
    else
    {
      return [sh_commands::CMD_FAIL, "Privilege escalation is being used which requires timeout or perl to be avilable on the system."];
    }

    return [sh_commands::CMD_OK, cmd];
  }

  ##
  # Runs command on host with timeout capabilities.
  # Does not validate command. This is a helper function for running
  # already validated commands and shouldn't be used directly by plugins.
  #
  # @param  cmd  Command string to execute on host.
  # @param  timeout  Timeout parameter for command (optional)
  # @param  multi_cmd Set to TRUE if composed of multiple commands. Defaults FALSE.
  # @param  stderr_to_dev_null If TRUE redirects stderr to /dev/null on host. Defaults FALSE.
  #
  # @return list list[0] is return status, list[1] is error message
  #              or result of command
  ##
  function run(cmd, timeout, multi_cmd, stderr_to_dev_null)
  {
    if (empty_or_null(cmd)) cmd = _FCT_ANON_ARGS[0];
    if (empty_or_null(cmd)) return [sh_commands::CMD_FAIL, 'run() requires a command to run.'];

    if (empty_or_null(stderr_to_dev_null)) stderr_to_dev_null = FALSE;

    if (stderr_to_dev_null)
    {
      cmd += ' 2>/dev/null';
    }

    var timedout = FALSE;

    var init_result = init_cmd_runner(cache_only:TRUE);

    if (init_result[0] == sh_commands::CMD_FAIL)
    {
      return init_result;
    }

    if (!isnull(timeout))
    {
      cmd = add_command_timeout(cmd:cmd, timeout:timeout, multi_cmd:multi_cmd);
      if (cmd[0] == sh_commands::CMD_OK)
      {
        cmd = cmd[1];
      }
      else
      {
        spad_log(message:'command_builder::run() failed with error ' + cmd[1] + '.');
        return cmd;
      }
    }

    # Send command with timeout and additional time to allow for the timeout host side.
    spad_log(message:'command_builder::run() ran "' + cmd + '".');
    var buf = info_send_cmd(cmd:cmd, timeout:timeout + 5);
    spad_log(message:'command_builder::run() returned "' + buf + '".');

    # Determine if the command timed out
    if (!isnull(timeout))
    {
      if (buf)
      {
        var lines = split(buf, keep:FALSE);

        if (timeout_exists)
        {
          # Return Code is 137 if timed out since we use signal KILL(9)
          if (lines[max_index(lines)-1] == "137")
          {
            timedout = TRUE;
          }
        }
        else
        {
          if (lines[max_index(lines)-1] == "TERMINATED")
          {
            timedout = TRUE;
          }
        }

        # If needed remove timeout related data at end of output
        # in the case of the timeout this can include the last incomplete line
        var skip = 0;
        if(timeout_exists || timedout)
        {
          skip = 2;
        }

        # Reconstruct buf
        buf = '';
        for(var i = 0; i < max_index(lines)-skip; ++i)
        {
          buf += lines[i] + '\n';
        }
      }
      # On some systems where the timeout command does not exist
      # the command sends nothing in return. In that case set buf to empty
      else
      {
        buf = '';
      }
    }

    if(timedout)
    {
      return [sh_commands::CMD_TIMEOUT, buf];
    }

    return [sh_commands::CMD_OK, buf];
  }

  ##
  # Check if timeout command exists
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return NULL
  ##
  function does_timeout_exist(cache_only)
  {
    var buf, kb_name, cmd;

    if (isnull(cache_only)) cache_only = FALSE;

    kb_name = "Host/command_builder/timeout_exists";

    # check cache
    timeout_exists = get_kb_item(kb_name);
    if(!isnull(timeout_exists))
    {
      return NULL;
    }

    timeout_exists = FALSE;

    if (!cache_only)
    {
      cmd = 'type timeout 2>&1';
      spad_log(message:'Timeout command check ran "' + cmd + '".');
      buf = info_send_cmd(cmd: cmd);
      spad_log(message:'Timeout command check returned "' + cmd + '".');
      if (buf && 'not found' >!< buf)
      {
        timeout_exists = TRUE;
      }

      # cache finding
      replace_kb_item(name:kb_name, value:timeout_exists);
    }

    return NULL;
  }

  ##
  # Check if perl exists
  #
  # @param cache_only Only check for cached results and do not query the host. Defaults to FALSE.
  #
  # @return NULL
  ##
  function does_perl_exist(cache_only)
  {
    var buf, kb_name, cmd;

    if (isnull(cache_only)) cache_only = FALSE;

    kb_name = "Host/command_builder/perl_exists";

    # check cache
    perl_exists = get_kb_item(kb_name);
    if(!isnull(perl_exists))
    {
      return NULL;
    }

    perl_exists = FALSE;

    if (!cache_only)
    {
      cmd = 'type perl 2>&1';
      spad_log(message:'Timeout command check ran "' + cmd + '".');
      buf = info_send_cmd(cmd: cmd);
      spad_log(message:'Timeout command check returned "' + cmd + '".');
      if (buf && 'not found' >!< buf)
      {
        perl_exists = TRUE;
      }

      # cache finding
      replace_kb_item(name:kb_name, value:perl_exists);
    }

    return NULL;
  }

  ##
  # Check that command exists on host.
  #
  # @anonparam output of command
  #
  # @return TRUE if exists FALSE if not found.
  ##
  function validate_command_exists()
  {
    var value = _FCT_ANON_ARGS[0];

    if(!empty_or_null(value) && 'not found' >< value)
    {
      return FALSE;
    }

    return TRUE;
  }

  
  ##
  # Check that value is alphanumeric.
  #
  # @anonparam value
  #
  # @return TRUE if valid FALSE if invalid.
  ##
  function validate_alphanumeric()
  {
    var value = _FCT_ANON_ARGS[0];

    if (isnull(value) || value !~ "^[0-9A-Za-z]+$")
    {
      return FALSE;
    }

    return TRUE;
  }

  ##
  # Check that value is an integer.
  #
  # @anonparam value
  #
  # @return TRUE if valid FALSE if invalid.
  ##
  function validate_int()
  {
    var value = _FCT_ANON_ARGS[0];

    if (isnull(value) || value !~ "^\d+$")
    {
      return FALSE;
    }

    return TRUE;
  }

  ##
  # Check that value has no command injection.
  #
  # @anonparam value
  #
  # @return TRUE if valid FALSE if invalid.
  ##
  function validate_no_injection()
  {
    # only allow whitelisted characters to prevent command injection
    # strings starting with '-' aren't allowed unless surrounded by quotes
    var pat = '^(( *[*A-Za-z0-9_./\\[\\]][*A-Za-z0-9_.\\-/\\[\\]]*)*|'+
              '(\'[*A-Za-z0-9_.\\-/\\[\\] ]*\')|'+
              '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$';
    var value = _FCT_ANON_ARGS[0];
  
    if (empty_or_null(value) || value !~ pat)
    {
      return FALSE;
    }

    return TRUE;
  }
}

namespace sh_commands
{
  # Return status constants
  var CMD_FAIL = 0;
  var CMD_OK = 1;
  var CMD_TIMEOUT = 2;
}
