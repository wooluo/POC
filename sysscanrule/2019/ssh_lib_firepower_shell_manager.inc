#TRUSTED 9301a95d02beb01a9bfc7f7664a42374950c71f5f18db7b4f8fe18b274daa979f4970ba3868f492a7bdb0c106a255f8ba6d9de8dbf2c3dcf2102e475a6c138e68cc5778481873b9ed8378f5debe54e40b0b2c272a7b6c9f1c644e7bcfb3b78a8ff85941e29cab38b5586a4250d4420fae03221977fc5b26c7ad2b2d7dd6635e681b474e2045c391e27456f946e877058b2591b6e0133f8de28705507170fb574ce334395b7080f6226ae2a220d25868775daa36b0dece5e4c16459c79e260a0b83cc43d03fb775445c919a48440c0bc4031ebd17af9d4874e9ac07a8c417010d6f5649a488902e5845972c95d9cf56a482753802e47db323e130b05992013763010c0fba611ac853f84809d988d18ac3eb6d434625b11e9715737d2984b701800fd3deab3507c43772ff0cb97fc4db895157a71435b187a612ed100f5da791ecae540902cc4a0ab619d2b0c022e473ef27386abedc84dd3ecf36436be7f66848b9e126e134cad22ec98aa29433b2b1a36f7e0f214da6b86726688529fdb63a29922b8bebadf749fd1c130e06e74493aef123829fd66b4925f2df61aba012ac92ea83cb9eaa6e5a1e3402337d8c3f0e841abcbe691314cd53d81fff93af09df4b9067266b137602852269d07cd2f0c9041b2ff639274f589285f2fe49e4fe74a1fbbf67b94310f123ebb12b4dd119c867fde57bf9552920baff1ae414366624c4
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# Revision:1.13
#
# This shell handler is more of a wrapper around the basic shell handler.
# The idea is that the handler will manage a stack of layers that the shell
# can be in; what layer it entered at, what layer it is in, how to change
# between the layers.
#
# The handler will obtain a specified shell, and remain at that shell for
# future calls.
#
# A revert() was added to be able to revert to the original entry shell.
#
# A close() is included to properly revert and close the channel.  This does
# not appear to be necessary, but provided to give a better close out in the
# session.  The technical challenge of using a desconstructor is the required
# access to 'channel'.
#
###

include("ssh_lib_util.inc");
include('ssh_lib_basic_shell_handler.inc');

namespace sshlib
{
  global_var _FP_SH_DEFAULT_INACTIVITY_TIMEOUT = 60;
  global_var _FP_SH_INITIAL_INACTIVITY_TIMEOUT = 5;

  ##
  # Firepower shells
  ##
  var FP_SH_CHASSIS = 'Firepower_FX-OS';
  var FP_SH_MODULE  = 'Firepower_bootCLI';
  var FP_SH_FTD     = 'Firepower_FTD_App';

  ##
  # callback function that checks to see if module has been
  # successfully entered
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if timeout reached
  # @category SSH
  ##
  function cb_fp_sh_entered_module_or_timeout(&session, &channel)
  {
    if(!channel.shell_handler) return channel_closed_return_true(channel:channel);
    return channel.shell_handler.cb_entered_module_or_timeout(channel:channel);
  }

  ##
  # callback function that checks to see if ftd has been
  # successfully entered
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if timeout reached
  # @category SSH
  ##
  function cb_fp_sh_entered_ftd_or_timeout(&session, &channel)
  {
    if(!channel.shell_handler) return channel_closed_return_true(channel:channel);
    return channel.shell_handler.cb_entered_ftd_or_timeout(channel:channel);
  }

  # Firepower shell manager, handles 3 firepower shells and switching
  # between them while wrapping basic_shell_handler to run commands
  object firepower_shell_manager : sshlib::basic_shell_handler
  {
    var objname = 'firepower_shell_manager::';
    var default_shell;
    var last_shell_used;
    var last_module_used;
    var cmd_prompts = {};
    var kb_cmd_prompts = {};
    var kb_id;

    ##
    # Shell that channel is currently in
    ##
    var current_shell;

    # Shell handler initialization caller
    # @category SSH
    ##
    function firepower_shell_manager()
    {
      this.init();

      this.kb_cmd_prompts[FP_SH_CHASSIS] = '/fp_cmd_prompt_chassis';
      this.kb_cmd_prompts[FP_SH_MODULE] = '/fp_cmd_prompt_module';
      this.kb_cmd_prompts[FP_SH_FTD] = '/fp_cmd_prompt_ftd';
    }

    ##
    # Initialize cmd_prompts from KB
    # @category SSH
    ##
    function get_cmd_prompts()
    {
      var key, module, modules, val;
      foreach var layer ([FP_SH_CHASSIS, FP_SH_MODULE, FP_SH_FTD])
      {
        key = this.kb_id + this.kb_cmd_prompts[layer];
        this.cmd_prompts[layer] = get_kb_blob(kb_id + this.kb_cmd_prompts[layer]);
        modules = get_kb_blob_list(key + '/*');
        foreach module (keys(modules))
        {
          val = modules[module];
          module -= key + '/';
          this.cmd_prompts[layer + module] = val;
        }
      }
    }

    ##
    # Set a command prompt in the KB
    # @param layer Shell layer
    # @param module Module number if applicable
    # @param cmd_prompt Command prompt to set
    # @category SSH
    ##
    function set_fp_cmd_prompt(layer, module, cmd_prompt)
    {
      this.cmd_prompts[layer + module] = cmd_prompt;
      var key = this.kb_id + this.kb_cmd_prompts[layer];
      if (!isnull(module)) key += '/' + module;
      return replace_kb_blob(name:key, value:cmd_prompt);
    }

    ##
    # Get a command prompt from the KB
    # @param layer Shell layer
    # @param module Module number if applicable
    # @param cmd_prompt Command prompt to set
    # @category SSH
    ##
    function get_fp_cmd_prompt(layer, module)
    {
      if (this.cmd_prompts[layer + module])
        return this.cmd_prompts[layer + module];
      var key = this.kb_id + this.kb_cmd_prompts[layer];
      if (!isnull(module)) key += '/' + module;
      return get_kb_blob(key);
    }

    ##
    # callback function that checks to see if module has been
    # successfully entered
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if timeout reached
    # @category SSH
    ##
    public function cb_entered_module_or_timeout(&channel)
    {
      var fn = objname + FUNCTION_NAME;
      var session = channel.session;

      if ("Cisco Security Services Platform" >< channel.data_buf)
      {
        this.current_shell = FP_SH_MODULE;
        return TRUE;
      }
      else if ("No connectivity to module" >< channel.data_buf)
      {
        dbg_log(session:session, fn:fn, message:'No connectivity to module.');
        return TRUE;
      }

      return this.check_inactivity_timeout(channel:channel);
    }

    ##
    # callback function that checks to see if ftd has been
    # successfully entered
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if timeout reached
    # @category SSH
    ##
    public function cb_entered_ftd_or_timeout(&channel)
    {
      ### needed for 9300 when slot has no FTD
      if ("ftd is not running." >< channel.data_buf)
      {
        spad_log(message:'FTD not running.  Unable to connect.\n');
        # Return TRUE to stop looping and receiving
        return TRUE;
      }
      if ("enter exit to return to bootCLI" >< channel.data_buf)
      {
        this.current_shell = FP_SH_FTD;
        return TRUE;
      }
      return this.check_inactivity_timeout(channel:channel);
    }

    ##
    # Opens a new shell and runs "show version" to determine the
    # default shell
    #
    # @param channel channel for ssh session
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    protected function _set_default_shell(&channel, cmd_timeout_min,
        inactivity_timeout_min)
    {
      var fn = objname + FUNCTION_NAME;
      var session = channel.session;
      var res = super.run_command(
        command                : "show version",
        channel                : channel,
        cmd_timeout_min        : cmd_timeout_min,
        inactivity_timeout_min : inactivity_timeout_min);
      if (!res)
      {
        dbg_log(session:session, fn:fn, message:'Default shell does not appear ' +
          'to be a Firepower shell because command "show version" ' +
          'failed to return results.');
        return FALSE;
      }

      if ('Version:' >< res && 'Startup-Vers:' >< res)
      {
        this._init_shell_values(shell: channel.shell_handler, layer: FP_SH_CHASSIS);
      }
      else if ('Image type' >< res && 'Key Version' >< res)
      {
        this._init_shell_values(shell: channel.shell_handler, layer: FP_SH_MODULE);
      }
      else if ('Threat Defense' >< res)
      {
        this._init_shell_values(shell: channel.shell_handler, layer: FP_SH_FTD);
      }
      else
      {
        dbg_log(session:session, fn:fn, message:'Default shell does not appear to ' +
          'be a Firepower shell based on result of "show version" :\n' +
          res);
        return FALSE;
      }

      dbg_log(session:session, fn:fn, message:'Setting default shell to: ' + this.default_shell);
      replace_kb_item(name:kb_id + '/default_shell', value:this.default_shell);
      return TRUE;
    }

    ##
    # Helper function to set the default values for the identified shell.
    #
    # @param layer name of shell to use
    # @param shell shell handler object
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    protected function _init_shell_values(layer, shell)
    {
      if (isnull(layer))
        return FALSE;

      if (isnull(shell) && isnull(this.cmd_prompts[layer]))
        return FALSE;

      this.default_shell = layer;
      this.current_shell = layer;
      if (shell) this.cmd_prompts[layer] = shell.cmd_prompt;
      if (!get_kb_item(kb_id + this.kb_cmd_prompts[layer]))
        set_kb_blob(name:kb_id + this.kb_cmd_prompts[layer], value:this.cmd_prompts[layer]);
      this.last_shell_used = this.default_shell;

      return TRUE;
    }

    ##
    # Switches the shell handler between the different posible shells
    #
    # @param channel channel for ssh session
    # @param source  The source shell changing from
    # @param destination  The destination shell changing to
    # @param module  The module number associated with the destination (if applicable)
    # @param command The command to use to change the shell (optional, default 'exit')
    # @param callback The callback function to use (optional, default @basic_shell_handler_at_prompt3_or_timeout)
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    protected function _change_shell_layer(&channel, source, destination, module, command, callback)
    {
      var fn = objname + FUNCTION_NAME;
      var session = channel.session;
      var msg = NULL;
      var default_callback = FALSE;

      # verify the environment is setup as needed
      if (this.current_shell != source)
      {
        dbg_log(session:session, fn:fn, message:'Current shell is not "' + source + '".');
        return FALSE;
      }

      if (isnull(command))
      {
        dbg_log(session:session, fn:fn, message:'No command provided.');
        return FALSE;
      }

      if (!channel_usable_for_shell_command(channel:channel))
        return FALSE;

      if (isnull(callback))
      {
        dbg_log(session:session, fn:fn, message:'Using default callback.');
        default_callback = TRUE;
        callback = @basic_shell_handler_at_prompt3_or_timeout;
      }

      dbg_log(session:session, fn:fn, message:'Changing "' + source + '" to "' + destination + '".');
      dbg_log(session:session, fn:fn, message:'command: ' + command);

      # Null out and set the cmd prompt if known
      var orig_cmd_prompt = this.cmd_prompt;
      this.cmd_prompt = this.get_fp_cmd_prompt(layer:destination, module:module);
      var check_len = 3;
      if (this.cmd_prompt)
      {
        if (strlen(this.cmd_prompt) < 3) check_len = strlen(this.cmd_prompt);
        dbg_log(session:session, fn:fn, message:'Expecting command prompt: ' + this.cmd_prompt);
      }

      # run command to get change layer
      channel.clear_data_buf();
      channel.window_send_data(data:command + '\n');
      this.timeout_check = _FP_SH_DEFAULT_INACTIVITY_TIMEOUT;
      channel.session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : callback,
        channel        : channel,
        timeout        : this.recv_timeout);

      # If using the default callback and did not time out, then the
      # shell was gained with the expected command prompt
      if (default_callback && !this.timed_out)
      {
        this.current_shell = destination;
      }
      # Custom call backs will change the shell on their own
      else if (this.current_shell != destination)
      {
        msg = 'Failed to obtain shell "' + destination + '"';
        if (module) msg += ', module ' + module;
        dbg_log(session:session, fn:fn, message:msg);
        session.set_cmd_error(msg);
        # Try to get back to source cmd_prompt
        if (orig_cmd_prompt)
        {
          this.cmd_prompt = orig_cmd_prompt;
          check_len = 3;
          if (strlen(this.cmd_prompt) < 3) check_len = strlen(this.cmd_prompt);
          dbg_log(session:session, fn:fn, message:'Expecting command prompt: ' + this.cmd_prompt);
          dbg_log(session:session, fn:fn, message:'Getting command prompt');
          channel.window_send_data(data:'\x03');
          this.timeout_check = _FP_SH_INITIAL_INACTIVITY_TIMEOUT;
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @basic_shell_handler_at_prompt2_or_timeout,
            channel        : channel,
            timeout        : this.recv_timeout);

          # If we got back to the original command prompt, don't set
          # last_cmd_error
          if (!this.timed_out)
          {
            return FALSE;
          }

          dbg_log(session:session, fn:fn, cmd_error:TRUE, message:
            'Timed out waiting for expected command prompt: ' + this.cmd_prompt);
        }
        this.last_cmd_error = TRUE;
        return FALSE;
      }
      # Try to receive the command prompt if we haven't already
      else if (isnull(this.cmd_prompt) || !super.at_cmd_prompt(buf:channel.data_buf, check_len:check_len))
      {
        if (!channel_usable_for_shell_command(channel:channel))
          return FALSE;

        dbg_log(session:session, fn:fn, message:'Getting command prompt');
        channel.window_send_data(data:'\x03');
        this.timeout_check = _FP_SH_INITIAL_INACTIVITY_TIMEOUT;
        channel.session.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          check_callback : @basic_shell_handler_at_prompt2_or_timeout,
          channel        : channel,
          timeout        : this.recv_timeout);

        if (this.cmd_prompt && this.timed_out)
        {
          dbg_log(session:session, fn:fn, cmd_error:TRUE, message:
            'Timed out waiting for expected command prompt: ' + this.cmd_prompt);
          this.last_cmd_error = TRUE;
          return FALSE;
        }
        if (!this.cmd_prompt)
        {
          # originally
          #var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
          #this.cmd_prompts[destination] = lines[max_index(lines)-1];

          # changed to
          var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
          var tmp_prompt = lines[max_index(lines)-1];
          dbg_log(session:session, fn:fn, message:'Found tmp_prompt: ' + tmp_prompt);
          if (tmp_prompt =~ '^\xA0')
          {
            tmp_prompt = substr(tmp_prompt, 1);
            dbg_log(session:session, fn:fn, message:'Massaging tmp_prompt: ' + tmp_prompt);
          }
          if (tmp_prompt =~ '^\\^C')
          {
            tmp_prompt = substr(tmp_prompt, 2);
            dbg_log(session:session, fn:fn, message:'Massaging tmp_prompt: ' + tmp_prompt);
          }
          this.cmd_prompt = tmp_prompt;
          this.cmd_prompts[destination] = this.cmd_prompt;

          this.set_fp_cmd_prompt(layer:destination, module:module, cmd_prompt:this.cmd_prompt);
          dbg_log(session:session, fn:fn, message:'Found command prompt: ' + this.cmd_prompt);
        }
      }
      dbg_log(session:session, fn:fn, message:'Successfully obtained shell "' +
        destination + '"');

      this.fresh_shell = FALSE;
      this.timed_out = FALSE;
      this.last_cmd_error = FALSE;
      this.last_shell_used = destination;
      if (module) this.last_module_used = module;
      channel.clear_data_buf();

      return TRUE;
    }

    ##
    # Utility functions to request a shell change to chassis
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    public function get_sh_chassis(&channel)
    {
      # make sure the change can happen
      if (this.default_shell == FP_SH_FTD)
        return FALSE;

      if (this.default_shell == FP_SH_MODULE)
        return FALSE;

      # change the shells
      if (this.current_shell == FP_SH_FTD)
        this._change_shell_layer(
          channel:channel,
          source:FP_SH_FTD,
          destination:FP_SH_MODULE,
          module:this.last_module_used,
          command:'exit');

      if (this.current_shell == FP_SH_MODULE)
        this._change_shell_layer(
          channel:channel,
          source:FP_SH_MODULE,
          destination:FP_SH_CHASSIS,
          command:'exit');

      # check that ending shell is the correct shell
      if (this.current_shell == FP_SH_CHASSIS)
        return TRUE;

      return FALSE;
    }

    ##
    # Utility functions to request a shell change to module
    #
    # @param channel channel for ssh session
    # @param module module number to use
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    public function get_sh_module(&channel, module)
    {
      # make sure the change can happen
      if (this.default_shell == FP_SH_FTD)
        return FALSE;

      # change the shells
      if (this.current_shell == FP_SH_CHASSIS)
        this._change_shell_layer(
          channel:channel,
          source:FP_SH_CHASSIS,
          destination:FP_SH_MODULE,
          module:module,
          command:this._get_module_connect(module: module),
          callback:this._get_module_callback());

      if (this.current_shell == FP_SH_FTD)
        this._change_shell_layer(
          channel:channel,
          source:FP_SH_FTD,
          destination:FP_SH_MODULE,
          module:module,
          command:'exit');

      # check that ending shell is the correct shell
      if (this.current_shell == FP_SH_MODULE)
        return TRUE;

      return FALSE;
    }

    ##
    # Utility functions to request a shell change to threat defense
    #
    # @param channel channel for ssh session
    # @param module module number to use
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    public function get_sh_ftd(&channel, module)
    {
      # change the shells
      if (this.current_shell == FP_SH_CHASSIS)
        this._change_shell_layer(
          channel:channel,
          source:FP_SH_CHASSIS,
          destination:FP_SH_MODULE,
          module:module,
          command:this._get_module_connect(module:module),
          callback:this._get_module_callback(module:module));

      if (isnull(module)) module = this.last_module_used;
      if (this.current_shell == FP_SH_MODULE)
        this._change_shell_layer(
          channel:channel,
          source:FP_SH_MODULE,
          destination:FP_SH_FTD,
          module:module,
          command:'connect ftd',
          callback:this._get_ftd_callback(module:module));

      # check that ending shell is the correct shell
      if (this.current_shell == FP_SH_FTD)
        return TRUE;

      return FALSE;
    }

    ##
    # Determine command to connect to the module.
    #
    # @param module module number to connect to
    #
    # @return command string command to connect to module
    ##
    protected function _get_module_connect(module)
    {
      if (isnull(module))
        if (isnull(this.last_module_used))
          module = 1;
        else
          module = this.last_module_used;

      return 'connect module ' + module + ' telnet';
    }

    ##
    # Determine command to connect to the module.
    #
    # @param module Module number
    # @return function reference
    ##
    protected function _get_module_callback(module)
    {
      if (isnull(this.get_fp_cmd_prompt(layer:FP_SH_MODULE, module:module)))
        return @cb_fp_sh_entered_module_or_timeout;
      else
        return NULL;
    }

    ##
    # Determine command to connect to the module.
    #
    # @param module Module number
    # @return function reference
    ##
    protected function _get_ftd_callback(module)
    {
      #if (isnull(this.cmd_prompts[FP_SH_FTD]))
      if (
        isnull(this.get_fp_cmd_prompt(layer:FP_SH_FTD, module:module)) ||
        strlen(this.cmd_prompts[FP_SH_FTD]) < 3
      )
        return @cb_fp_sh_entered_ftd_or_timeout;
      else
        return NULL;
    }

    ##
    # Utility functions to check all valid FP shells
    #
    # @param shell shell string to check
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    protected function _is_valid_shell(shell)
    {
      return
        shell == FP_SH_CHASSIS ||
        shell == FP_SH_MODULE ||
        shell == FP_SH_FTD;
    }

    ##
    # run given command
    #
    # @param session SSH session in case reconnection is needed
    # @param channel channel for ssh session
    # @param command cmd to run
    # @param force_priv_escl force priv escalation flag
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    # @param cmd_shell The global var for the Firepower shell that should
    #                  be used to run the command (optional, default FP_SH_FTD)
    # @param module    Module number to use (optional, default to 1)
    #
    # @return command result or NULL on failure
    # @category SSH
    ##
    public function run_command(&session, &channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min, cmd_shell, module)
    {
      var fn = objname + FUNCTION_NAME;
      var obj_ch_id = '[channel ' + channel.local_channel + ']: ';
      var msg, res;

      # Check channel and replace if necessary; replace_shell() will
      # set applicable error if it fails
      channel.set_shell_handler(shell_handler:this);
      if (!channel_usable_for_shell_command(channel:channel))
      {
        if (!session_replace_shell(session:session, channel:channel))
          return dbg_log(session:session, fn:fn, error:TRUE, message:
            'Did not run command due to session error.' +
            '\nCommand : ' + command + '\nSession error : "' + last_error + '"');
        this.fresh_shell = TRUE;
      }

      # Initialize variables
      set_timeouts(inactivity_timeout_min:inactivity_timeout_min,
          cmd_timeout_min:cmd_timeout_min);

      this.kb_id = SSH_LIB_KB_PREFIX + session.get_kb_connection_id();
      this.get_cmd_prompts();

      if (this.fresh_shell && !this.default_shell)
      {
        dbg_log(session:session, fn:fn, message:'Checking default Firepower shell.');
        this.default_shell = get_kb_item(this.kb_id + '/default_shell');
        if (!this.default_shell || !this.cmd_prompts[this.default_shell])
        {
          this._set_default_shell(
            channel                : channel,
            cmd_timeout_min        : cmd_timeout_min,
            inactivity_timeout_min : inactivity_timeout_min);
        }
      }

      if (!this.default_shell)
      {
        session.set_cmd_error('Unable to run command. Failed to ' +
          'confirm that default shell is a Firepower shell.');
        return NULL;
      }

      # If fresh shell, assume current shell is default shell
      if (this.fresh_shell) this._init_shell_values(layer:this.default_shell);

      # Assume last shell used as shell to run in if not specified
      if (isnull(cmd_shell)) cmd_shell = this.last_shell_used;

      # Assume last module used as moudle to run in for escalation from chassis
      # to bootCLI
      if (isnull(module)) module = this.last_module_used;

      dbg_log(session:session, fn:fn, message:'Command to run : ' + command);
      dbg_log(session:session, fn:fn, message:'Firepower shell to use : ' + cmd_shell + ' (' + module + ')');

      # Verify the current and target shells are known shell before proceeding
      if (!this._is_valid_shell(shell: this.current_shell))
      {
        session.set_cmd_error('Unable to run command. Current shell "' +
          this.current_shell + '" is not a known Firepower shell.');
        return NULL;
      }
      if (!this._is_valid_shell(shell: cmd_shell))
      {
        session.set_cmd_error('Unable to run command. Target shell "' +
          cmd_shell + '" is not a known Firepower shell.');
        return NULL;
      }

      # If module is not the last module used, must return to chassis before
      # re-escalating to the application
      if (!isnull(this.last_module_used) && module != this.last_module_used)
      {
        if (!this.get_sh_chassis(channel:channel))
        {
          session.set_cmd_error('Unable to return to chassis to escalate to ' +
            'different module (' + this.last_module_used + ' -> ' + module + ').');
          return NULL;
        }
        # clear out upper layer cmd_prompts to allow for re-identification of
        # command prompts
        this.cmd_prompts[FP_SH_MODULE] = NULL;
        this.cmd_prompts[FP_SH_FTD] = NULL;
      }

      # Set sh to the target shell for the command
      dbg_log(session:session, fn:fn, message:'Making sure the current shell ' +
        'is the specified shell "' + cmd_shell + '" to run the command.');

      if (cmd_shell == this.current_shell)
      {
        res = TRUE;
      }
      else if (cmd_shell == FP_SH_CHASSIS)
      {
        res = this.get_sh_chassis(channel:channel);
      }
      else if (cmd_shell == FP_SH_MODULE)
      {
        res = this.get_sh_module(channel:channel, module:module);
      }
      else if (cmd_shell == FP_SH_FTD)
      {
        res = this.get_sh_ftd(channel:channel, module:module);
      }
      else
      {
        session.set_cmd_error('Unknown Firepower shell "' + cmd_shell + '".');
        return NULL;
      }

      if (!res)
      {
        session.set_cmd_error('Unable to obtain shell "' + cmd_shell +
          '" specified to run command.');
        return NULL;
      }

      dbg_log(session:session, fn:fn, message:'Running command "' + command +
        '" using Firepower shell "' + this.current_shell + '"');

      var ret = super.run_command(
        channel                : channel,
        command                : command,
        cmd_timeout_min        : cmd_timeout_min,
        inactivity_timeout_min : inactivity_timeout_min);

      # set last shell and last module after successful command run
      if (!isnull(ret))
      {
        this.last_shell_used = cmd_shell;
        this.last_module_used = module;
      }

      return ret;
    }

    ##
    # Revert to default shell
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    public function revert(&channel)
    {
      var fn = objname + FUNCTION_NAME;
      var session = channel.session;
      var res = TRUE;

      if (this.current_shell == this.default_shell)
        return TRUE;

      dbg_log(session:session, fn:fn, message:'Reverting current shell "' +
        this.current_shell + '" to default shell "' +
        this.default_shell + '".');

      if (this.default_shell == FP_SH_CHASSIS)
        res = this.get_sh_chassis(channel:channel);
      else if(this.default_shell == FP_SH_MODULE)
        res = this.get_sh_module(channel:channel);
      else if(this.default_shell == FP_SH_FTD)
        res = this.get_sh_ftd(channel:channel);

      if (!res)
      {
        session.set_cmd_error('Failed to revert to default Firepower shell.');
        return FALSE;
      }

      return TRUE;
    }


    ##
    # Close the shell by sending an 'exit'
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if successful, FALSE otherwise
    ##
    public function close(&channel)
    {
      var fn = objname + FUNCTION_NAME;
      var session = channel.session;

      dbg_log(session:session, fn:fn, message:'Closing Firepower shell.');

      # Revert to default shell if necessary
      if (this.current_shell != this.default_shell)
      {
        this.revert(channel:channel);
      }

      super.run_command(
        channel                : channel,
        command                : 'exit');

      return TRUE;
    }

    ##
    # test private function
    #
    # @param name name of function to return
    # @param args args to pass to the function
    #
    # @return NULL on error / result of named function
    # @category SSH
    ##
    public function test_private_function(name, args)
    {
      var fn = 'sh_shell_handler.test_private_function';
      if (isnull(name))
      {
        spad_log(message:fn + ': Missing name parameter');
        return;
      }
      switch (name)
      {
        default:
          spad_log(message:fn + ': "'+name+'()" is not yet implemented for testing with this function');
          return NULL;
      }
    }
  }
}
