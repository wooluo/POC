#TRUSTED 65cb9bde76fbc312c2774f138c345239fe245778fe980b08b8a4ba16d2e9a43b0fc3de564af2c602f3100b053d54af4b5d7b1c84bfb05db87889bfcc29a1b7f3e9fe628cd80eb54414781c1f04fc54b3392708b869180cdffe472e9d0c694d3dba0d9401e5709ca64bd44f3be4ca499dda2342921aa77ce59fbb806790bf65d8c5dbf949dc7b2efacd5b274caf0fa0bfb193894856f4f06840e1a27e0afff7946edb02e10ec6ddbda88474d3d8fee0ade7b3c96aa6877bcf066396e5584ce222d35c1fe7dabfa5891ab0f9e6edaa6bff2e2b91cb0260b6d8a782241df076992a9f8bf9aac5514b9f747d0630bcba04551202a8f77b883efcbfd1a7e59b3822fcb1e8f28a88f5e35ccb122f7745d0a54c7e3363c1811d7f489ad8df7b2e4d7fe75718689419a29001a7764d458037bd9330239381101bfe0749569a62d02ee6adca11806693a204d5275f9d086121ad64e9439607dd53dbeda2a86868229816830cffd276ad6e932ad1da52c2fd0faa19421ce6862f1f673eb5672bfd6c8afa54f4e6a977c8b99800397635103859f447068f8474d8d5a47b0d0a5ed60953336a3aedab65b311c711eacc5d84fab7921c358c5a059c4e2b94b16a91a7cbdc1f6fda8e23492f4193d723d2746c40eb1774067e8d847b7ab44ff2cce334c8b05c315bde5692fc6632fbe2a1138b52dd25f2bd40c93b188302c4c8b888a61f036c4b
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
###

include("ssh_lib_util.inc");

namespace sshlib
{
  DEFAULT_PRIV_ESCL_WARNING_TIMEOUT = 3;
  global_var _BASIC_DEFAULT_INACTIVITY_TIMEOUT = 60;
  global_var _BASIC_INITIAL_INACTIVITY_TIMEOUT = 5;
  global_var _BASIC_DEFAULT_CMD_TIMEOUT = NULL;

  ### RECV_UNTIL CALLBACKS ###

  ##
  # callback function that checks for either a timeout or buffer update
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if timeout reached
  # @category SSH
  ##
  function basic_shell_handler_on_channel_buffer_update_or_timeout(&session, &channel)
  {
    var sh = channel.shell_handler;
    if(!sh) return channel_closed_return_true(channel:channel);
    return sh.on_channel_buffer_update_or_timeout(channel:channel);
  }

  ##
  # callback function that checks for buffer inactivity
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if inactive
  # @category SSH
  ##
  function basic_shell_handler_on_channel_buffer_inactivity(&session, &channel)
  {
    var sh = channel.shell_handler;
    if(!sh) return channel_closed_return_true(channel:channel);
    return sh.on_channel_buffer_inactivity(channel:channel);
  }

  ##
  # callback function to check for prompt or timeout
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if found
  # @category SSH
  ##
  function basic_shell_handler_at_prompt3_or_timeout(&session, &channel)
  {
    var sh = channel.shell_handler;
    if(!sh) return channel_closed_return_true(channel:channel);
    return sh.at_prompt3_or_timeout(channel:channel);
  }

  ##
  # callback function to check for prompt or timeout
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if found
  # @category SSH
  ##
  function basic_shell_handler_at_prompt2_or_timeout(&session, &channel)
  {
    var sh = channel.shell_handler;
    if(!sh) return channel_closed_return_true(channel:channel);
    return sh.at_prompt2_or_timeout(channel:channel);
  }
  ### END RECV_UNTIL CALLBACKS ###

  ### Basic shell handler utils ###

  ##
  # Logs error and returns TRUE
  #
  # @param channel channel for ssh session
  #
  # @return TRUE
  ##
  function channel_closed_return_true(&channel)
  {
    spad_log(message:'basic_shell_handler [channel ' +
      channel.local_channel + ']: Channel is closed.');
    return TRUE;
  }

  ##
  # Logs error and returns NULL
  #
  # @param fn function name for logging
  # @param session session handle for ssh session
  # @anonparam channel for ssh session
  #
  # @return NULL
  ##
  function channel_closed_return_null(fn, &session, &channel)
  {
    var ch_label = '';
    if (channel) ch_label = '[channel ' + channel.local_channel + ']: ';
    var msg = ch_label + 'Channel is closed.';
    if (session) session.dbg_log(fn:fn, level:DEBUG1, message:msg);
    else spad_log(message:fn + ' ' + msg);
    return NULL;
  }

  ### End basic shell handler utils ###

  # basic raw shell handler, no escalation or special formatting
  object basic_shell_handler
  {
    var fresh_shell = TRUE;
    var last_buffer_update_ts;
    var cur_user;
    var cur_buf = "";
    var cur_buf_change_counter = 0;

    # this can be set in class before using sshrecv_until.  this will cause the callback check functions to
    # return after a given inactivity period (no channel data updates)
    var timeout_check;
    var timed_out = FALSE;

    var command_result_found;

    # did we run into a problem running last command? if so set this, so we don't
    # try running more
    var last_cmd_error = FALSE;

    # buffer received after initial login before shell starts waiting for input, include prompt
    var post_login_buffer = NULL;
    var cmd_prompt = NULL;

    # number of seconds of inactivity before we assume shell is ready for input
    var initial_inactivity_period = _BASIC_INITIAL_INACTIVITY_TIMEOUT;
    # timeout for sshrecv for initial wait to reach command prompt post login
    var initial_recv_timeout = 2;
    # default buffer inactivity timeout check
    var inactivity_timeout = _BASIC_DEFAULT_INACTIVITY_TIMEOUT;
    # default timeout for individual recv
    var recv_timeout = 2;
    # default timeout for cmd_timeout (no default)
    var cmd_timeout = _BASIC_DEFAULT_CMD_TIMEOUT;

    var settings;
    var objname = 'basic_shell_handler::';

    ##
    # Shell handler initialization caller
    # @category SSH
    ##
    function basic_shell_handler()
    {
      this.init();
    }

    ##
    # Shell handler init
    # @param settings
    # @category SSH
    ##
    public function init(settings)
    {
      if (!isnull(settings)) this.settings = settings;
      this.cmd_prompt = this.settings['cmd_prompt'];
      this.fresh_shell = TRUE;
      this.cur_buf = "";
      this.cur_buf_change_counter = 0;
      this.last_cmd_error = FALSE;
      this.command_result_found = FALSE;
    }

    public function set_cmd_prompt()
    {
      this.cmd_prompt = _FCT_ANON_ARGS[0];
    }

    ##
    # Returns carriage return opcode if the default shell is not ksh
    # else returns carriage return opcode and echo opcode
    # @return list of required pty opcodes
    # @category SSH
    ##
    public function get_pty_opts()
    {
      return make_array(PTY_OPT_OCRNL, mkdword(0, order:BYTE_ORDER_BIG_ENDIAN));
    }

    ##
    # get default size PTY chars
    # @return default size PTY chars
    # @category SSH
    ##
    public function get_pty_size_chars()
    {
      return DEFAULT_PTY_SIZE_CHARS;
    }

    ##
    # get default size PTY pixels
    # @return default size PTY pixels
    # @category SSH
    ##
    public function get_pty_size_pixels()
    {
      return DEFAULT_PTY_SIZE_PIXELS;
    }

    ##
    # get pty term
    # @return default pty term
    # @category SSH
    ##
    public function get_pty_term()
    {
      return DEFAULT_PTY_TERM;
    }

    ##
    # should we send / recv data to device without setting up a channel?
    # @return FALSE
    # @category SSH
    ##
    public function is_nosetup()
    {
      return FALSE;
    }

    ##
    # do we want to request a PTY on this device?
    # @return TRUE
    # @category SSH
    ##
    public function send_pty_req()
    {
      return TRUE;
    }

    ##
    # set priv escalation
    #
    # @param type escalation type
    # @param extra
    #
    # @category SSH
    ##
    public function set_priv_escalation(type, extra)
    {
      return NULL;
    }

    ##
    # unset priv escalation
    # @category SSH
    ##
    public function unset_priv_escalation()
    {
      return NULL;
    }

    ##
    # send command by line length
    #
    # @param cmd command to run
    # @param max_cmd_len max command length
    # @param channel channel
    #
    # @category SSH
    ##
    protected function send_command_by_line_length(cmd, max_cmd_len, &channel)
    {
      local_var subcmd_start, subcmd_end, subcmd;

      #Honor no limit for TAP testing
      if(TAP_MODE) max_cmd_len = 1 << 30;

      for ( subcmd_start = 0 ; subcmd_start < strlen(cmd) ; subcmd_start += max_cmd_len)
      {
        if ( strlen(cmd) <= subcmd_start + max_cmd_len - 1)
          subcmd_end = strlen(cmd) - 1;
        else
          subcmd_end = subcmd_start + max_cmd_len - 1;
        subcmd = substr(cmd, subcmd_start, subcmd_end);
        channel.window_send_data(data:subcmd);
      }
    }

    ##
    # check inactivity timeout function
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if timeout reached
    # @category SSH
    ##
    protected function check_inactivity_timeout(&channel)
    {
      var fn = objname + FUNCTION_NAME;
      var ch_label = 'channel ' + channel.local_channel + ']: ';
      this.timed_out = FALSE;
      if(channel.state == CHANNEL_STATE_CLOSED)
      {
        spad_log(message:fn + ' ' + ch_label + 'Channel is closed.');
        return TRUE;
      }
      if(channel.buf_change_counter != cur_buf_change_counter)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:ch_label +
          'Channel data buffer updated, resetting shell inactivity timer.\n');
        cur_buf_change_counter = channel.buf_change_counter;
        this.last_buffer_update_ts = unixtime();
      }
      else
      {
        if ((unixtime() - this.last_buffer_update_ts) >= this.timeout_check)
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:ch_label +
            'Reached recv timeout limit [' + this.timeout_check + 's].\n');
          this.timed_out = TRUE;
          return TRUE;
        }
      }
    }

    ##
    # function to check for buffer update or inactivity timeout
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if found
    # @category SSH
    ##
    public function on_channel_buffer_update_or_timeout(&channel)
    {
      if(channel.buf_change_counter != cur_buf_change_counter)
      {
        cur_buf_change_counter = channel.buf_change_counter;
        return TRUE;
      }
      return this.check_inactivity_timeout(channel:channel);
    }

    ##
    # check for prompt or inactivity timeout
    #
    # @param channel channel for ssh session
    #
    # @return TRUE
    # @category SSH
    ##
    public function at_prompt3_or_timeout(&channel)
    {
      if(this.at_cmd_prompt(buf:channel.data_buf, check_len:3)) return TRUE;
      return this.check_inactivity_timeout(channel:channel);
    }

    ##
    # check for prompt or inactivity timeout with 2 character prompt
    #
    # @param channel channel for ssh session
    #
    # @return TRUE
    # @category SSH
    ##
    public function at_prompt2_or_timeout(&channel)
    {
      if(this.at_cmd_prompt(buf:channel.data_buf, check_len:2)) return TRUE;
      return this.check_inactivity_timeout(channel:channel);
    }

    ##
    # check for buffer or inactivity timeout
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if found
    # @category SSH
    ##
    public function on_channel_buffer_inactivity(&channel)
    {
      if(this.fresh_shell && !isnull(this.post_login_buffer))
      {
        if(this.post_login_buffer >< channel.data_buf) return TRUE;
      }
      return this.check_inactivity_timeout(channel:channel);
    }

    ##
    # determine if we are at command prompt
    #
    # @param channel channel
    #
    # @return TRUE if found
    # @category SSH
    ##
    protected function at_cmd_prompt(buf, check_len)
    {
      if (isnull(cmd_prompt)) return FALSE;
      if (strlen(cmd_prompt) < check_len) return FALSE;
      var sub_prompt = substr(cmd_prompt, strlen(cmd_prompt) - check_len, strlen(cmd_prompt) - 1);
      if(strlen(buf) < check_len) return FALSE;
      var sub_buf = substr(buf, strlen(buf) - check_len, strlen(buf) - 1);
      if(sub_prompt == sub_buf)
        return TRUE;
    }

    ##
    # Set the shell timeouts
    #
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    #
    # @return NULL
    # @category SSH
    ##
    protected function set_timeouts(inactivity_timeout_min, cmd_timeout_min)
    {
      # Reset default timeouts
      this.inactivity_timeout = _BASIC_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _BASIC_DEFAULT_CMD_TIMEOUT;

      # If custom inactivity_timeout and cmd_timeout values are passed,
      # ensure the values in use meet or exceed passed values
      if (inactivity_timeout_min &&
          this.inactivity_timeout < inactivity_timeout_min)
        this.inactivity_timeout = inactivity_timeout_min;

      if (cmd_timeout_min &&
          this.cmd_timeout < cmd_timeout_min)
        this.cmd_timeout = cmd_timeout_min;

      return NULL;
    }

    ##
    # run given command
    #
    # @param channel channel for ssh session
    # @param command cmd to run
    # @param force_priv_escl force priv escalation flag
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    #
    # @return command result or NULL on failure
    # @category SSH
    ##
    public function run_command(&channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = objname + FUNCTION_NAME;
      var obj_ch_id = '[channel ' + channel.local_channel + ']: ';

      # Check shell state
      if(last_cmd_error)
      {
        return channel.session.set_error(obj_ch_id +
          'ERROR - shell is in unknown state from last interaction, ' +
          'no additional commands via this shell will be executed.');
      }

      # Initialize variables
      set_timeouts(inactivity_timeout_min:inactivity_timeout_min,
          cmd_timeout_min:cmd_timeout_min);

      var session = channel.session;
      var cmd_logger = new("sshlib::cmd_logger");
      this.command_result_found = FALSE;
      session.clear_cmd_error();

      cur_user = session.user;

      var item, kb_id, msg, cb;
      kb_id = SSH_LIB_KB_PREFIX + session.get_kb_connection_id();

      # Get command prompt

      var send_stty = FALSE;
      if(fresh_shell)
      {
        send_stty = TRUE;
        post_login_buffer = get_kb_blob(kb_id + "/post_login_buffer");
        this.cmd_prompt = get_kb_blob(kb_id + "/cmd_prompt");
        this.settings['cmd_prompt'] = this.cmd_prompt;
        session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "Getting prompt on fresh shell.");

        this.timeout_check = this.initial_inactivity_period;
        this.last_buffer_update_ts = unixtime();

        var check_prompt = FALSE;
        # see if we can look for prompt from previous login rather
        # than waiting for timeout
        if(strlen(cmd_prompt) >= 3)
        {
          # remove first found instance of prompt from previous post
          # login buffer
          var sub_prompt = substr(cmd_prompt, strlen(cmd_prompt) - 3, strlen(cmd_prompt) - 1);
          post_login_buffer -= sub_prompt;

          # if we don't find it again (e.g. in MOTD), it's probably ok
          # to look for last characters of prompt to recognize prompt
          if(sub_prompt >!< post_login_buffer)
            check_prompt = TRUE;
        }

        if(check_prompt)
        {
          session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using command prompt from previous login to find cmd prompt.");
          channel.set_shell_handler(this);
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @basic_shell_handler_at_prompt3_or_timeout,
            channel        : channel,
            timeout        : initial_recv_timeout
          );
        }
        else
        {
          session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
            "Waiting for inactivity period to find command prompt.");
          channel.set_shell_handler(this);
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @basic_shell_handler_on_channel_buffer_inactivity,
            channel        : channel,
            timeout        : initial_recv_timeout);
        }
        if(empty_or_null(channel.data_buf))
        {
          if(this.timed_out)
            return session.set_cmd_error(obj_ch_id +
              "Timed out waiting for data from server after opening shell.");

          last_cmd_error = TRUE;
          return session.set_cmd_error(obj_ch_id +
            "No data received from server after opening shell.");
        }
        if("password has expired" >< channel.data_buf)
        {
          session.set_error(obj_ch_id +
            "Account password has expired.");
          last_cmd_error = TRUE;
          return NULL;
        }
        if(channel.state == CHANNEL_STATE_CLOSED)
        {
          session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            'Channel is closed.');
          this.last_cmd_error = TRUE;
          return NULL;
        }

        post_login_buffer = channel.data_buf;

        if(isnull(get_kb_item(kb_id + "/post_login_buffer")))
          set_kb_blob(name:kb_id + "/post_login_buffer", value:post_login_buffer);

        channel.clear_data_buf();
        fresh_shell = FALSE;

        var lines = split(post_login_buffer, sep:'\n', keep:FALSE);
        cmd_prompt = lines[max_index(lines)-1];

        if(isnull(get_kb_item(kb_id + "/cmd_prompt")))
          set_kb_blob(name:kb_id + "/cmd_prompt", value:cmd_prompt);

        session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
          'Detected command prompt  "' + cmd_prompt + '".');

        if(strlen(cmd_prompt) == 0)
        {
          session.set_cmd_error(obj_ch_id +
            "Unable to detect command prompt on shell.");
          last_cmd_error = TRUE;
          return NULL;
        }
      }

      if(channel.state == CHANNEL_STATE_CLOSED)
      {
        this.last_cmd_error = TRUE;
        return channel_closed_return_null(fn:fn, session:session, channel:channel);
      }

      # Run command and receive response, sending password as prompted
      session.reset_cmd_interrupted();

      session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
        "Sending command: " + command);

      # Use a 256 character line length limit for HP-UX and SunOS
      this.send_command_by_line_length(cmd:command + '\n', max_cmd_len:256, channel:channel);

      this.last_buffer_update_ts = unixtime();
      this.timeout_check = inactivity_timeout;
      channel.set_shell_handler(this);
      session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @basic_shell_handler_at_prompt2_or_timeout,
        channel        : channel,
        timeout        : recv_timeout,
        cmd_timeout    : cmd_timeout
      );

      if(channel.state == CHANNEL_STATE_CLOSED)
      {
        this.last_cmd_error = TRUE;
        return channel_closed_return_null(fn:fn, session:session, channel:channel);
      }

      if(empty_or_null(channel.data_buf))
      {
        if(!this.timed_out)
        {
          msg = obj_ch_id + "No data received in response to command.";
          last_cmd_error = TRUE;
        }
        else
          msg = obj_ch_id + "Timed out waiting for command result. No data received.";

        channel.session.set_cmd_error(msg);
        return cmd_logger.log_error(
          cmd                : command,
          error              : session.cmd_error,
          user               : session.user
        );
      }

      var cmd_res = channel.data_buf;

      var check_len = 3;
      if(strlen(cmd_prompt) < 3) check_len = strlen(cmd_prompt);

      # Unless we've previously identified that we can't reach the
      # command prompt after executing a command,
      # recv up to two more times until we get to cmd prompt if we
      # aren't already
      var prompt_timeout_kb = SSH_LIB_KB_PREFIX + "cmd_prompt_timeouts";
      if (get_kb_item(prompt_timeout_kb) >= 3)
      {
        session.set_cmd_error(obj_ch_id +
          'Returning to command prompt previously failed. Not looking' +
          ' for command prompt.');
        last_cmd_error = TRUE;
      }
      else
      {
        cur_buf_change_counter = channel.buf_change_counter;
        this.last_buffer_update_ts = unixtime();

        var i = 0;
        while(!at_cmd_prompt(buf:channel.data_buf, check_len:check_len))
        {
          if(i > 2) break;
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @basic_shell_handler_on_channel_buffer_update_or_timeout,
            channel        : channel,
            timeout        : recv_timeout
          );
          i++;
        }

        if(at_cmd_prompt(buf:channel.data_buf, check_len:check_len))
          session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            'Back at command prompt.');

        if(!at_cmd_prompt(buf:channel.data_buf, check_len:check_len))
        {
          last_cmd_error = TRUE;
          var prompt_timeout_count = get_kb_item(prompt_timeout_kb);
          if (!isnull(prompt_timeout_count))
            replace_kb_item(name:prompt_timeout_kb, value:prompt_timeout_count+1);
          else set_kb_item(name:prompt_timeout_kb, value:1);
          session.set_cmd_error(obj_ch_id +
            "ERROR - unable to get back to command prompt.");
        }
      }

      channel.clear_data_buf();

      if(!empty_or_null(cmd_res))
      {
        cmd_res = str_replace(find:command, replace:'', string:cmd_res);
        if (cmd_prompt)
          cmd_res = str_replace(find:cmd_prompt, replace:'', string:cmd_res);
        cmd_res = strip(cmd_res);
      }

      session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
        "Extracted cmd result: " + cmd_res);

      cmd_logger.add(
        cmd         : command,
        response    : cmd_res,
        error       : session.cmd_error,
        user        : session.user
      );

      if(!empty_or_null(cmd_res)) return cmd_res;
      else return NULL;
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
        case "send_command_by_line_length":
          var old_mode = TAP_MODE;
          TAP_MODE = FALSE;
          var channel = args["channel"];
          var result = send_command_by_line_length(cmd:args["cmd"],
                                                   max_cmd_len:args["max_cmd_len"],
                                                   channel:channel);
          TAP_MODE = old_mode;
          return result;
        default:
          spad_log(message:fn + ': "'+name+'()" is not yet implemented for testing with this function');
          return NULL;
      }
    }
  }
}
