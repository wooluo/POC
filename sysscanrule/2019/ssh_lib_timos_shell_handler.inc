#TRUSTED 16555b0c0d7bdfcdd10e523b4e3391359ebf2255283ee3158600e990e4111e41c260996e387a0d268bb2656cf7db1c86c94932d3cced3dd411c418ed717cbfe587b317b72d6659606c1ee063f35bece166f0f292a61716a455eb7f50b3b8e0adb58b1c370b026608ee64094ee076318b01440b36044cda986a28496dab12a3ad7e8d4b407440778b51f351f9ff0e8ea62996f62d5a47272485f2c58ecd3b5bb9f0107eb9c6e092f4df2c2b8124bff185aa71d336e3cd809207cbd1a4849e84944084a474956e7bfedc24715472eb8460ad7db7c38033abab0e44e1fafaf27071fd13e2b8a74c41e15f582ca32c3517ca95f7b84cde0c3735792973e4c80bad43bc9ad667612ab64a772de269907454807a03cd345a9561e2f3dadb2b640faca0cdd2bab1fe0b8c7887614b4027f839aa4661cf4fb3851a393dd62ac7d78217354209d35d0e4abc68ab0d31015e0f42543d41cf162980a18bf7690b5133e4675202ab330bd4e66cf47c69fa8a2c1c7c4bed1bf5f6c0db4af1a81a0161bbfced57f8ef04238b90b36a95dcd13c11f4a414dd71c608c60c9d36de187c8d6e70e91206381e459d30ec12b3eaa015bb74201f04898a3147200ea7a255d07b741e02a74192765e99cb9bfac26c5482752a6937051606609329ca3402bb181ea1d8846c592d948efdb1fe4deb4c00d96ac5d0d7b27e3ff0d460e362a0ec8c59325e21e7

#
# (C) WebRAY Network Security, Inc.
#

namespace sshlib
{

  # all timeouts are controlled by a timer with 1s resolution
  # for that reason keep the shell timeout sufficiently beyond
  # the timer resolution (10s = 10x resolution)
  global_var _TIMOS_DEFAULT_CMD_TIMEOUT = 10;
  global_var _TIMOS_DEFAULT_INACTIVITY_TIMEOUT = 10;
  global_var _TIMOS_INITIAL_INACTIVITY_TIMEOUT = 10;

  # a space is included in shell prompt
  global_var _TIMOS_DEFAULT_PROMPT = "# ";

  # cmd_states
  # _TIMOS_CMD_STATE_SEND_REQ: ready to send a command to device
  # _TIMOS_CMD_STATE_RECV_RSP: ready to recv a response from device
  # _TIMOS_CMD_STATE_AT_PROMPT: found command prompt in response
  global_var _TIMOS_CMD_STATE_SEND_REQ = 0;
  global_var _TIMOS_CMD_STATE_RECV_RSP = 1;
  global_var _TIMOS_CMD_STATE_AT_PROMPT = 2;
  global_var _TIMOS_CMD_STATE_SEND_ESCL_REQ = 3;
  global_var _TIMOS_CMD_STATE_RECV_ESCL_RSP = 4;
  global_var _TIMOS_CMD_STATE_GET_PROMPT = 5;

  # a space is included in shell prompt
  global_var _TIMOS_DEFAULT_ENABLE_PROMPT = "Password: ";

  ### RECV_UNTIL CALLBACKS ###

  # By default, the CLI command prompt indicates the device being
  # accessed and the current CLI context. For example, the prompt:
  # A:ALA-1>config>router>if#
  # indicates the active context, the user is on the device with
  # hostname ALA-1 in the configure>router>interface context. In the
  # prompt, the separator used between contexts is the “>” symbol.
  #
  # At the end of the prompt, there is either a pound sign (“#”) or a
  # dollar sign (“$”). A “#” at the end of the prompt indicates the
  # context is an existing context. A “$” at the end of the prompt
  # indicates the context has been newly created. New contexts are
  # newly created for logical entities when the user first navigates
  # into the context.
  #
  # Since there can be a large number of sublevels in the CLI, the
  # environment command reduced- prompt no of nodes in prompt allows
  # the user to control the number of levels displayed in the prompt.
  #
  # All special characters (#, $, etc.) must be enclosed within double
  # quotes, otherwise it is seen as a comment character and all
  # characters on the command line following the # are ignored. For
  # example:
  #          *A:ALA-1>config>router# interface "primary#1"
  #
  # When changes are made to the configuration file a “*” appears in
  # the prompt string (*A:ALA-1) indicating that the changes have not
  # been saved. When an admin save command is executed the “*”
  # disappears. This behavior is controlled in the saved-ind-prompt
  # command in the environment context.
  #
  function timos_shell_handler_incoming_data_cb( session, channel )
  {
    var fn = 'timos_shell_handler_incoming_data_cb';
    # does a channel exist?
    if ( isnull(channel) )
    {
      # no channel so there is no data buffer to check
      return FALSE;
    }
    # does channel have a valid data buffer?
    if ( isnull(channel.data_buf) )
    {
      # no data buffer to check
      return FALSE;
    }
    if ( isnull(channel.shell_handler ) )
    {
      # no shell handler on channel, oops can't proceed
      return FALSE;
    }
    var sh = channel.shell_handler;
    var cmd_state = sh.cmd_state;
    var cmd_last = sh.cmd_last;
    var buf_length = strlen( channel.data_buf );

    # Decision is based on command state
    if ( cmd_state == _TIMOS_CMD_STATE_SEND_REQ ||
         cmd_state == _TIMOS_CMD_STATE_SEND_ESCL_REQ )
    {
      # Sent command to device, waiting echo back of last command
      if ( buf_length >= strlen(cmd_last) )
      {
        var last = substr( channel.data_buf, buf_length - strlen(cmd_last) );
        if ( last == cmd_last )
        {
          if ( cmd_state == _TIMOS_CMD_STATE_SEND_ESCL_REQ )
            sh.set_cmd_state( new_cmd_state:_TIMOS_CMD_STATE_RECV_ESCL_RSP );
          else
            sh.set_cmd_state( new_cmd_state:_TIMOS_CMD_STATE_RECV_RSP );
          channel.session.dbg_log(fn:fn, level:DEBUG2, message: "cmd_state:_TIMOS_CMD_STATE_RECV_RSP(" + sh.cmd_state + ")" );
          channel.clear_data_buf();
          channel.window_send_data(data:'\n');
        }
      }
    }
    else if ( cmd_state == _TIMOS_CMD_STATE_RECV_ESCL_RSP )
    {
      var cmd_enable_prompt = sh.cmd_enable_prompt;
      var cmd_enable_prompt_length = strlen(cmd_enable_prompt);
      # does buffer have enough characters to include prompt?
      if ( buf_length > cmd_enable_prompt_length )
      {
        # buffer has enough characters, perform prompt test
        var maybe_password_prompt = substr( channel.data_buf, buf_length - cmd_enable_prompt_length );
        # buffer include password prompt?
        if ( maybe_password_prompt == cmd_enable_prompt )
        {
          # last characters in buffer match prompt, found password prompt
          channel.session.dbg_log(fn:fn, level:DEBUG2, message: "found password prompt");
          channel.clear_data_buf();
          var cmd_enable_password = sh.priv_escalation_extra['enable_pass'];
          channel.session.set_redact( TRUE );
          channel.window_send_data(data:cmd_enable_password + '\n' );
          channel.session.set_redact( FALSE );
          sh.set_cmd_state( new_cmd_state: _TIMOS_CMD_STATE_GET_PROMPT);

          return FALSE;
        }
      }
    }
    else
    {
      var cmd_prompt = sh.cmd_prompt;
      var cmd_prompt_length = strlen(cmd_prompt);
      # does buffer have enough characters to include prompt?
      if ( buf_length > cmd_prompt_length )
      {
        # buffer has enough characters, perform prompt test
        var maybe_prompt = substr( channel.data_buf, buf_length - cmd_prompt_length );
        # buffer include prompt?
        if ( maybe_prompt == cmd_prompt )
        {
          # last characters in buffer match prompt, found prompt
          sh.set_cmd_state( new_cmd_state:_TIMOS_CMD_STATE_AT_PROMPT );
          channel.session.dbg_log(fn:fn, level:DEBUG2, message: "cmd_state:_TIMOS_CMD_STATE_AT_PROMPT(" + sh.cmd_state + ")" );
          return TRUE;
        }
      }
    }
    return sh.check_inactivity_timeout(channel:channel);
  }
  ### END RECV_UNTIL CALLBACKS ###

  # timos shell handler
  object timos_shell_handler
  {
    var settings;
    var cmd_state;
    var cmd_last;
    var cmd_prompt;
    var cmd_timeout;
    var initial_inactivity_timeout;
    var inactivity_timeout;
    var cmd_enable_password;
    var cmd_enable_prompt;
    var last_md5;
    var last_buffer_update_ts;
    # did we run into a problem running last command? if so set this
    var last_cmd_error = FALSE;
    var priv_escalation_type;
    var priv_escalation_extra;
    var fresh_shell = TRUE;
    var escalated_shell = FALSE;

    function timos_shell_handler()
    {
      this.init();
    }

    public function init(settings)
    {
      this.cmd_last = "";
      this.cmd_prompt = _TIMOS_DEFAULT_PROMPT;
      this.cmd_timeout = _TIMOS_DEFAULT_CMD_TIMEOUT;
      this.initial_inactivity_timeout = _TIMOS_INITIAL_INACTIVITY_TIMEOUT;
      this.inactivity_timeout = _TIMOS_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_enable_prompt = _TIMOS_DEFAULT_ENABLE_PROMPT;
      this.cmd_state = _TIMOS_CMD_STATE_SEND_REQ;
      this.last_cmd_error = FALSE;
      if (!isnull(settings))
      {
        this.settings = settings;
        if ( !isnull(this.settings['cmd_prompt']) ) this.cmd_prompt = this.settings['cmd_prompt'];
        if ( !isnull(this.settings['cmd_timeout']) ) this.cmd_timeout = this.settings['cmd_timeout'];
        if ( !isnull(this.settings['cmd_enable_prompt']) ) this.cmd_enable_prompt = this.settings['cmd_enable_prompt'];
        if ( !isnull(this.settings['priv_escalation_type']) ) this.priv_escalation_type = this.settings['priv_escalation_type'];
        if ( !isnull(this.settings['priv_escalation_extra']) ) this.priv_escalation_extra = this.settings['priv_escalation_extra'];
      }
    }

    # should we send / recv data to device without setting up a channel?
    public function is_nosetup()
    {
      return FALSE;
    }

    # do we want to request a PTY on this device?
    public function send_pty_req()
    {
      return FALSE;
    }

    public function check_inactivity_timeout(channel)
    {
      var fn = 'timos_shell_handler.check_inactivity_timeout';
      if ( channel && channel.data_buf && strlen(channel.data_buf) > 0 )
      {
        var new_md5 = MD5( channel.data_buf );
        if ( this.last_md5 != new_md5 )
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:'timos_shell_handler [channel ' + channel.local_channel + ']: Channel data buffer updated, resetting shell inactivity timer.\n');
          this.last_md5 = new_md5;
          this.last_buffer_update_ts = unixtime();
          return FALSE;
        }
      }
      if ((unixtime() - this.last_buffer_update_ts) >= this.inactivity_timeout)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:'timos_shell_handler [channel ' + channel.local_channel + ']: reached timeout limit [' + this.inactivity_timeout + 's].\n');
        return TRUE;
      }
      return FALSE;
    }

    public function set_cmd_state(new_cmd_state)
    {
      this.cmd_state = new_cmd_state;
    }

    public function run_command(channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = 'timos_shell_handler.run_command';
      var obj_ch_id = 'timos_shell_handler [channel '+channel.local_channel+']: ';

      #Channel objects clean up and delete their sessions.
      #Keep a local reference so that we can log errors, etc.
      var sess = channel.session;

      if ( isnull(channel) )
      {
        return NULL;
      }
      if ( isnull(command) )
      {
        return NULL;
      }

      if( this.last_cmd_error )
      {
        sess.set_error(obj_ch_id +
          'ERROR - shell is in unknown state from last interaction, ' +
          'no additional commands via this shell will be executed.');
        return NULL;
      }

      # are there multiple input commands to process?
      if ( typeof(command) == "array" )
      {
        # there are multiple input commands to process
        # collect the concatenated results into variable total_res
        var total_res = NULL;
        # process each command provided
        var i = 0;
        for ( i = 0 ; i < max_index(command) ; i++ )
        {
          # concatenate the results of each command together
          total_res += run_command(
            channel                : channel,
            command                : command[i],
            force_priv_escl        : force_priv_escl,
            cmd_timeout_min        : cmd_timeout_min,
            inactivity_timeout_min : inactivity_timeout_min);
          # did an error occur?
          if ( sess.error )
          {
            # an error occured, stop processing and return result
            break;
          }
        }
        return total_res;
      }

      # Reset default timeouts
      this.inactivity_timeout = _TIMOS_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _TIMOS_DEFAULT_CMD_TIMEOUT;

      # If custom inactivity_timeout and cmd_timeout values are passed,
      # ensure the values in use meet or exceed passed values
      if (inactivity_timeout_min &&
          this.inactivity_timeout < inactivity_timeout_min)
        this.inactivity_timeout = inactivity_timeout_min;

      if (cmd_timeout_min &&
          this.cmd_timeout < cmd_timeout_min)
        this.cmd_timeout = cmd_timeout_min;

      # Find command prompt if fresh shell
      var kb_id = sess.get_kb_connection_id();
      if (fresh_shell)
      {
        var post_login_buffer = get_kb_blob(kb_id + "/post_login_buffer");
        var tmp_prompt = get_kb_blob(kb_id + "/cmd_prompt");
        sess.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "Getting prompt on fresh shell.");

        var check_prompt = FALSE;
        # see if we can look for prompt from previous login rather
        # than waiting for timeout
        if(strlen(tmp_prompt) >= 3)
        {
          # remove first found instance of prompt from previous post
          # login buffer
          var sub_prompt = substr(tmp_prompt, strlen(tmp_prompt) - 3, strlen(tmp_prompt) - 1);
          post_login_buffer -= sub_prompt;

          # if we don't find it again (e.g. in MOTD), it's probably ok
          # to look for last characters of prompt to recognize prompt
          if(sub_prompt >!< post_login_buffer)
          {
            this.cmd_prompt = tmp_prompt;
            this.settings['cmd_prompt'] = this.cmd_prompt;
            check_prompt = TRUE;
          }
        }

        if(check_prompt)
        {
          sess.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using command prompt from previous login to find cmd prompt.");
        }
        else
        {
          sess.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using default prompt to find command prompt.");
        }

        this.cmd_state = _TIMOS_CMD_STATE_GET_PROMPT;
        this.last_buffer_update_ts = unixtime();
        sess.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          check_callback : @timos_shell_handler_incoming_data_cb,
          channel        : channel,
          cmd_timeout    : this.initial_inactivity_timeout
        );

        if(empty_or_null(channel.data_buf))
        {
          last_cmd_error = TRUE;
          sess.set_cmd_error(obj_ch_id +
            "No data received from server after opening shell.");
          return NULL;
        }

        post_login_buffer = channel.data_buf;
        if(isnull(get_kb_item(kb_id + "/post_login_buffer")))
          set_kb_blob(name:kb_id + "/post_login_buffer", value:post_login_buffer);
        channel.clear_data_buf();
        fresh_shell = FALSE;

        var lines = split(post_login_buffer, sep:'\n', keep:FALSE);
        this.cmd_prompt = lines[max_index(lines)-1];

        if(isnull(get_kb_item(kb_id + "/cmd_prompt")))
          set_kb_blob(name:kb_id + "/cmd_prompt", value:cmd_prompt);

        sess.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
          'Detected command prompt  "' + this.cmd_prompt + '".');

        if(strlen(this.cmd_prompt) == 0)
        {
          sess.set_cmd_error(obj_ch_id +
            "Unable to detect command prompt on shell.");
          last_cmd_error = TRUE;
          return NULL;
        }

        this.settings['cmd_prompt'] = this.cmd_prompt;
      }

      # Determine if privilege escalation should be used
      var use_priv_escl = FALSE;
      var priv_escl_failed = FALSE;
      var tmp_bad_escl_kb =
        "tmp/" + kb_id + "/ssh_bad_priv_escl/" + this.priv_escalation_type;
      var escl_hexstr = hexstr(MD5(serialize(this.priv_escalation_extra)));

      if ( this.priv_escalation_type == "cisco_enable" )
      {
        if ( get_kb_item(tmp_bad_escl_kb) == escl_hexstr )
        {
          sess.set_error(obj_ch_id + "Not using privilege " +
            "escalation due to failure in a previous session.");
        }
        else
        {
          use_priv_escl = TRUE;
        }
      }

      # Escalate shell using 'enable-admin' if necessary
      if ( use_priv_escl && !this.escalated_shell )
      {
        this.cmd_last = 'enable-admin';
        sess.dbg_log(fn:fn, level:DEBUG2, message: obj_ch_id +
          "Sending command 'enable-admin' to escalate shell.");
        channel.clear_data_buf();
        this.last_buffer_update_ts = unixtime();
        this.cmd_state = _TIMOS_CMD_STATE_SEND_ESCL_REQ;
        sess.dbg_log(fn:fn, level:DEBUG2, message:
          "cmd_state:_TIMOS_CMD_STATE_SEND_ESCL_REQ(" + this.cmd_state + ")" );
        channel.window_send_data(data:cmd_last);
        sess.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          check_callback : @timos_shell_handler_incoming_data_cb,
          channel        : channel,
          cmd_timeout    : this.cmd_timeout
        );

        # Check response for failure or success
        if ( channel.data_buf )
        {
          if ( "Invalid password" >< channel.data_buf )
          {
            sess.set_cmd_error(
              remove_cmd_prompt(cmd_res:channel.data_buf));
            sess.set_cmd_error(obj_ch_id +
              "Privilege escalation appears to have failed. Removing " +
              "privilege escalation from credential set.");
            replace_kb_item(name:tmp_bad_escl_kb, value:escl_hexstr);
            priv_escl_failed = TRUE;
          }
          else if ( "Already in admin mode" >< channel.data_buf )
          {
            sess.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
              "Shell is already in admin mode.");
            this.escalated_shell = TRUE;
          }
        }

        if ( this.cmd_state != _TIMOS_CMD_STATE_AT_PROMPT )
        {
          sess.set_cmd_error(obj_ch_id +
            "Unable to return to command prompt after attempting to " +
            "escalate privileges.");
          this.last_cmd_error = TRUE;
          return NULL;
        }

        # TiMOS returns to the command prompt without confirmation if
        # enable-admin is successful, so send it again to confirm
        if (!this.escalated_shell && !priv_escl_failed)
        {
          sess.dbg_log(fn:fn, level:DEBUG2, message: obj_ch_id +
            "Sending command 'enable-admin' again to confirm escalation " +
            "was successful.");
          channel.clear_data_buf();
          this.last_buffer_update_ts = unixtime();
          this.cmd_state = _TIMOS_CMD_STATE_SEND_REQ;
          channel.window_send_data(data:cmd_last);
          sess.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @timos_shell_handler_incoming_data_cb,
            channel        : channel,
            cmd_timeout    : this.cmd_timeout
          );

          if ( channel.data_buf &&
               "Already in admin mode" >< channel.data_buf )
          {
            sess.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
              "Successfully enabled admin mode.");
            this.escalated_shell = TRUE;
          }
          else
          {
            sess.set_cmd_error(obj_ch_id +
              "Unable to confirm if admin mode was successfully enabled.");
          }

          if ( this.cmd_state != _TIMOS_CMD_STATE_AT_PROMPT )
          {
            sess.set_cmd_error(obj_ch_id +
              "Unable to return to command prompt after attempting to " +
              "escalate privileges.");
            this.last_cmd_error = TRUE;
            return NULL;
          }
        }
      }

      this.cmd_last = command;
      sess.reset_cmd_interrupted();

      sess.dbg_log(fn:fn, level:DEBUG2, message: "sending command: " + cmd_last);
      channel.clear_data_buf();
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _TIMOS_CMD_STATE_SEND_REQ;
      sess.dbg_log(fn:fn, level:DEBUG2, message: "cmd_state:_TIMOS_CMD_STATE_SEND_REQ(" + this.cmd_state + ")" );
      channel.window_send_data(data:cmd_last);
      sess.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @timos_shell_handler_incoming_data_cb,
        channel        : channel,
        cmd_timeout    : this.cmd_timeout
      );
      var msg = "Timed out waiting for data from server after opening shell.";
      if ((unixtime() - this.last_buffer_update_ts) >= this.cmd_timeout)
      {
        if ( this.cmd_state == _TIMOS_CMD_STATE_SEND_REQ )
        {
          msg = "Unable to verify command on shell.";
        }
        else if ( this.cmd_state == _TIMOS_CMD_STATE_RECV_RSP )
        {
          msg = "Timed out waiting for command result.";
        }
        this.last_cmd_error = TRUE;
        sess.dbg_log(fn:fn, level:DEBUG2, message: msg );
        return sess.set_cmd_error( msg );
      }
      if(channel && channel.data_buf )
      {
        var ret = channel.data_buf;
        # MINOR: CLI Invalid password..
        if ( "MINOR: CLI Command not allowed for this user" >< ret )
        {
          # Command sent indicated enable-admin needs to run first
          # let caller know this error occured
          msg = "Error: CLI Command not allowed for this user.";
          this.last_cmd_error = TRUE;
          sess.dbg_log(fn:fn, level:DEBUG2, message: msg );
          return sess.set_cmd_error( msg );
        }
        else if ( "Error: Bad command." >< ret )
        {
          msg = "Error: Bad command.";
          this.last_cmd_error = TRUE;
          sess.dbg_log(fn:fn, level:DEBUG2, message: msg );
          return sess.set_cmd_error( msg );
        }
        # IGNORE "MINOR: CLI Already in admin mode." (not an error)
        # already in admin mode response comes after enable-admin is
        # sent twice, this device supports both success and failure
        # indications of privilege modes that way

        if ( this.cmd_state != _TIMOS_CMD_STATE_AT_PROMPT )
        {
          sess.set_cmd_error(obj_ch_id +
            "Unable to return to command prompt after attempting to " +
            "escalate privileges.");
          this.last_cmd_error = TRUE;
        }

        return chomp(string_reverse(chomp(string_reverse(remove_cmd_prompt(cmd_res:ret)))));
      }
      return NULL;
    }

    public function set_priv_escalation(type, extra)
    {
      this.priv_escalation_type = type;
      this.priv_escalation_extra = extra;
      this.settings['priv_escalation_type'] = type;
      this.settings['priv_escalation_extra'] = extra;
    }

    public function unset_priv_escalation()
    {
      this.priv_escalation_type = NULL;
      this.priv_escalation_extra = NULL;
      this.settings['priv_escalation_type'] = NULL;
      this.settings['priv_escalation_extra'] = NULL;
    }

    public function remove_cmd_prompt(cmd_res)
    {
      var idx = stridx(cmd_res, this.cmd_prompt);
      return substr(cmd_res, 0, idx-1);
    }
  }
}
