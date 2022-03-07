#TRUSTED 7736d48c7e47414705bfc4ea54d5c2f3207c102240d97ea02c5c1d5dc6f7aefe95e7f77cdd7ea5d9ea751ed719ab205b7bf3861d711c85fe3c39416e3e41ae8a637f61c77b5b06de56876392d783601be33a2aa8075f0803bfe2a38b951abaaf04e69ccd3fec059ffb42bd0dc8e07422f0ee10ccd1796beac8e6a71057419afe22322ff9b620bcdaeb49d47e2dfdb87b70fc39670cdc8b531af14580e3f8cd4f3ec9d4be5e412310f7c1c85c4745bad67e0666e2e582aaa38ca4e6b53f7cea827818da791639b42b2328df1a8aea65679e7a4aab331c255dd7d0d33cdf3e3f1d25e2e67ba13823b2f51e2b23c2a4fe29c0d4bbeac893dc71bf184fb6a444a5a3b27e87ae174f5ef823971b8ee01e141e0538493534f042b2570dc458cf29083b44143fe563526b9c653da645bc641b54ff1bb4954deb1491d202a517bb2992490f1eaf1e2177708fd2cd35f08340237a69b1260542e30b16dcefef50c9c21f6dc3df49e04c105d13b042fc72104c744859cf85220284bc5e7811ab65a3d47558733835b1e4e0632e6ab842f4e005794933dcbe002547f33012ba818c458909a9c083bdf60f70b7871bdd129da932b5fd1cec6b4a2a3023be30b2546d5c7308863e8171c79f5cfd0f8517828cca15af4a58f607e1eddaa87644c91616ff4972f040c316318eb92dd0af238b90aea0fa11389e706b23a3308b3a60ea6b4e59161f
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.2


namespace sshlib
{
  # all timeouts are controlled by a timer with 1s resolution
  # for that reason keep the shell timeout sufficiently beyond
  # the timer resolution (10s = 10x resolution)
  global_var _NETAPP_DEFAULT_CMD_TIMEOUT = 60;
  global_var _NETAPP_DEFAULT_INACTIVITY_TIMEOUT = 45;
  global_var _NETAPP_INITIAL_INACTIVITY_TIMEOUT = 2;

  # a space is included in shell prompt
  global_var _NETAPP_DEFAULT_PROMPT = "> ";

  # cmd_states
  # _NETAPP_CMD_STATE_SEND_REQ: ready to send a command to device
  # _NETAPP_CMD_STATE_RECV_RSP: ready to recv a response from device
  # _NETAPP_CMD_STATE_AT_PROMPT: found command prompt in response
  global_var _NETAPP_CMD_STATE_SEND_REQ = 0;
  global_var _NETAPP_CMD_STATE_RECV_RSP = 1;
  global_var _NETAPP_CMD_STATE_AT_PROMPT = 2;
  global_var _NETAPP_CMD_STATE_SEND_ESCL_REQ = 3;
  global_var _NETAPP_CMD_STATE_RECV_ESCL_RSP = 4;
  global_var _NETAPP_CMD_STATE_GET_PROMPT = 5;


  global_var _NETAPP_DEFAULT_ENABLE_PROMPT = "Password:";


  function netapp_shell_handler_incoming_data_timeout_cb(session, channel)
  {
    var fn = 'netapp_shell_handler_incoming_data_timeout_cb';
    var sh = channel.shell_handler;
    var obj_ch_id = 'netapp_shell_handler [channel '+channel.local_channel+']: ';
    if( isnull(channel) || isnull(channel.session))
    {
      if(!isnull(session))
        session.dbg_log(fn:fn, level:DEBUG1, message:"Channel does not exist");
      return FALSE;
    }
    channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "_NETAPP_STATE : " + sh.cmd_state);
    return sh.check_inactivity_timeout(channel:channel);
  }


  function netapp_shell_handler_incoming_data_timeout_or_prompt_cb( session, channel )
  {
    var fn = 'netapp_shell_handler_incoming_data_timeout_or_prompt_cb';
    var obj_ch_id = 'netapp_shell_handler [channel '+channel.local_channel+']: ';
    var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
    var last_line = lines[max_index(lines)-1];
    # does a channel exist?
    if ( isnull(channel) ) 
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:"Channel does not exist");
      return FALSE;
    }
    # does channel have a valid data buffer?
    if ( isnull(channel.data_buf) )
    {
      channel.session.dbg_log(fn:fn, level:DEBUG1, message:"Channel.data_buf does not exist");
      return FALSE;
    }
    if ( isnull(channel.shell_handler ) )
    {
      channel.session.dbg_log(fn:fn, level:DEBUG1, message:"Shell handler does not exist");
      return FALSE;
    }
    var sh = channel.shell_handler;
    channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "_NETAPP_STATE : " + sh.cmd_state);

    return sh.at_prompt_or_timeout(channel:channel);

  }


  object netapp_shell_handler
  {
    var settings;
    var cmd_state;
    var cmd_last;
    var cmd_prompt;
    var cmd_timeout;
    var inactivity_timeout;
    var cmd_enable_password;
    var cmd_enable_prompt;
    var last_md5;
    var last_buffer_update_ts;
    var last_cmd_error = FALSE;
    var priv_escalation_type;
    var priv_escalation_extra;
    var fresh_shell = TRUE;
    var timed_out = FALSE;
    var escalated_shell = FALSE;
    var least_privilege = FALSE;
    var previous_prompt;
    var priv_escl_failed = FALSE;
    var new_channel_needs_new_connection = TRUE;

    function netapp_shell_handler()
    {
      settings = _FCT_ANON_ARGS[0];
      this.init(settings:settings);
    }

    public function init(settings)
    {
      this.cmd_last = "";
      this.cmd_prompt = _NETAPP_DEFAULT_PROMPT;
      this.cmd_timeout = _NETAPP_DEFAULT_CMD_TIMEOUT;
      this.inactivity_timeout = _NETAPP_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_enable_prompt = _NETAPP_DEFAULT_ENABLE_PROMPT;
      this.cmd_state = _NETAPP_CMD_STATE_SEND_REQ;
      this.last_cmd_error = FALSE;
      this.priv_escalation_type = NULL;
      this.last_buffer_update_ts = unixtime();
      if (!isnull(settings))
      {
        this.settings = settings;
        if ( !isnull(this.settings['cmd_prompt']) )
          this.cmd_prompt = this.settings['cmd_prompt'];
        if ( !isnull(this.settings['cmd_prompt']) )
          this.previous_prompt = this.settings['cmd_prompt'];
        if ( !isnull(this.settings['cmd_timeout']) )
          this.cmd_timeout = this.settings['cmd_timeout'];
        if ( !isnull(this.settings['least_privilege']) )
          this.least_privilege = this.settings['least_privilege'];
        if ( !isnull(this.settings['cmd_enable_prompt']) )
          this.cmd_enable_prompt = this.settings['cmd_enable_prompt'];
        if ( !isnull(this.settings['priv_escalation_type']) )
          this.priv_escalation_type = this.settings['priv_escalation_type'];
        if ( !isnull(this.settings['priv_escalation_extra']) )
          this.priv_escalation_extra = this.settings['priv_escalation_extra'];
      }
      else this.settings = make_array();
    }

    # This function is not implemented or supported by the NetApp Shell
    public function get_supported_escalation_method()
    {
      return NULL;
    }

    # This function is not implemented or supported by the NetApp Shell
    public function get_least_privilege()
    {
      return NULL;
    }

    public function get_cmd_prompt()
    {
      return this.cmd_prompt;
    }

    public function get_pty_opts()
    {
      return make_array(PTY_OPT_OCRNL, mkdword(0, order:BYTE_ORDER_BIG_ENDIAN));
    }

    public function get_pty_size_chars()
    {
      return make_list(200, 200);
    }

    public function get_pty_size_pixels()
    {
      return DEFAULT_PTY_SIZE_PIXELS;
    }

    public function get_pty_term()
    {
      return DEFAULT_PTY_TERM;
    }

    public function is_nosetup()
    {
      return FALSE;
    }

    public function send_pty_req()
    {
      return TRUE;
    }

    public function set_last_cmd_error()
    {
      this.last_cmd_error = _FCT_ANON_ARGS[0];
    }

    public function set_cmd_prompt()
    {
      this.previous_prompt = this.cmd_prompt;
      this.cmd_prompt = _FCT_ANON_ARGS[0];
    }

    # This function is not implemented or supported by the NetApp Shell
    public function set_least_privilege()
    {
      return NULL;
    }

    # This function is not implemented or supported by the NetApp Shell
    public function set_escalated_shell()
    {
      return NULL;
    }

    public function set_cmd_state(new_cmd_state)
    {
      var channel = _FCT_ANON_ARGS[0];
      if(!isnull(channel))
      {
        var obj_ch_id = 'netapp_shell_handler [channel '+channel.local_channel+']: ';
        channel.session.dbg_log(
            fn:'netapp_shell_handler.set_cmd_state',
            level:DEBUG3,
            message:
              obj_ch_id +
              ' updating from state '+
              this.cmd_state +
              ' to state ' +
              new_cmd_state);
      }
      this.cmd_state = new_cmd_state;
    }

    public function run_command(channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = 'netapp_shell_handler.run_command';
      var obj_ch_id = 'netapp_shell_handler [channel '+channel.local_channel+']: ';
      var cmd_logger = new("sshlib::cmd_logger");
      var lines;
      var last_line;
      var escl_result;
      var kb_id = channel.session.get_kb_connection_id();
      var kb_base = SSH_LIB_KB_PREFIX + kb_id;
      if ( isnull(channel) )
      {
        return NULL;
      }
      if ( isnull(command) )
      {
        return NULL;
      }
      if(force_priv_escl)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Privilege escalation was forced, however theNetApp shell handler "+
          "does not support privilege escalation");
      }


      if( this.last_cmd_error )
      {
        channel.session.set_error(obj_ch_id +
          'ERROR - shell is in unknown state from last interaction, ' +
          'no additional commands via this shell will be executed.');
        return NULL;
      }

      if(get_kb_item("SSH/attempt_least_privilege"))
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Attempt least privilege is enabled, however the NetApp shell handler "+
          "does not support privilege escalation");
        this.least_privilege = TRUE;
      }

      # Reset default timeouts
      this.inactivity_timeout = _NETAPP_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _NETAPP_DEFAULT_CMD_TIMEOUT;

      # If custom inactivity_timeout and cmd_timeout values are passed,
      # ensure the values in use meet or exceed passed values
      if (inactivity_timeout_min &&
          this.inactivity_timeout < inactivity_timeout_min)
        this.inactivity_timeout = inactivity_timeout_min;

      if (cmd_timeout_min &&
          this.cmd_timeout < cmd_timeout_min)
        this.cmd_timeout = cmd_timeout_min;

      if (this.fresh_shell)
      {
        if(this.cmd_prompt != _NETAPP_DEFAULT_PROMPT)
        {
          check_prompt = TRUE;
        }
        else
        {
          var post_login_buffer = get_kb_blob(kb_base + "/post_login_buffer");
          var tmp_prompt = get_kb_blob(kb_base + "/cmd_prompt");
          channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            "Getting prompt on fresh shell.");

          var check_prompt = FALSE;
          # see if we can look for prompt from previous login rather
          # than waiting for timeout
          if(strlen(tmp_prompt) >= 3)
          {
            # remove first found instance of prompt from previous post
            # login buffer
            var sub_prompt = substr(
                               tmp_prompt,
                               strlen(tmp_prompt) - 3,
                               strlen(tmp_prompt) - 1
                             );
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
        }

        var initial_recv_timeout = _NETAPP_INITIAL_INACTIVITY_TIMEOUT;

        if(check_prompt)
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using command prompt from previous login to find cmd prompt.");
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @netapp_shell_handler_incoming_data_timeout_or_prompt_cb,
            channel        : channel,
            cmd_timeout    : initial_recv_timeout
          );
        }
        else
        {
          channel.session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
            "Waiting for inactivity period to find command prompt.");
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @netapp_shell_handler_incoming_data_timeout_cb,
            channel        : channel,
            cmd_timeout    : initial_recv_timeout
          );
        }

        if(empty_or_null(channel.data_buf))
        {
          if(this.timed_out)
            return channel.session.set_cmd_error(obj_ch_id +
              "Timed out waiting for data from server after opening shell.");

          last_cmd_error = TRUE;
          return channel.session.set_cmd_error(obj_ch_id +
            "No data received from server after opening shell.");
        }

        post_login_buffer = channel.data_buf;
        if(isnull(get_kb_item(kb_base + "/post_login_buffer")))
          set_kb_blob(name:kb_base + "/post_login_buffer", value:post_login_buffer);
        channel.clear_data_buf();
        this.fresh_shell = FALSE;
        this.timed_out = FALSE;

        lines = split(post_login_buffer, sep:'\n', keep:FALSE);
        this.cmd_prompt = lines[max_index(lines)-1];

        if(isnull(get_kb_item(kb_base + "/cmd_prompt")))
          set_kb_blob(name:kb_base + "/cmd_prompt", value:cmd_prompt);

        channel.session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
          'Detected command prompt  "' + this.cmd_prompt + '".');

        if(strlen(this.cmd_prompt) == 0)
        {
          channel.session.set_cmd_error(obj_ch_id +
            "Unable to detect command prompt on shell.");
          last_cmd_error = TRUE;
          return NULL;
        }

        this.settings['cmd_prompt'] = this.cmd_prompt;
      }

      this.cmd_last = command + '\n';
      channel.session.reset_cmd_interrupted();

      channel.session.dbg_log(fn:fn, level:DEBUG2, message: "sending command: " + cmd_last);
      channel.clear_data_buf();
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _NETAPP_CMD_STATE_SEND_REQ;
      channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
        "cmd_state:_NETAPP_CMD_STATE_SEND_REQ(" + this.cmd_state + ")" );
      channel.window_send_data(data:cmd_last);
      channel.session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @netapp_shell_handler_incoming_data_timeout_or_prompt_cb,
        channel        : channel,
        cmd_timeout    : this.cmd_timeout
      );

      var ret = NULL;

      if(channel && channel.data_buf )
      {
        ret = channel.data_buf;

        if ( this.cmd_state != _NETAPP_CMD_STATE_AT_PROMPT )
        {
          channel.session.set_cmd_error(obj_ch_id +
            "Unable to return to command prompt after last command.");
          this.last_cmd_error = TRUE;
        }

        ret = str_replace(string:ret, find:command, replace:'');

        ret = chomp(string_reverse(chomp(string_reverse(remove_cmd_prompt(cmd_res:ret)))));

        cmd_logger.add(
          cmd                : this.cmd_last,
          response           : ret,
          error              : channel.session.cmd_error,
          ran_with_priv_escl : this.escalated_shell,
          forced_escl        : force_priv_escl,
          priv_escl_failed   : FALSE,
          escl_method        : this.priv_escalation_type,
          user               : channel.session.user,
          escl_user          : NULL
        );
        if ( "Error: " >< ret && "is not a recognized command" >< ret)
        {
          channel.session.set_cmd_error(obj_ch_id + 
              'Command not recognized.');
          return NULL;
        }
      }

      if(ret == '')
      {
        channel.session.set_cmd_error(obj_ch_id +
          "No output returned from command.");
        return NULL;
      }

      if(isnull(ret))
      {
        cmd_logger.add(
          cmd                : this.cmd_last,
          response           : ret,
          error              : channel.session.cmd_error,
          ran_with_priv_escl : this.escalated_shell,
          forced_escl        : force_priv_escl,
          priv_escl_failed   : FALSE,
          escl_method        : this.priv_escalation_type,
          user               : channel.session.user,
          escl_user          : NULL
        );
      }

      return ret;

    }

    private function deescalate_shell(channel, obj_ch_id)
    {
      return NULL;
    }

    private function escalate_shell(channel, obj_ch_id, tmp_bad_escl_kb, escl_hexstr)
    {
      return NULL;
    }

    ##
    # Sets the privilege escalation method for the shell handler.
    #
    # NOTE: this function is not used
    #
    # @param [type:string] the privilege escalation method
    # @param [extra:array] key value pair with the escalation details
    # @param [timeout:int] timeout for escalation
    #
    # @return NULL
    ##
    public function set_priv_escalation(type, extra)
    {
      return NULL;
    }

    ##
    # Removes privilege escalation information from the shell handler.
    #
    # @return NULL;
    ##
    public function unset_priv_escalation()
    {
      return NULL;
    }

    ##
    # Removed the command prompt from the output
    #
    # @param [cmd_res:string] command results
    #
    # @return the command output stripped of the prompt
    ##
    public function remove_cmd_prompt(cmd_res)
    {
      var idx = stridx(cmd_res, this.cmd_prompt);
      var ret = substr(cmd_res, 0, idx-1);
      return ret;
    }

    ##
    # Determines if the shell is back at the command prompt. 
    #
    # @param [buf:data] the incoming data buffer
    # @anonparam First the channel belonging to the shell handler
    #
    # @return TRUE if at prompt, esle implicitly returns NULL
    ##
    function at_cmd_prompt(buf)
    {
      var channel = _FCT_ANON_ARGS[0];
      var lines = split(buf, sep:'\n', keep:FALSE);
      var last_line = lines[max_index(lines)-1];
      channel.session.dbg_log(
          fn:'netapp_shell_handler.at_cmd_prompt',
          level:DEBUG2,
          message:"last line = "+serialize(last_line)+
                  '\ncmd_prompt = '+serialize(this.cmd_prompt));
      if(this.cmd_prompt >< last_line)
      {
        this.set_cmd_state(
           new_cmd_state: _NETAPP_CMD_STATE_AT_PROMPT,
           channel);
        return TRUE;
      }
    }

    ##
    # Determines if the shell is at the prompt or a timeout has occurred
    #
    # @param [channel:object] the channel belonging to the shell handler
    #
    # @return TRUE if at prompt or timed out, FALSE if neither
    ##
    public function at_prompt_or_timeout(channel)
    {
      if(at_cmd_prompt(buf:channel.data_buf, channel)) return TRUE;
      return check_inactivity_timeout(channel:channel);
    }

    ##
    # Determines if there has been a timeout to inactivity
    #
    # @param [channel:object] the channel belonging to the shell handler
    #
    # @return TRUE if timeout reached, else FALSE
    ##
    public function check_inactivity_timeout(channel)
    {
      var fn = 'netapp_shell_handler.check_inactivity_timeout';
      if ( channel && channel.data_buf && strlen(channel.data_buf) > 0 )
      {
        var new_md5 = MD5( channel.data_buf );
        if ( this.last_md5 != new_md5 )
        {
          if(!isnull(channel) && !isnull(channel.session))
          {
            channel.session.dbg_log(
                fn:fn,
                level:DEBUG2,
                message:"New data found, updating last_buffer_update_ts");
          }
          this.last_md5 = new_md5;
          this.last_buffer_update_ts = unixtime();
          return FALSE;
        }
      } 
      if (channel && (unixtime() - this.last_buffer_update_ts) >= this.inactivity_timeout)
      {
        if(channel.session)
        {
          channel.session.dbg_log(
              fn:fn,
              level:DEBUG2,
              message:"Inactivity timeout.");
        }
        this.timed_out = TRUE;
        return TRUE;
      }
      else if(isnull(channel))
      {
        return TRUE;
      }

      return FALSE;
    }

  }
}

