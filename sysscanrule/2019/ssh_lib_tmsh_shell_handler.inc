#TRUSTED 650656f8b8148070bdcf88e69c695e4d17c43b8018aa1f0b5d6c7f3c892bee45d3c5635154f8b7bf66a9bf4af64960a2072b28deb52732f65954a12ddca6395543b9e1bfec628f65e3c33a4e7856b25273d07b4b29b72c3cefd520effc75671e6dc802b54f868cb6f44be5875f2934006e45398b3a389bf9eaf88f05559989627b594ec8232cf65a517d065543ff21152ee2e2a3105b71b5bba5e1e691a60bb2ab51893bd06aafb6965de50e2758894e659744aafc623c3064087e4edd5f5d69b52230e8098093a34ad4f569226e073f7e36c4ee694244480e09a54d39a329cf147cdac1c3e35d6a8d0e1dac6e5a70246b8b4176592067617d6b4777ccbea82da502b9baccb35e156abb02bc602aaa2418b94e47b364ff2d5b500c7dc1b4f5846c1b63e2bd52297c97e85cc2c85f581ab9300924da329094f2818c50684e624565ba9a671cd01f5c74b6efa8cf08cf0074674a0c650b7064b4dc8a82d9cde75ab850718d570875aedea6047e0a1f937a4c04bd33bb3332c29cf1d52861a90bf8f8061d59122895ecf2d847faf205a3e8469fb6749e99465a2eedff07e231b4ddb556c66b384824dad87f23f10d558a4ae44d9b76120fa594d32c456ffeff2bbcb67a7b81f37354af897ba733f33f5001c29a202c0dcd18fb93fa53a4b04a9d04c60470f38f96974e6d49c63555d84fd19cde2f50f74be96e6ec66ff8253ecda6
namespace sshlib
{
  global_var _TMSH_DEFAULT_PROMPT = ')#';
  global_var _TMSH_DEFAULT_CMD_TIMEOUT = 60;
  global_var _TMSH_DEFAULT_INACTIVITY_TIMEOUT = 45;
  global_var _TMSH_INITIAL_INACTIVITY_TIMEOUT = 2;
  global_var _TMSH_CMD_STATE_SEND_REQ = 0;
  global_var _TMSH_CMD_STATE_AT_PROMPT = 1;
  global_var _LESS_PATTERN = ".\[7m---\(less\s+[0-9]+%\)---.\[m.\[K";

  function tmsh_shell_handler_incoming_data_timeout_cb(session, channel)
  {
    var fn = 'tmsh_shell_handler_incoming_data_timeout_cb';
    var sh = channel.shell_handler;
    # does a channel exist?
    if ( isnull(channel) ) 
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:"Channel does not exist");
      return FALSE;
    }
    # does channel have a valid data buffer?
    if ( isnull(channel.data_buf) )
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:"Channel.data_buf does not exist");
      return FALSE;
    }
    if ( isnull(channel.shell_handler ) )
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:"Shell handler does not exist");
      return FALSE;
    }
    if("This account is currently not available" >< channel.data_buf)
      return FALSE;
    return sh.check_inactivity_timeout(channel:channel);
  }

  function tmsh_shell_handler_incoming_data_timeout_or_prompt_cb( session, channel )
  {
    var fn = 'tmsh_shell_handler_incoming_data_timeout_or_prompt_cb';
    var obj_ch_id = 'tmsh_shell_handler [channel '+channel.local_channel+']: ';
    var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
    var last_line = lines[max_index(lines)-1];
    if("This account is currently not available" >< channel.data_buf)
      return FALSE;
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
    if(pgrep(pattern:_LESS_PATTERN, string:last_line))
    {
      sh.set_less(TRUE);
      channel.window_send_data(data:' ');
      return FALSE;
    }
    if("(END)" >< last_line)
    {
      channel.window_send_data(data:'q\n');
      return FALSE;
    }

    return sh.at_prompt_or_timeout(channel:channel);

  }

  object tmsh_shell_handler
  {
    var settings;
    var cmd_state;
    var cmd_last;
    var cmd_prompt;
    var cmd_timeout;
    var inactivity_timeout;
    var last_md5;
    var last_buffer_update_ts;
    var last_cmd_error = FALSE;
    var fresh_shell = TRUE;
    var timed_out = FALSE;
    var previous_prompt;
    var less;
    var new_channel_needs_new_connection = TRUE;

    function tmsh_shell_handler()
    {
      settings = _FCT_ANON_ARGS[0];
      this.init(settings:settings);
    }

    function init(settings)
    {
      this.cmd_last = "";
      this.cmd_prompt = _TMSH_DEFAULT_PROMPT;
      this.cmd_timeout = _TMSH_DEFAULT_CMD_TIMEOUT;
      this.inactivity_timeout = _TMSH_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_state = _TMSH_CMD_STATE_SEND_REQ;
      this.last_cmd_error = FALSE;
      this.last_buffer_update_ts = unixtime();
      if (!isnull(settings))
      {
        this.settings = settings;
        if ( !isnull(this.settings['cmd_prompt']) )
          this.cmd_prompt = this.settings['cmd_prompt'];
        if ( !isnull(this.settings['cmd_timeout']) )
          this.cmd_timeout = this.settings['cmd_timeout'];
      }
      else this.settings = make_array();
    }

    public function run_command(channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = 'tmsh_shell_handler.run_command';
      # Local reference to session, channel's reference gets deleted
      # if the channel gets closed
      var session = channel.session;
      var obj_ch_id = 'tmsh_shell_handler [channel '+channel.local_channel+']: ';
      var cmd_logger = new("sshlib::cmd_logger");
      var lines;
      var last_line;
      var kb_base = SSH_LIB_KB_PREFIX + session.get_kb_connection_id();
      if ( isnull(channel) )
      {
        return NULL;
      }
      if ( isnull(command) )
      {
        return NULL;
      }
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "In run_command");

      if( this.last_cmd_error )
      {
        session.set_error(obj_ch_id +
          'ERROR - shell is in unknown state from last interaction, ' +
          'no additional commands via this shell will be executed.');
        return NULL;
      }

      # Reset default timeouts
      this.inactivity_timeout = _TMSH_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _TMSH_DEFAULT_CMD_TIMEOUT;

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
        var check_prompt;
        if(this.cmd_prompt != _TMSH_DEFAULT_PROMPT)
        {
          check_prompt = TRUE;
        }
        else
        {
          var post_login_buffer = get_kb_blob(kb_base + "/post_login_buffer");
          var tmp_prompt = get_kb_blob(kb_base + "/cmd_prompt");
          session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            "Getting prompt on fresh shell.");

          check_prompt = FALSE;
        }

        var initial_recv_timeout = _TMSH_INITIAL_INACTIVITY_TIMEOUT;

        if(check_prompt)
        {
          session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using command prompt from previous login to find cmd prompt.");
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @tmsh_shell_handler_incoming_data_timeout_or_prompt_cb,
            channel        : channel,
            cmd_timeout    : initial_recv_timeout
          );
        }
        else
        {
          session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
            "Waiting for inactivity period to find command prompt.");
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @tmsh_shell_handler_incoming_data_timeout_cb,
            channel        : channel,
            cmd_timeout    : initial_recv_timeout
          );
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

        post_login_buffer = channel.data_buf;
        if(isnull(get_kb_item(kb_base + "/post_login_buffer")))
          set_kb_blob(name:kb_base + "/post_login_buffer", value:post_login_buffer);
        channel.clear_data_buf();
        this.fresh_shell = FALSE;

        lines = split(post_login_buffer, sep:'\n', keep:FALSE);
        this.cmd_prompt = lines[max_index(lines)-1];

        if(isnull(get_kb_item(kb_base + "/cmd_prompt")))
          set_kb_blob(name:kb_base + "/cmd_prompt", value:cmd_prompt);

        session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
          'Detected command prompt  "' + this.cmd_prompt + '".');

        if(strlen(this.cmd_prompt) == 0)
        {
          session.set_cmd_error(obj_ch_id +
            "Unable to detect command prompt on shell.");
          last_cmd_error = TRUE;
          return NULL;
        }

        this.settings['cmd_prompt'] = this.cmd_prompt;

      }

      if(channel.state == CHANNEL_STATE_CLOSED)
      {
        session.set_cmd_error(obj_ch_id + "Channel is closed.");
        last_cmd_error = TRUE;
        return NULL;
      }

      this.cmd_last = command + '\n';

      var ret = NULL;
      session.reset_cmd_interrupted();

      session.dbg_log(fn:fn, level:DEBUG2, message: "sending command: " + cmd_last);
      channel.clear_data_buf();
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _TMSH_CMD_STATE_SEND_REQ;
      session.dbg_log(
        fn      : fn,
        level   : DEBUG2,
        message : "cmd_state:_TMSH_CMD_STATE_SEND_REQ(" + this.cmd_state + ")"
      );
      channel.window_send_data(data:cmd_last);
      session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @tmsh_shell_handler_incoming_data_timeout_or_prompt_cb,
        channel        : channel,
        cmd_timeout    : this.cmd_timeout
      );

      if(channel && channel.data_buf )
      {

        ret = channel.data_buf;


        if ( this.cmd_state != _TMSH_CMD_STATE_AT_PROMPT )
        {
          if(strlen(this.cmd_prompt) >= 10)
          {
            lines = split(channel.data_buf, sep:'\n', keep:FALSE);
            last_line = lines[max_index(lines)-1];
            var prompt_start = substr(this.cmd_prompt, 0, 9);
            if(prompt_start >< last_line)
            {
              var context = "unknown";
              var pattern = "\(([a-z.]+)\)#";
              var matches = pregmatch(pattern:pattern, string:last_line);
              if(!isnull(matches) && !isnull(matches[1]))
                context = matches[1];
              session.set_cmd_error(obj_ch_id + 
                  "There was an attempt to switch to context " +context+
                  ". Context switching is not currently supported."+
                  " Either operate from the root context or add the support" +
                  " to the tmsh shell handler.");
              this.last_cmd_error = TRUE;
              cmd_logger.add(
                cmd                : this.cmd_last,
                response           : ret,
                error              : channel.session.cmd_error,
                ran_with_priv_escl : FALSE,
                forced_escl        : FALSE,
                priv_escl_failed   : FALSE,
                user               : channel.session.user
              );
              return NULL;
            }
          }

          session.set_cmd_error(obj_ch_id +
            "Unable to return to command prompt after last command.");
        cmd_logger.add(
          cmd                : this.cmd_last,
          response           : ret,
          error              : channel.session.cmd_error,
          ran_with_priv_escl : FALSE,
          forced_escl        : FALSE,
          priv_escl_failed   : FALSE,
          user               : channel.session.user
        );
          this.last_cmd_error = TRUE;
          return NULL;
        }

        ret = chomp(string_reverse(chomp(string_reverse(remove_cmd_prompt(cmd_res:ret)))));


      }
      cmd_logger.add(
        cmd                : this.cmd_last,
        response           : ret,
        error              : channel.session.cmd_error,
        ran_with_priv_escl : FALSE,
        forced_escl        : FALSE,
        priv_escl_failed   : FALSE,
        user               : channel.session.user
      );
      set_less(FALSE);
      return ret;
    }

    public function set_less()
    {
      this.less = _FCT_ANON_ARGS[0];
    }

    public function remove_cmd_prompt(cmd_res)
    {
      var idx = stridx(cmd_res, this.cmd_prompt);
      var ret = substr(cmd_res, 0, idx-1);
      ret = str_replace(string:ret, find:'\r', replace:'');
      # first line will be the command echoed. Remove
      idx = stridx(ret, '\n');
      ret = substr(ret, idx+1);
      # if output was paged with less, remove formatting. Don't remove by default
      # in case the more generic regexes take actual data.
      if(this.less)
      {
        ret = ereg_replace(pattern:_LESS_PATTERN, string:ret, replace:'\n');
        ret = ereg_replace(pattern:"\(END\)", string:ret, replace:"");
        ret = ereg_replace(pattern:".\[\??[0-9]?[Kmlh]", string:ret, replace:"");
        ret = ereg_replace(pattern:".[>=]$", string:ret, replace:"");
      }

      return ret;

    }

    public function set_cmd_prompt()
    {
      this.cmd_prompt = _FCT_ANON_ARGS[0];
    }

    public function get_pty_opts()
    {
      return make_array(PTY_OPT_OCRNL, mkdword(0, order:BYTE_ORDER_BIG_ENDIAN));
    }

    public function get_pty_size_chars()
    {
      return make_list(80, 500);
    }

    public function get_pty_size_pixels()
    {
      return DEFAULT_PTY_SIZE_PIXELS;
    }

    public function get_pty_term()
    {
      return DEFAULT_PTY_TERM;
    }

    public function send_pty_req()
    {
      return TRUE;
    }

    public function is_nosetup()
    {
      return FALSE;
    }

    public function set_cmd_state(new_cmd_state)
    {
      this.cmd_state = new_cmd_state;
    }

    function at_cmd_prompt(buf)
    {
      var lines = split(buf, sep:'\n', keep:FALSE);
      var last_line = lines[max_index(lines)-1];
      if(this.cmd_prompt >< last_line)
      {
        this.set_cmd_state( new_cmd_state: _TMSH_CMD_STATE_AT_PROMPT);
        return TRUE;
      }
    }

    public function check_inactivity_timeout(channel)
    {
      var fn = 'tmsh_shell_handler.check_inactivity_timeout';
      var obj_ch_id = 'tmsh_shell_handler [channel ]: ';
      if ( channel && channel.data_buf && strlen(channel.data_buf) > 0 )
      {
        var new_md5 = MD5( channel.data_buf );
        if ( this.last_md5 != new_md5 )
        {
          this.last_md5 = new_md5;
          this.last_buffer_update_ts = unixtime();
          return FALSE;
        }
      } 
      if ((unixtime() - this.last_buffer_update_ts) >= this.inactivity_timeout)
      {
        this.timed_out = TRUE;
        return TRUE;
      }
      return FALSE;
    }

    public function at_prompt_or_timeout(channel)
    {
      if(at_cmd_prompt(buf:channel.data_buf)) return TRUE;
      return check_inactivity_timeout(channel:channel);
    }

    public function set_priv_escalation(type, extra)
    {
      return NULL;
    }

    public function unset_priv_escalation()
    {
      return NULL;
    }
  }
}
