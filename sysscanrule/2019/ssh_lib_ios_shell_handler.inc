#TRUSTED 782c11e3f228e4e322a70590c068c9e05097556fc493eee9c30292f2df47b5557dfd3ff547ca19e3f29d0b5435085073cef7d12f68fb720f884d68756ceed5c129e8530a27271d1d2ac73f242392d90478d9f649a1fd26c6947ca6d8c531b45f0d59826751673f8918457970bb71f3c2408aa0df725f01e26df9b0df4100423dcf7679e917b0591648ad396b39ac2ea81204e72801603bde562252645b049c9d18c0ef042ce83527c4ceda6c93eac53a5b15b770a9754140a56071bd5b2fa4369ca5681a77475948b8e8274131dd72efcc9934550b0a0412c2be12d7fc8ce7f28cce1c7f9e6dc467d3e9bdff17873ef7683b5ddebc723652552f5126d32c5480c8c4131f34f2dc76773f68a2dbc2f5982edfc0ca5e0308d8236d7629deed83a18fb864789b4ebe75f79d74c4843b7a8fe1df18655aa512cb6cf79bf2eb2d93852610dc95a0f21279ab17ea374dd140d9c25e9d590c13988f0227418e03290e71eba1d7572d75ec3e60aed9eab8c922cdeff441f1e376186ac763b658f2ee7fee911eaad175c104040bdf6faf4d2cf00ae0dec17cb0d0fd2f980532723d2be6a7c297f871431f83f2e0b679997cbdcb9782a990d2c283b34a63bfdd25d5a18fb281168a765e2a930081c4d5a69e094907ca5d3eedb0de5848248f62decda39dfdb30cac6695c4e2dcbe5c39e0f68ff6fb792264c475c1f053e11a8b4364b5516c
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.13
include("ssh_lib_util.inc");

namespace sshlib
{

  # all timeouts are controlled by a timer with 1s resolution
  # for that reason keep the shell timeout sufficiently beyond
  # the timer resolution (10s = 10x resolution)
  global_var _IOS_DEFAULT_CMD_TIMEOUT = 60;
  global_var _IOS_DEFAULT_INACTIVITY_TIMEOUT = 45;
  global_var _IOS_INITIAL_INACTIVITY_TIMEOUT = 2;

  # a space is included in shell prompt
  global_var _IOS_DEFAULT_PROMPT = "> ";
  global_var _IOS_DEFAULT_ENABLED_PROMPT = "# ";

  # cmd_states
  # _IOS_CMD_STATE_SEND_REQ: ready to send a command to device
  # _IOS_CMD_STATE_RECV_RSP: ready to recv a response from device
  # _IOS_CMD_STATE_AT_PROMPT: found command prompt in response
  global_var _IOS_CMD_STATE_SEND_REQ = 0;
  global_var _IOS_CMD_STATE_RECV_RSP = 1;
  global_var _IOS_CMD_STATE_AT_PROMPT = 2;
  global_var _IOS_CMD_STATE_SEND_ESCL_REQ = 3;
  global_var _IOS_CMD_STATE_RECV_ESCL_RSP = 4;
  global_var _IOS_CMD_STATE_GET_PROMPT = 5;


  global_var _BANNER_PAGINATION_SPACES = FALSE;

  global_var _IOS_DEFAULT_ENABLE_PROMPT = "Password:";

  function ios_shell_handler_enable_cb(session, channel)
  {
    var fn = 'ios_shell_handler_enable_cb';
    var obj_ch_id = 'ios_shell_handler [channel '+channel.local_channel+']: ';
    # does a channel exist?
    if ( isnull(channel) ) return TRUE;
    if(channel.state == CHANNEL_STATE_CLOSED)
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "Channel is closed.");
      return TRUE;
    }
    # does channel have a valid data buffer?
    if ( isnull(channel.data_buf) )  return TRUE;
    if ( isnull(channel.shell_handler ) )  return TRUE;

    var sh = channel.shell_handler;
    var cmd_state = sh.cmd_state;
    var cmd_last = sh.cmd_last;
    var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
    var last_line = lines[max_index(lines)-1];

    var enabled_prompt;

    if(sh.cmd_prompt)
    {
      enabled_prompt = str_replace(
                           string  : sh.cmd_prompt,
                           find    : '>',
                           replace : '#');
    }
    else
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "sh.cmd_prompt is not set. Using default enabled prompt.");
      enabled_prompt = _IOS_DEFAULT_ENABLED_PROMPT;
    }
    var cmd_enable_prompt = sh.cmd_enable_prompt;
    var cmd_enable_prompt_length = strlen(cmd_enable_prompt);
    channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "_IOS_STATE : " + sh.cmd_state);

    if ( cmd_state == _IOS_CMD_STATE_SEND_ESCL_REQ)
    {
      if(tolower(cmd_enable_prompt) >< tolower(channel.data_buf))
      {
        channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
              "Setting _IOS_STATE : " + _IOS_CMD_STATE_RECV_ESCL_RSP);
        sh.set_cmd_state( new_cmd_state:_IOS_CMD_STATE_RECV_ESCL_RSP );
      }
      # When IOS is configured to be enabled by default enable returns
      # you to the prompt.
      #else if(strip(last_line) == strip(enabled_prompt))
      else if(last_line == enabled_prompt)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
              "Setting _IOS_STATE : " + sh.cmd_state);
        sh.set_cmd_state( new_cmd_state: _IOS_CMD_STATE_AT_PROMPT);
        channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "Shell was already escalated");
        sh.set_shell_default_escl(TRUE);
        sh.set_escalated_shell(TRUE);
        return TRUE;
      }
    }
    cmd_state = sh.cmd_state;
    if ( cmd_state == _IOS_CMD_STATE_RECV_ESCL_RSP )
    {
      if(tolower(cmd_enable_prompt) >< tolower(channel.data_buf))
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message: "found password prompt");
        # if timeout expired the password could be entered as a command and echoed back
        if("timeout expired" >< channel.data_buf)
        {
          channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
                "Enable password timeout. Setting _IOS_STATE : " + _IOS_CMD_STATE_GET_PROMPT);
          sh.set_cmd_state( new_cmd_state: _IOS_CMD_STATE_GET_PROMPT);
          return TRUE;
        }
        channel.clear_data_buf();
        var cmd_enable_password = sh.priv_escalation_extra['enable_pass'];
        channel.session.set_redact( TRUE );
        channel.window_send_data(data:cmd_enable_password + '\n' );
        channel.session.set_redact( FALSE );
        sh.set_cmd_state( new_cmd_state: _IOS_CMD_STATE_GET_PROMPT);
        # replace last character of prompt with #

        return FALSE;
      }
    }
    else if(cmd_state == _IOS_CMD_STATE_GET_PROMPT)
    {
      if(last_line == enabled_prompt)
      {
        sh.set_cmd_prompt(enabled_prompt);
        sh.set_cmd_state( new_cmd_state: _IOS_CMD_STATE_AT_PROMPT);
        channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "Successfully escalated");
        sh.set_escalated_shell(TRUE);
        return TRUE;
      }
      else if(tolower(last_line) == "password: ")
      {
        channel.window_send_data(data:'\n');
        return FALSE;
      }
    }
    return sh.check_inactivity_timeout(channel:channel);
  }

  function ios_shell_handler_incoming_data_timeout_cb(session, channel)
  {
    var fn = 'ios_shell_handler_incoming_data_timeout_cb';
    var sh = channel.shell_handler;
    var obj_ch_id = 'ios_shell_handler [channel '+channel.local_channel+']: ';
    var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
    var last_line = lines[max_index(lines)-1];
    if(isnull(channel))
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:
        "Channel does not exist");
      return TRUE;
    }
    if(channel.state == CHANNEL_STATE_CLOSED)
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "Channel is closed.");
      return TRUE;
    }

    if(pgrep(pattern:"-+\s*[Mm]ore\s*-+", string:last_line))
    {
      channel.window_send_data(data:' ');
      _BANNER_PAGINATION_SPACES = TRUE;
      return FALSE;
    }

    channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "_IOS_STATE : " + sh.cmd_state);
    return sh.check_inactivity_timeout(channel:channel);
  }

  function ios_shell_handler_incoming_data_timeout_or_prompt_cb( session, channel )
  {
    var fn = 'ios_shell_handler_incoming_data_timeout_or_prompt_cb';
    var obj_ch_id = 'ios_shell_handler [channel '+channel.local_channel+']: ';
    var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
    var last_line = lines[max_index(lines)-1];
    # does a channel exist?
    if ( isnull(channel) )
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:
        "Channel does not exist");
      return TRUE;
    }
    if (channel.state == CHANNEL_STATE_CLOSED)
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "Channel is closed.");
      return TRUE;
    }
    # does channel have a valid data buffer?
    if ( isnull(channel.data_buf) )
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "Channel.data_buf does not exist");
      return TRUE;
    }
    if ( isnull(channel.shell_handler ) )
    {
      session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
        "Shell handler does not exist");
      return TRUE;
    }
    var sh = channel.shell_handler;
    session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "_IOS_STATE : " + sh.cmd_state);

    if(pgrep(pattern:"-+\s*[Mm]ore\s*-+", string:last_line))
    {
      channel.window_send_data(data:' ');
      return FALSE;
    }

    return sh.at_prompt_or_timeout(channel:channel);

  }

  object ios_shell_handler
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
    var default_escl = FALSE;
    var least_privilege = FALSE;
    var previous_prompt;
    var priv_escl_failed = FALSE;
    var new_channel_needs_new_connection = TRUE;

    function ios_shell_handler()
    {
      settings = _FCT_ANON_ARGS[0];
      this.init(settings:settings);
    }

    public function init(settings)
    {
      this.cmd_last = "";
      this.cmd_prompt = _IOS_DEFAULT_PROMPT;
      this.cmd_timeout = _IOS_DEFAULT_CMD_TIMEOUT;
      this.inactivity_timeout = _IOS_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_enable_prompt = _IOS_DEFAULT_ENABLE_PROMPT;
      this.cmd_state = _IOS_CMD_STATE_SEND_REQ;
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

    public function get_supported_escalation_method()
    {
      return this.priv_escalation_type;
    }

    public function get_least_privilege()
    {
      return this.priv_escalation_type;
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
      # Make the default pty size large to avoid issues with truncation
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

    # should we send / recv data to device without setting up a channel?
    public function is_nosetup()
    {
      return FALSE;
    }

    # do we want to request a PTY on this device?
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

    public function set_least_privilege()
    {
      this.least_privilege = _FCT_ANON_ARGS[0];
    }

    public function set_shell_default_escl()
    {
      this.default_escl = _FCT_ANON_ARGS[0];
    }

    public function set_escalated_shell()
    {
      this.escalated_shell = _FCT_ANON_ARGS[0];
    }

    public function set_cmd_state(new_cmd_state)
    {
      var channel = _FCT_ANON_ARGS[0];
      if(!isnull(channel))
      {
        var obj_ch_id = 'ios_shell_handler [channel '+channel.local_channel+']: ';
        channel.session.dbg_log(
            fn:'ios_shell_handler.set_cmd_state',
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
      var fn = 'ios_shell_handler.run_command';
      # Local reference to session, channel's reference gets deleted
      # if the channel gets closed
      var session = channel.session;
      var obj_ch_id = 'ios_shell_handler [channel '+channel.local_channel+']: ';
      var cmd_logger = new("sshlib::cmd_logger");
      var lines;
      var last_line;
      var escl_result;
      var kb_id = session.get_kb_connection_id();
      var kb_base = SSH_LIB_KB_PREFIX + kb_id;
      var use_priv_escl = FALSE;
      var least_priv_escl = FALSE;
      if(isnull(force_priv_escl))
        force_priv_escl = FALSE;
      if(force_priv_escl) use_priv_escl = TRUE;
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

      if(get_kb_item("SSH/attempt_least_privilege"))
      {
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Attempt least privilege is enabled.");
        this.least_privilege = TRUE;
      }

      # Reset default timeouts
      this.inactivity_timeout = _IOS_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _IOS_DEFAULT_CMD_TIMEOUT;

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
        if(this.cmd_prompt != _IOS_DEFAULT_PROMPT)
        {
          check_prompt = TRUE;
        }
        else
        {
          var post_login_buffer = get_kb_blob(kb_base + "/post_login_buffer");
          var tmp_prompt = get_kb_blob(kb_base + "/cmd_prompt");
          session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
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

        var initial_recv_timeout = _IOS_INITIAL_INACTIVITY_TIMEOUT;

        if(check_prompt)
        {
          session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using command prompt from previous login to find cmd prompt.");
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @ios_shell_handler_incoming_data_timeout_or_prompt_cb,
            channel        : channel,
            timeout        : initial_recv_timeout
          );
        }
        else
        {
          session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
            "Waiting for inactivity period to find command prompt.");
          session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @ios_shell_handler_incoming_data_timeout_cb,
            channel        : channel,
            timeout        : initial_recv_timeout
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

        if (channel.state == CHANNEL_STATE_CLOSED)
        {
          session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            "Channel is closed.");
          return TRUE;
        }

        post_login_buffer = channel.data_buf;
        if(isnull(get_kb_item(kb_base + "/post_login_buffer")))
          set_kb_blob(name:kb_base + "/post_login_buffer", value:post_login_buffer);
        channel.clear_data_buf();
        this.fresh_shell = FALSE;
        this.timed_out = FALSE;

        lines = split(post_login_buffer, sep:'\n', keep:FALSE);
        this.cmd_prompt = lines[max_index(lines)-1];
        if('\n' >< this.cmd_prompt)
          this.cmd_prompt = str_replace(find:'\n', replace:'', string:this.cmd_prompt);

        # There will be a bunch of spaces echoed from pagination in the banner, remove all but one.
        if(_BANNER_PAGINATION_SPACES)
          this.cmd_prompt = str_replace(find:'  ', replace:'', string:this.cmd_prompt);

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

      # Determine if privilege escalation should be used
      priv_escl_failed = FALSE;
      var tmp_bad_escl_kb =
        "tmp/" + kb_id + "/ssh_bad_priv_escl/" + this.priv_escalation_type;
      var escl_hexstr = hexstr(MD5(serialize(this.priv_escalation_extra)));

      if ( this.priv_escalation_type == "cisco_enable" )
      {
        if ( get_kb_item(tmp_bad_escl_kb) == escl_hexstr )
        {
          session.set_error(obj_ch_id + "Not using privilege " +
            "escalation due to failure in a previous session.");
        }
        else
        {
          use_priv_escl = TRUE;
        }
      }

      # escalate shell
      if ( !this.escalated_shell && use_priv_escl && (!this.least_privilege || force_priv_escl ))
      {
        if(this.least_privilege && force_priv_escl)
        {
          channel.session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id+
              'force_priv_escl is set, ignoring least_privilege.');
        }
        escl_result = escalate_shell(
                        channel         : channel,
                        obj_ch_id       : obj_ch_id,
                        tmp_bad_escl_kb : tmp_bad_escl_kb,
                        escl_hexstr     : escl_hexstr);
        if(isnull(escl_result))
        {
          cmd_logger.add(
            cmd                : command,
            response           : '',
            error              : 'Privilege escalation failed',
            ran_with_priv_escl : FALSE,
            forced_escl        : force_priv_escl,
            priv_escl_failed   : TRUE,                     # exit on failed privesc
            escl_method        : this.priv_escalation_type,
            user               : channel.session.user,
            escl_user          : channel.session.user
          );
          return NULL;
        }
      }
      else if (this.least_privilege && !force_priv_escl)
      {
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Not escalating shell, attempting least privilege.");
      }
      else if (this.escalated_shell)
      {
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Not escalating, shell is already escalated.");
      }
      else if (!use_priv_escl)
      {
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Not escalating shell.");
      }

      this.cmd_last = command + '\n';
      session.reset_cmd_interrupted();

      session.dbg_log(fn:fn, level:DEBUG2, message: "sending command: " + cmd_last);
      channel.clear_data_buf();
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _IOS_CMD_STATE_SEND_REQ;
      session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
        "cmd_state:_IOS_CMD_STATE_SEND_REQ(" + this.cmd_state + ")" );
      channel.window_send_data(data:cmd_last);
      session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @ios_shell_handler_incoming_data_timeout_or_prompt_cb,
        channel        : channel,
        cmd_timeout    : this.cmd_timeout
      );

      var ret = NULL;

      if(channel && channel.data_buf )
      {
        ret = channel.data_buf;

        if ( this.cmd_state != _IOS_CMD_STATE_AT_PROMPT )
        {
          session.set_cmd_error(obj_ch_id +
            "Unable to return to command prompt after last command.");
          this.last_cmd_error = TRUE;
          return NULL;
        }

        ret = str_replace(string:ret, find:command, replace:'');

        ret = chomp(string_reverse(chomp(string_reverse(remove_cmd_prompt(cmd_res:ret)))));

        if(this.least_privilege && force_priv_escl && this.escalated_shell)
        {
          if(!this.default_escl)
          {
            channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
              "Least privilege was enabled, but escalation was forced. Deescalating shell.");
            escl_result = deescalate_shell(
                            channel   : channel,
                            obj_ch_id : obj_ch_id);
            if(isnull(escl_result)) return NULL;
          }
          else
          {
            channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
              "Least privilege was enabled, and escalation was forced but the shell is " +
              "enabled by default. Not deescalating.");
          }
        }
      }
      if(this.least_privilege &&
         !force_priv_escl && (
          '% Invalid input'  >< ret ||
          '% This command is not authorized' >< ret ||
          'ERROR: Command authorization failed' >< ret
          ))
      {
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Command failed, trying escalated.");
        escl_result = escalate_shell(
                        channel         : channel,
                        obj_ch_id       : obj_ch_id,
                        tmp_bad_escl_kb : tmp_bad_escl_kb,
                        escl_hexstr     : escl_hexstr
                      );
        least_priv_escl = TRUE;
        if(isnull(escl_result))
        {
          cmd_logger.add(
            cmd                : command,
            response           : '',
            error              : 'Privilege escalation failed',
            ran_with_priv_escl : FALSE,
            forced_escl        : force_priv_escl,
            priv_escl_failed   : TRUE,        # exit on failed privesc
            escl_method        : this.priv_escalation_type,
            user               : session.user,
            escl_user          : session.user
          );
          session.set_cmd_error(obj_ch_id +
            "Insufficient privileges to run command.");
          this.last_cmd_error = TRUE;
          return NULL;
        }
        this.cmd_last = command + '\n';
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "sending command: " + cmd_last);
        channel.clear_data_buf();
        this.last_buffer_update_ts = unixtime();
        this.cmd_state = _IOS_CMD_STATE_SEND_REQ;
        session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "cmd_state:_IOS_CMD_STATE_SEND_REQ(" + this.cmd_state + ")" );
        channel.window_send_data(data:cmd_last);
        session.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          check_callback : @ios_shell_handler_incoming_data_timeout_or_prompt_cb,
          channel        : channel,
          cmd_timeout    : this.cmd_timeout
        );
        if(channel && channel.data_buf )
        {
          ret = channel.data_buf;

          if ( this.cmd_state != _IOS_CMD_STATE_AT_PROMPT )
          {
            channel.session.set_cmd_error(obj_ch_id +
              "Unable to return to command prompt after last command.");
            this.last_cmd_error = TRUE;
            return NULL;
          }

          ret = str_replace(string:ret, find:command, replace:'');

          ret = chomp(string_reverse(chomp(string_reverse(remove_cmd_prompt(cmd_res:ret)))));

        }
        escl_result = deescalate_shell(
                        channel   : channel,
                        obj_ch_id : obj_ch_id);
        if(isnull(escl_result)) return NULL;
      }
      cmd_logger.add(
        cmd                : this.cmd_last,
        response           : ret,
        error              : session.cmd_error,
        ran_with_priv_escl : this.escalated_shell || least_priv_escl,
        forced_escl        : force_priv_escl || least_priv_escl,
        priv_escl_failed   : FALSE,                     # exit on failed privesc
        escl_method        : this.priv_escalation_type,
        user               : session.user,
        escl_user          : session.user
      );
      return ret;


    }

    private function deescalate_shell(channel, obj_ch_id)
    {
      var fn  = 'deescalate_shell';
      channel.session.dbg_log(fn      : fn,
                              level   : DEBUG2,
                              message : "Deescalating shell");
      channel.clear_data_buf();
      this.set_cmd_prompt(this.previous_prompt);
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _IOS_CMD_STATE_SEND_REQ;
      channel.session.dbg_log(
          fn      : fn,
          level   : DEBUG2,
          message : "cmd_state:_IOS_CMD_STATE_SEND_REQ(" + this.cmd_state + ")" );
      channel.window_send_data(data:'disable\n');
      channel.session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @ios_shell_handler_incoming_data_timeout_or_prompt_cb,
        channel        : channel,
        cmd_timeout    : this.cmd_timeout
      );

      if ( this.cmd_state != _IOS_CMD_STATE_AT_PROMPT )
      {
        channel.session.set_cmd_error(obj_ch_id +
          "Unable to return to command prompt after last command.");
        this.last_cmd_error = TRUE;
        return NULL;
      }

      set_escalated_shell(FALSE);
      return TRUE;

    }

    private function escalate_shell(channel, obj_ch_id, tmp_bad_escl_kb, escl_hexstr)
    {
      var fn = 'escalate_shell';
      this.cmd_last = 'enable\n';
      channel.session.dbg_log(fn:fn, level:DEBUG2, message: obj_ch_id +
        "Sending command 'enable' to escalate shell.");
      channel.clear_data_buf();
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _IOS_CMD_STATE_SEND_ESCL_REQ;
      channel.session.dbg_log(fn:fn, level:DEBUG2, message:
        "cmd_state:_IOS_CMD_STATE_SEND_ESCL_REQ(" + this.cmd_state + ")" );
      channel.window_send_data(data:cmd_last);
      channel.session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @ios_shell_handler_enable_cb,
        channel        : channel,
        cmd_timeout    : this.cmd_timeout
      );

      # Check response for failure or success
      if ( channel.data_buf && !this.escalated_shell)
      {

        if ( "Invalid password" >< channel.data_buf || 
             "% Bad passwords" >< channel.data_buf  ||
             "% Access denied" >< channel.data_buf)
        {
          channel.session.set_cmd_error(
            remove_cmd_prompt(cmd_res:channel.data_buf));
          channel.session.set_cmd_error(obj_ch_id +
            "Privilege escalation appears to have failed. Removing " +
            "privilege escalation from credential set.");
          replace_kb_item(name:tmp_bad_escl_kb, value:escl_hexstr);
          this.priv_escl_failed = TRUE;
          channel.window_send_data(data:'\n\n');
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @ios_shell_handler_incoming_data_timeout_or_prompt_cb,
            channel        : channel,
            cmd_timeout    : this.cmd_timeout
          );
        }
        else if ( "ERROR: % Invalid input" >< channel.data_buf )
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Shell is already in admin mode.");
          set_escalated_shell(TRUE);
        }
      }

      if ( this.cmd_state != _IOS_CMD_STATE_AT_PROMPT )
      {
        channel.session.set_cmd_error(obj_ch_id +
          "Unable to return to command prompt after attempting to " +
          "escalate privileges. at state " + this.cmd_state);
        this.last_cmd_error = TRUE;
        return NULL;
      }
      return TRUE;
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
      var ret = substr(cmd_res, 0, idx-1);
      # remove null bytes so that it doesn't break ereg_replace
      ret = str_replace(string: ret, find:'\x00', replace:'');
      ret = ereg_replace(pattern:"([Mm]ore[^\x08\n]*)\n([^\x08\n]*\x08)", string:ret, replace:'\\1\\2');
      var tmp = '';
      var line;
      foreach line (split(ret))
      {
        line = ereg_replace(
                pattern:"^ *<?--+ *\(?[Mm]ore ?([0-9]+%)?\)? *--+>? *(.*( \x08+)+|(\x0d +\x0d*)?)",
                replace:"",
                string:line);

        line = ereg_replace(pattern:"(lines [0-9]+-[0-9]+(/[0-9]+( \(END\))?)? \x0d(\x07\x0d)?)", replace:"", string:line);

        tmp  += line;
      }

      ret = tmp;

      return ret;

    }

    function at_cmd_prompt(buf)
    {
      var channel = _FCT_ANON_ARGS[0];
      var lines = split(buf, sep:'\n', keep:FALSE);
      var last_line = lines[max_index(lines)-1];
      if(this.cmd_prompt && this.cmd_prompt >< last_line)
      {
        this.set_cmd_state(
           new_cmd_state: _IOS_CMD_STATE_AT_PROMPT,
           channel);
        return TRUE;
      }
    }

    public function at_prompt_or_timeout(channel)
    {
      if(at_cmd_prompt(buf:channel.data_buf, channel)) return TRUE;
      return check_inactivity_timeout(channel:channel);
    }

    public function check_inactivity_timeout(channel)
    {
      var fn = 'ios_shell_handler.check_inactivity_timeout';
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
