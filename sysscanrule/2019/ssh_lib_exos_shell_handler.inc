#TRUSTED ad53aa1fe41522e0deb7ddcab75c56ad35f0f4ec25a474e2a5fc9c25f374fe0737b643126e315408e436c1bb313e06bc13abd3617d2792b4e550e6fa956d6c0c02a9bacec660f48926f797cb0819cae7c829ff94be7524fbee25592ef6bbf5ee9cbb8584ba2cd49a2a0aded3f5a7573b3fd628acaacb223f92efb8807ea26526778d30e87d69529b9c46083f32ffeb09247043bde778261a7ff6293907b4b8c0d4eee6f3081812c0b51b9fb36e74170d37ccdee357198fb7611b7e76fa37348fd131be3463e0764085fe4145adccdb97b1e82e149ee0ed643f2a2b01da669b26f05c7458a4089999d60f2b24860007a1d9a89f70d7fc02cb5554f10a3b6c35069de504e9dc3c8ed2904594abf63d3943b608f6a1f6ab9f95b5698b07d42773f5f02b19aeb8f1a86f3f29083ac54dee45d7f445a07b3bc009a9884eac19a1030b525a9c361145d8fcb07ddbc27741a4c253fe2fa2f50ac81683516d50ca80717aea14073281069b05b902d0a66477cb452faacc1eecf9a0f1a33d8db0026621fb6e0c9bb897f21ed88463793ecc61d490b67046c4b304fa346cee10c8d819a80a5de2a239c10bcfd1b862b77f7db95030622ec054b5709b9a381abd82d98080cc9a1d6ab7ada19542b651507ad726be8fbd32c9bbd56016fee68a88f4bb6ddcbeb376b1980f5517e2d4d8e62d38be62b35f89636b154ba7495606a8288752aaa4

#
# (C) WebRAY Network Security, Inc.
#

namespace sshlib
{

  # all timeouts are controlled by a timer with 1s resolution
  # for that reason keep the shell timeout sufficiently beyond
  # the timer resolution (10s = 10x resolution)
  global_var _EXOS_DEFAULT_CMD_TIMEOUT = 10;
  global_var _EXOS_DEFAULT_INACTIVITY_TIMEOUT = 10;

  # a space is included in shell prompt
  global_var _EXOS_DEFAULT_PROMPT = "> ";

  # cmd_states
  # _EXOS_CMD_STATE_SEND_REQ: ready to send a command to device
  # _EXOS_CMD_STATE_RECV_RSP: ready to recv a response from device

  global_var _EXOS_CMD_STATE_SEND_REQ = 0;
  global_var _EXOS_CMD_STATE_RECV_RSP = 1;

  # a space is included in shell prompt
  global_var _EXOS_DEFAULT_ENABLE_PROMPT = "Password: ";

  function exos_shell_handler_incoming_data_cb( session, channel )
  {
    var fn = 'exos_shell_handler_incoming_data_cb';
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
      # no shell handler on channel, oops cant proceed
      return FALSE;
    }
    var sh = channel.shell_handler;
    var cmd_state = sh.cmd_state;
    var cmd_last = sh.cmd_last;
    var buf_length = strlen( channel.data_buf );
    # Decision is based on command state

    if ( cmd_state == _EXOS_CMD_STATE_SEND_REQ )
    {
      # Sent command to device, waiting echo back of last command
      if ( buf_length >= strlen(cmd_last) )
      {
        var last = substr( channel.data_buf, buf_length - strlen(cmd_last) );
        if ( last == cmd_last )
        {
          sh.set_cmd_state( new_cmd_state:_EXOS_CMD_STATE_RECV_RSP );
          channel.session.dbg_log(fn:fn, level:DEBUG2, message: "cmd_state: " + sh.cmd_state);
          channel.clear_data_buf();
          channel.window_send_data(data:'\n');
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
          channel.session.dbg_log(fn:fn, level:DEBUG2, message: "found prompt");
          return TRUE;
        }
      }

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
          channel.window_send_data(data:sh.cmd_enable_password + '\n' );
          return FALSE;
        }
      }
    }
    return sh.check_inactivity_timeout(channel:channel);
  }
  ### END RECV_UNTIL CALLBACKS ###

  # exos shell handler
  object exos_shell_handler
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

    function exos_shell_handler()
    {
      this.init();
    }

    public function init(settings)
    {
      this.cmd_last = "";
      this.cmd_prompt = _EXOS_DEFAULT_PROMPT;
      this.cmd_timeout = _EXOS_DEFAULT_CMD_TIMEOUT;
      this.inactivity_timeout = _EXOS_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_enable_prompt = _EXOS_DEFAULT_ENABLE_PROMPT;
      this.cmd_state = _EXOS_CMD_STATE_SEND_REQ;

      if (!isnull(settings))
      {
        this.settings = settings;
        if ( !isnull(this.settings['cmd_prompt']) ) this.cmd_prompt = this.settings['cmd_prompt'];
        if ( !isnull(this.settings['cmd_timeout']) ) this.cmd_timeout = this.settings['cmd_timeout'];
        if ( !isnull(this.settings['cmd_enable_prompt']) ) this.cmd_enable_prompt = this.settings['cmd_enable_prompt'];
        if ( !isnull(this.settings['cmd_enable_password']) ) this.cmd_enable_password = this.settings['cmd_enable_password'];
      }
    }

    # Called on all shell handlers in ssh_lib.inc so we have to define it here
    public function set_priv_escalation(type, extra)
    {
      return FALSE;
    }

    # Called on all shell handlers in ssh_lib.inc so we have to define it here
    public function unset_priv_escalation()
    {
      return FALSE;
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
      var fn = 'exos_shell_handler.check_inactivity_timeout';
      if ( channel && channel.data_buf && strlen(channel.data_buf) > 0 )
      {
        var new_md5 = MD5( channel.data_buf );
        if ( this.last_md5 != new_md5 )
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:'exos_shell_handler [channel ' + channel.local_channel + ']: Channel data buffer updated, resetting shell inactivity timer.\n');
          this.last_md5 = new_md5;
          this.last_buffer_update_ts = unixtime();
          return FALSE;
        }
      }
      if ((unixtime() - this.last_buffer_update_ts) >= this.inactivity_timeout)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:'exos_shell_handler [channel ' + channel.local_channel + ']: reached timeout limit [' + this.inactivity_timeout + 's].\n');
        return TRUE;
      }
      return FALSE;
    }

    public function on_channel_buffer_inactivity(channel)
    {
      var fn = 'exos_shell_handler.on_channel_buffer_inactivity';
      channel.session.dbg_log(fn:fn, level:DEBUG2, message:'exos_shell_handler [channel ' + channel.local_channel + ']: buffer inactivity\n');
      return check_inactivity_timeout(channel:channel);
    }

    public function set_cmd_state(new_cmd_state)
    {
      this.cmd_state = new_cmd_state;
    }

    public function run_command(channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = 'exos_shell_handler.run_command';
      var obj_ch_id = 'exos_shell_handler [channel '+channel.local_channel+']: ';

      if ( isnull(channel) )
      {
        return NULL;
      }
      if ( isnull(command) )
      {
        return NULL;
      }
      this.cmd_last = command;

      # Reset default timeouts
      this.inactivity_timeout = _EXOS_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _EXOS_DEFAULT_CMD_TIMEOUT;

      # If custom inactivity_timeout and cmd_timeout values are passed,
      # ensure the values in use meet or exceed passed values
      if (inactivity_timeout_min &&
          this.inactivity_timeout < inactivity_timeout_min)
        this.inactivity_timeout = inactivity_timeout_min;

      if (cmd_timeout_min &&
          this.cmd_timeout < cmd_timeout_min)
        this.cmd_timeout = cmd_timeout_min;

      channel.session.reset_cmd_interrupted();

      channel.session.dbg_log(fn:fn, level:DEBUG2, message: "sending command: " + cmd_last);
      channel.clear_data_buf();
      this.last_buffer_update_ts = unixtime();
      this.cmd_state = _EXOS_CMD_STATE_SEND_REQ;
      channel.window_send_data(data:cmd_last);
      channel.session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : @exos_shell_handler_incoming_data_cb,
        channel        : channel,
        cmd_timeout    : cmd_timeout
      );
      if(channel && channel.data_buf && this.cmd_state != _EXOS_CMD_STATE_SEND_REQ)
      {
        return chomp(string_reverse(chomp(string_reverse(channel.data_buf))));
      }
      return NULL;
    }
  }
}


