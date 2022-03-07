#TRUSTED 0f825e7ed8b8d49bcccbd6ba4e857361e07ebf1506cf5f49cf79afc84af805ab2d5824535554722ae5f0579e9a2441fe683d43fe9eb24df15715e0118b7a4915cb9595043c7e11f11e89c4e044b44039e8df730f2bc49aea2f5bba2053183ae6363c95f3c1e12555a0d5299fe07f2ec29fd49d6f7ccc354fe323037d476aead0d32c6cedccd6a52d961e0da9b5c261bf6346870d4f523419969363f23f4ca129261ad03a8aed03c7df5dee27376be3a0c16d1a07c086cfb11ccb9fe9e2375a814c3492628d6b6675a42033cb3bbe5af8568244622f300c4a3c1fcc67af03d65be71775a0645d0f51dd13efcf93e9c92c755e480506664a3d5b6bc5591b1bc84d02b130cff39398c44e68a5e4a50d157f259388f7ab9c3805bbe08c46312c599febd571d34b104ac73ea6eae18a497a7b8fbac95479c5d7301384261d8c23108a9ffea677a1e37e43c7894349b68aa1a232122dabb31486b41017a94e301a5649e675406b956f7150b2a77242433186b5273f7d4644e42c8e23f32f5c804d55a1f149e1217d9d91b54d68948e1b0e604678d0d32715731fffe300b6da84e157d14a08f92253cc96593a4b7416d1943d15b1aa8ea5fe14e2bb36c143fff21cd18aa68af1bd4fa69ef83b54ec39319ca74ba7d2a28efe9052822b1b1f7232c835b0ada6ac1d4f08cd7d1ffa88450ff5e8171f9c1addb713255c5e4782c91dac2e6b
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# Revision:1.0
#
###

include("ssh_lib_util.inc");
include("ssh_lib_shell_handler.inc");

namespace sshlib
{
  DEFAULT_PRIV_ESCL_WARNING_TIMEOUT = 3;
  global_var _SH_DEFAULT_INACTIVITY_TIMEOUT = 60;
  global_var _SH_INITIAL_INACTIVITY_TIMEOUT = 5;
  global_var _SH_DEFAULT_CMD_TIMEOUT = NULL;
  global_var _PAGINATION_SONICWALL = FALSE;
  ### RECV_UNTIL CALLBACKS ###

  ##
  # callback function that checks for either a timeout or buffer end marker
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if timeout reached
  # @category SSH
  ##
  function sh_shell_handler_misc_callback_end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }
    return shell_handler.end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout(channel:channel);
  }

  ##
  # callback function that checks for either a timeout or buffer update
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if timeout reached
  # @category SSH
  ##
  function sh_shell_handler_misc_on_channel_buffer_update_or_timeout(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }

    return shell_handler.on_channel_buffer_update_or_timeout(channel:channel);
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
  function sh_shell_handler_misc_on_channel_buffer_inactivity(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }
    return shell_handler.on_channel_buffer_inactivity(channel:channel);
  }

  ##
  # callback function that checks for timeout or password prompt
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if found
  # @category SSH
  ##
  function sh_shell_handler_misc_password_prompt_or_timeout(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }

    return shell_handler.password_prompt_or_timeout(channel:channel);
  }

  ##
  # callback function that checks for either a timeout,
  # password prompt, or start/end marker
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return True if found
  # @category SSH
  ##
  function sh_shell_handler_misc_start_marker_or_end_marker_or_password_prompt_or_timeout(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }

    return shell_handler.start_marker_or_end_marker_or_password_prompt_or_timeout(channel:channel);
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
  function sh_shell_handler_misc_at_prompt3_or_timeout(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }

    return shell_handler.at_prompt3_or_timeout(channel:channel);
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
  function sh_shell_handler_misc_at_prompt2_or_timeout(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }

    return shell_handler.at_prompt2_or_timeout(channel:channel);
  }

  ##
  # callback function to determine is we are back at promot
  # for sonicwall devices only. This will handle pagination
  # for certain commands when necessary.
  # Using global variable _PAGINATION_SONICWALL
  #
  # @param session session handle for ssh session
  # @param channel channel for ssh session
  #
  # @return TRUE if found
  # @category SSH
  ##
  function sh_shell_handler_misc_at_prompt2_or_timeout_sonicwall(session, channel)
  {
    var shell_handler = channel.shell_handler;
    if(!shell_handler)
    {
      spad_log(message:'sh_shell_handler_misc [channel ' +
        channel.local_channel + ']: Channel is closed.');
      return TRUE;
    }

    var lines = split(channel.data_buf, sep:'\n', keep:FALSE);
    var last_line = lines[max_index(lines)-1];
    if("--MORE--" >< last_line || "--more--" >< last_line)
    {
      _PAGINATION_SONICWALL = TRUE;
      channel.window_send_data(data:' ');
      return FALSE;
    }
    return shell_handler.at_prompt2_or_timeout(channel:channel);
  }

  ### END RECV_UNTIL CALLBACKS ###

  # alternate unix sh/bash shell handler
  object sh_shell_handler_misc
  {
    var use_priv_escl = FALSE;
    var fresh_shell = TRUE;
    var priv_escalation_type;
    var priv_escalation_extra;
    var escl_method_in_use;
    var supported_escalation_methods;
    var last_buffer_update_ts;
    var cur_user;
    var cur_buf = "";
    var cur_buf_change_counter = 0;
    # this can be set in class before using sshrecv_until.  this will cause the callback check functions to
    # return after a given inactivity period (no channel data updates)
    var timeout_check;
    var timed_out = FALSE;
    var password_prompt_locations_in_buffer;

    var found_password_prompt;
    var command_result_found;

    # did we run into a problem running last command? if so set this, so we don't
    # try running more
    var last_cmd_error = FALSE;

    # buffer received after initial login before shell starts waiting for input, include prompt
    var post_login_buffer = NULL;
    var cmd_prompt = NULL;

    # number of seconds of inactivity before we assume shell is ready for input
    var initial_inactivity_period = _SH_INITIAL_INACTIVITY_TIMEOUT;
    # timeout for sshrecv for initial wait to reach command prompt post login
    var initial_recv_timeout = 2;
    # default buffer inactivity timeout check
    var inactivity_timeout = _SH_DEFAULT_INACTIVITY_TIMEOUT;
    # default timeout for individual recv
    var recv_timeout = 2;
    # default timeout for cmd_timeout (no default)
    var cmd_timeout = _SH_DEFAULT_CMD_TIMEOUT;

    # random strings to look for that wrap the command
    var end_rand_str;
    var start_rand_str;
    # random strings to look for that wrap privilege escalation
    var escl_marker_start_rand_str;
    var escl_marker_end_rand_str;
    # This is set by sudo_escl_each_command() if least privilege is enabled
    var num_cmds;

    # These are set per-command for logging
    var escl_user = "";
    var escl_method = "";

    var priv_escl_bad_password;
    var priv_escl_warning_timeout = DEFAULT_PRIV_ESCL_WARNING_TIMEOUT;
    var sent_priv_escl_timeout_warning = FALSE;

    var settings;

    var ksh_default;
    var echo_checked;

    var objname = 'sh_shell_handler_misc';

    ##
    # Shell handler initialization caller
    # @category SSH
    ##
    function sh_shell_handler_misc()
    {
      supported_escalation_methods = make_list("sudo", "su", "su_sudo", "dzdo", "pbrun");
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
      this.priv_escalation_type = this.settings['priv_escalation_type'];
      this.priv_escalation_extra = this.settings['priv_escalation_extra'];
      this.cmd_prompt = this.settings['cmd_prompt'];
      this.fresh_shell = TRUE;
      this.cur_buf = "";
      this.cur_buf_change_counter = 0;
      this.last_cmd_error = FALSE;
      this.end_rand_str = NULL;
      this.start_rand_str = NULL;
      this.found_password_prompt = FALSE;
      this.command_result_found = FALSE;
      this.ksh_default = FALSE;
      if(!isnull(this.settings['ksh_default']))
        this.ksh_default = this.settings['ksh_default'];
      this.echo_checked = FALSE;
    }

    ##
    # Returns escalation method
    # @return escalation method
    # @category SSH
    ##
    public function get_supported_escalation_method()
    {
      var method;
      foreach method (supported_escalation_methods)
        if(method == this.priv_escalation_type) return method;
    }

    ##
    # Returns carriage return opcode if the default shell is not ksh
    # else returns carriage return opcode and echo opcode
    # @return list of required pty opcodes
    # @category SSH
    ##
    public function get_pty_opts()
    {
      if(this.ksh_default)
      {
        return make_array(
              PTY_OPT_ECHO, mkdword(1, order:BYTE_ORDER_BIG_ENDIAN),
              PTY_OPT_OCRNL, mkdword(0, order:BYTE_ORDER_BIG_ENDIAN)
            );
      }
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
      this.priv_escalation_type = type;
      this.priv_escalation_extra = extra;
      this.settings['priv_escalation_type'] = type;
      this.settings['priv_escalation_extra'] = extra;
    }

    ##
    # unset priv escalation
    # @category SSH
    ##
    public function unset_priv_escalation()
    {
      this.priv_escalation_type = NULL;
      this.priv_escalation_extra = NULL;
      this.settings['priv_escalation_type'] = NULL;
      this.settings['priv_escalation_extra'] = NULL;
    }

    ##
    # set ksh as the default shell
    # @category SSH
    ##
    public function set_ksh_default()
    {
      this.ksh_default = TRUE;
      this.echo_checked = TRUE;
      this.settings['ksh_default'] = TRUE;
    }

    public function set_echo_checked()
    {
      this.echo_checked = TRUE;
    }

    ##
    # Determine if the ECHO pty opcode is required. Currently checks
    # the $SHELL environment for ksh
    # @return TRUE if ECHO is required, else FALSE
    # @category FALSE
    ##
    public function is_echo_required(channel, session)
    {
      var res;
      # We already know this is required, so ECHO has already been set
      # or this has already been checked, so we don't need to check again
      if(this.ksh_default || this.echo_checked)
        return FALSE;

      res = run_command(channel:channel, command:"echo $SHELL | awk -F'/' '{print $NF}'", raw:TRUE);
      session.dbg_log(
            fn:this.objname + '.' + FUNCTION_NAME,
            level:DEBUG3,
            message:'echo $SHELL results : '+serialize(res));
      if(isnull(res))
        replace_kb_item(name:SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + '/default_shell', value:'UNKNOWN');
      else
      {
        res = strip(res);
        replace_kb_item(name:SSH_LIB_KB_PREFIX + session.get_kb_connection_id() + '/default_shell', value:res);
      }
      if(res == 'ksh')
      {
        # Set ksh_default so that ECHO pty option will be sent on a new channel request
        this.set_ksh_default();
        # Set last_cmd_error so that a new channel will be requested before the next command is run
        this.last_cmd_error = TRUE;
      }


      this.echo_checked = TRUE;
      return this.ksh_default;
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
    function send_command_by_line_length(cmd, max_cmd_len, channel)
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
    function check_inactivity_timeout(channel)
    {
      var fn = 'sh_shell_handler_misc.check_inactivity_timeout';
      this.timed_out = FALSE;
      if(channel.state == CHANNEL_STATE_CLOSED)
      {
        spad_log(message:fn + ' [channel ' +
          channel.local_channel + ']: Channel is closed.');
        return TRUE;
      }
      if(channel.buf_change_counter != cur_buf_change_counter)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:'sh_shell_handler_misc [channel ' + channel.local_channel + ']: Channel data buffer updated, resetting shell inactivity timer.\n');
        cur_buf_change_counter = channel.buf_change_counter;
        this.last_buffer_update_ts = unixtime();
      }
      else
      {
        if (this.use_priv_escl && this.escl_method_in_use &&
            !this.sent_priv_escl_timeout_warning &&
            (unixtime() - this.last_buffer_update_ts) >= this.priv_escl_warning_timeout)
        {
          spad_log(message:'sh_shell_handler_misc [channel ' + channel.local_channel + ']: Privilege escalation (using '
                +this.escl_method_in_use+') has taken over '+(unixtime() - this.last_buffer_update_ts)+'s, '
                +'which may be indicative of a misconfigured host or domain name.\n');
          this.sent_priv_escl_timeout_warning = TRUE;
        }

        if ((unixtime() - this.last_buffer_update_ts) >= this.timeout_check)
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:'sh_shell_handler_misc [channel ' + channel.local_channel + ']: reached recv timeout limit [' + this.timeout_check + 's].\n');
          this.timed_out = TRUE;
          return TRUE;
        }
      }
    }

    ##
    # function to check for new password prompt
    #
    # @param buf buffer
    #
    # @return TRUE if found
    # @category SSH
    ##
    function found_new_password_prompt(buf)
    {
      var item;
      var offset = 0;

      if(!isnull(password_prompt_locations_in_buffer))
      {
        offset = password_prompt_locations_in_buffer[max_index(password_prompt_locations_in_buffer) - 1];
        buf = substr(buf, offset);
      }

      if(buf == '') return FALSE;

      item = pregmatch(pattern:"([Pp]assword:[\s]{0,1})($|[\r\n]|[Pp]assword:)", string:buf);
      if(isnull(item) && this.escl_method_in_use == "pbrun")
        item = pregmatch(pattern:"(Authenticate " + cur_user + ":[\s]{0,1})", string:buf);

      if(!isnull(item))
      {
        var new_off = offset;
        new_off += strlen(item[1]);
        new_off += stridx(buf, item[1]);

        if(isnull(password_prompt_locations_in_buffer)) password_prompt_locations_in_buffer = make_list();

        password_prompt_locations_in_buffer = make_list(password_prompt_locations_in_buffer, new_off);
        return TRUE;
      }
      return FALSE;
    }

    ##
    # function to check for timeout or password prompt
    #
    # @param channel channel
    #
    # @return TRUE if found
    # @category SSH
    ##
    public function password_prompt_or_timeout(channel)
    {
      if(found_new_password_prompt(buf:channel.data_buf))
      {
        this.found_password_prompt = TRUE;
        return TRUE;
      }
      return check_inactivity_timeout(channel:channel);
    }


    ##
    # function to check for password prompt, start/end marker, or timeout
    # @param channel channel for ssh session
    #
    # @return TRUE if found
    # @category SSH
    ##
    public function start_marker_or_end_marker_or_password_prompt_or_timeout(channel)
    {
      if(("priv_escl_start_" + escl_marker_start_rand_str) >< channel.data_buf && found_new_password_prompt(buf:channel.data_buf))
      {
        this.found_password_prompt = TRUE;
        return TRUE;
      }
      else if(("command_start_" + start_rand_str) >< channel.data_buf)
      {
        return TRUE;
      }
      else if(("priv_escl_end_" + escl_marker_end_rand_str) >< channel.data_buf) return TRUE; # can happen on error (e.g. command not found)
      return check_inactivity_timeout(channel:channel);
    }

    ##
    # function to check for escalation failure or timeout
    # @param channel channel for ssh session
    #
    # @return TRUE
    # @category SSH
    ##
    public function end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout(channel)
    {
      var command_start = "command_start_" + start_rand_str;

      if(command_start >< channel.data_buf)
        this.command_result_found = TRUE;

      if( (this.escl_method_in_use == "su_sudo" &&
           max_index(password_prompt_locations_in_buffer) < 2) ||
          (this.escl_method_in_use == "sudo" &&
           use_priv_escl && SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED)
      )
      {
        if(found_new_password_prompt(buf:channel.data_buf))
        {
          this.found_password_prompt = TRUE;
          return TRUE;
        }
      }
      if(!this.command_result_found &&
          (tolower(channel.buf_tail.get()) =~ "incorrect password" ||
           tolower(channel.buf_tail.get()) =~ "sorry, try again.*password:\s*$"))
      {
        if(
            (this.escl_method_in_use != "sudo" && command_start >!< channel.data_buf && !priv_escl_bad_password) ||
            (this.escl_method_in_use == "sudo" && !priv_escl_bad_password)
            )
        {
          priv_escl_bad_password = TRUE;
          return TRUE;
        }
      }
      if(("priv_escl_end_" + escl_marker_end_rand_str) >< channel.buf_tail.get()) return TRUE;
      if(("command_done_" + end_rand_str) >< channel.buf_tail.get()) return TRUE;

      return check_inactivity_timeout(channel:channel);
   }

    ##
    # function to check for buffer update or inactivity timeout
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if found
    # @category SSH
    ##
    public function on_channel_buffer_update_or_timeout(channel)
    {
      if(channel.buf_change_counter != cur_buf_change_counter)
      {
        cur_buf_change_counter = channel.buf_change_counter;
        return TRUE;
      }
      return check_inactivity_timeout(channel:channel);
    }

    ##
    # check for prompt or inactivity timeout
    #
    # @param channel channel for ssh session
    #
    # @return TRUE
    # @category SSH
    ##
    public function at_prompt3_or_timeout(channel)
    {
      if(at_cmd_prompt(buf:channel.data_buf, check_len:3)) return TRUE;
      return check_inactivity_timeout(channel:channel);
    }


    ##
    # check for prompt or inactivity timeout with 2 character prompt
    #
    # @param channel channel for ssh session
    #
    # @return TRUE
    # @category SSH
    ##
    public function at_prompt2_or_timeout(channel)
    {
      if(at_cmd_prompt(buf:channel.data_buf, check_len:2)) return TRUE;
      return check_inactivity_timeout(channel:channel);
    }

    ##
    # check for buffer or inactivity timeout
    #
    # @param channel channel for ssh session
    #
    # @return TRUE if found
    # @category SSH
    ##
    public function on_channel_buffer_inactivity(channel)
    {
      if(fresh_shell && !isnull(post_login_buffer))
      {
        if(post_login_buffer >< channel.data_buf) return TRUE;
      }
      return check_inactivity_timeout(channel:channel);
    }

    ##
    # determine if we are at command prompt
    #
    # @param channel channel
    #
    # @return TRUE if found
    # @category SSH
    ##
    function at_cmd_prompt(buf, check_len)
    {
      var sub_prompt = substr(cmd_prompt, strlen(cmd_prompt) - check_len, strlen(cmd_prompt) - 1);
      if(strlen(buf) < check_len) return FALSE;
      var sub_buf = substr(buf, strlen(buf) - check_len, strlen(buf) - 1);
      if(sub_prompt == sub_buf)
        return TRUE;
    }

    ##
    # Add command_start_<randstr> and command_done_<randstr> tokens
    #
    # @param [command:string] The original command sent to run_command
    #
    # @return [string] command wrapped in start/done tokens
    ##
    public function add_command_tokens(command)
    {
      this.end_rand_str = rand_str(length:8);
      this.start_rand_str = rand_str(length:8);

      var end_head = '; printf "command_done_%s" "';
      if(pregmatch(pattern:";\s*$", string:command))
      {
        end_head = ' printf "command_done_%s" "';
      }

      # some shells echo, some don't (regardless of pty options), so
      # wrap command to handle that
      return 'printf "command_start_%s" "' + this.start_rand_str +
        '"; ' + command + end_head + this.end_rand_str + '"';
    }

    ##
    # Add privilege escalation to command string, plus
    # priv_escl_start_<randstr> and priv_escl_end_<randstr> tokens
    #
    # @param [command:string] The command string returned from
    #                         add_command_tokens()
    # @param [saved_cmd:string] The original command as sent to
    #                           run_command()
    # @param [escl_type:string] The escalation type/method to add
    #
    # @return [string] The command string with privilege escalation
    #                  wrapped in priv_escl start/end tokens
    ##
    public function add_priv_escl_to_command(command, saved_cmd, escl_type)
    {
      # Initialize object vars
      this.escl_marker_start_rand_str = rand_str(length:8);
      this.escl_marker_end_rand_str = rand_str(length:8);

      var new_command = command;

      # Escape characters in command as necessary
      # Most escalation methods need ' escaped because the command
      # will be inside ''
      new_command = str_replace(find:"'", replace:"'\''", string:new_command);
      # su_sudo needs extra escaping because it is inside
      # both '' and ""
      if (escl_type == "su_sudo")
      {
        new_command = str_replace(find:'"', replace:'\\"', string:new_command);
        new_command = str_replace(find:'$', replace:'\\$', string:new_command);
      }

      # Generate path_prefix for cmd_prefix
      var path_prefix = "";

      if (escl_type == "sudo")
        path_prefix = this.priv_escalation_extra["sudo_dir"];
      else if (
        escl_type == "su" ||
        escl_type == "su_sudo"
      )
        path_prefix = this.priv_escalation_extra["su_dir"];
      else if (escl_type == "pbrun")
        path_prefix = this.priv_escalation_extra["pbrun_dir"];
      else if (escl_type == "dzdo")
        path_prefix = this.priv_escalation_extra["dzdo_dir"];

      if (strlen(path_prefix) > 0)
      {
        if (path_prefix[strlen(path_prefix) - 1] != '/')
          path_prefix = path_prefix + '/';
      }

      # Generate cmd_prefix
      var cmd_prefix =
        'printf "priv_escl_start_%s" "' +
        this.escl_marker_start_rand_str + '"; ' + path_prefix;

      # Add privilege escalation
      if (escl_type == "sudo")
      {
        # If least privilege is enabled, the command string needs to
        # be split so that each command can be escalated
        if (SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED)
        {
          new_command =
            this.sudo_escl_each_command(saved_cmd:saved_cmd,
              path_prefix:path_prefix);
        }
        # Splitting the command string isn't necessary when least
        # privilege is not enabled
        else
        {
          new_command =
            cmd_prefix + "sudo -u " +
            this.priv_escalation_extra["sudo_user"] +
            " -p Password: sh -c '" + new_command + "'";
        }
        this.escl_user = this.priv_escalation_extra["sudo_user"];
      }
      else if (escl_type == "su")
      {
        new_command =
          cmd_prefix + "su " + this.priv_escalation_extra["su_user"] +
          " -c '" + new_command + "'";
        this.escl_user = this.priv_escalation_extra["su_user"];
      }
      else if (escl_type == "su_sudo")
      {
        # Path prefix for sudo; the path_prefix for su is already in
        # the cmd_prefix
        path_prefix = this.priv_escalation_extra["sudo_dir"];
        if (strlen(path_prefix) > 0)
        {
          if (path_prefix[strlen(path_prefix) - 1] != '/')
            path_prefix = path_prefix + '/';
        }
        new_command =
          cmd_prefix + "su " + this.priv_escalation_extra["su_user"] +
          ' -c "' + path_prefix + "sudo -S -u " +
          this.priv_escalation_extra["sudo_user"] +
          " -p Password: sh -c '" + new_command + '\'"';
        # Friendly escl_method and escl_user for logging
        this.escl_method = "su + sudo";
        this.escl_user =
          this.priv_escalation_extra["su_user"] + " + " +
          this.priv_escalation_extra["sudo_user"];
      }
      else if (escl_type == "dzdo")
      {
        new_command =
          cmd_prefix + "dzdo -u " +
          this.priv_escalation_extra["dzdo_user"] +
          " -p Password: sh -c '" + new_command + "'";
        this.escl_user = this.priv_escalation_extra["dzdo_user"];
      }
      else if (escl_type == "pbrun")
      {
        new_command =
          cmd_prefix + "pbrun -u " +
          this.priv_escalation_extra["pbrun_user"] +
          " sh -c '" + new_command + "'";
        this.escl_user = this.priv_escalation_extra["pbrun_user"];
      }
      else
      {
        spad_log(message:
          'sh_shell_handler_misc::add_priv_escl_to_command(): ' +
          'Unsupported escl_type "'+escl_type+'" received, ' +
          'returning command unchanged.');
        return command;
      }

      # Add priv_escl_end token
      new_command +=
        '; printf "priv_escl_end_%s" "' +
        this.escl_marker_end_rand_str + '"';

      return new_command;
    }

    ##
    # Splits the original command string into individual commands
    # and adds sudo privilege escalation to each command
    #
    # @param [saved_cmd:string] The original command as sent to
    #                           run_command()
    # @param [path_prefix:string] (optional) The path_prefix for the
    #                             sudo binary, e.g. /usr/bin/
    #                             add_priv_escl_to_command() will
    #                             always send this, but it's also set
    #                             here to allow testing individually
    #
    # @return [string] The command string with each command escalated
    #                  separately, prepended by priv_escl_start token
    ##
    public function sudo_escl_each_command(saved_cmd, path_prefix)
    {
      # The command start/done tokens will be added back later, they
      # do not need to be escalated
      var command = saved_cmd;

      # Set prefixes
      if (!path_prefix)
      {
        path_prefix = this.priv_escalation_extra["sudo_dir"];
        if (strlen(path_prefix) > 0)
        {
          if (path_prefix[strlen(path_prefix) - 1] != '/')
            path_prefix = path_prefix + '/';
        }
      }
      var cmd_prefix =
        'printf "priv_escl_start_%s" "' +
        this.escl_marker_start_rand_str + '"; ';

      # Escalate each command individually
      var sudo_str =
        path_prefix + "sudo -u " +
        this.priv_escalation_extra["sudo_user"] + " -p Password: ";

      var exclude_str = '(?!\\s*LANG=C\\s*(;|(\\|\\|)|(\\&\\&))?)';
      # Place sudo_str before first command
      if (command !~ "^LANG=C;")
        command = sudo_str + command;
      # After &&
      command = ereg_replace(string:command, pattern:'\\&\\&'+exclude_str,
        replace:"&& "+sudo_str);
      # After ||
      command = ereg_replace(string:command, pattern:'\\|\\|'+exclude_str,
        replace:"|| "+sudo_str);
      # After ;
      command = ereg_replace(string:command, pattern:";(?!(\s*LANG=C\s*(;|(\|\|)|(\&\&))?)|\s*$)",
        replace:"; "+sudo_str);

      # Count how many sudo_str instances are in the command so that
      # run_command() knows how many password prompts to expect
      var tmp = split(command, sep:sudo_str, keep:FALSE);
      this.num_cmds = max_index(tmp) - 1;

      # Add ; before command_done token only if necessary
      var end_head = '; printf "command_done_%s" "';
      if(pregmatch(pattern:";\s*$", string:command))
      {
        end_head = ' printf "command_done_%s" "';
      }

      # printf commands are not escalated
      command =
        'printf "command_start_%s" "' + start_rand_str + '"; ' +
        command + end_head + end_rand_str + '"';

      # Add priv_escl_start token
      command = cmd_prefix + command;

      return command;
    }

    ##
    # Check to determine if privilege escalation failed
    #
    # @param cmd_res result of remote command
    #
    # @return TRUE if failed
    # @category SSH
    ##
    function did_priv_escl_fail(cmd_res)
    {
      cmd_res = tolower(cmd_res);
      if(!this.command_result_found &&
         ( cmd_res =~ "not in the sudoers file" ||
           cmd_res =~ "not allowed to execute" ||
           cmd_res =~ "sorry, try again.*password:\s*$" ||
           cmd_res =~ "incorrect password"))
        return TRUE;
      else return FALSE;
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
    private function set_timeouts(inactivity_timeout_min, cmd_timeout_min)
    {
      # Reset default timeouts
      this.inactivity_timeout = _SH_DEFAULT_INACTIVITY_TIMEOUT;
      this.cmd_timeout = _SH_DEFAULT_CMD_TIMEOUT;

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
    # Set shell escalation variables
    #
    # @param force_priv_escl force priv escalation flag
    # @param channel channel for ssh session
    # @param command cmd to run
    # @param cmd_logger the command logger used to determine if 
    #                   escalation is required
    #
    # @return NULL
    # @category SSH
    ##
    private function setup_escl(force_priv_escl, command, channel, cmd_logger)
    {
      var obj_ch_id = 'sh_shell_handler_misc [channel '+channel.local_channel+']: ';
      if(get_kb_item("SSH/attempt_least_privilege"))
        SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED = TRUE;
      else use_priv_escl = TRUE;

      if(force_priv_escl) use_priv_escl = TRUE;

      if(!use_priv_escl)
      {
        if(cmd_logger.should_escl_privs(cmd:command))
        {
          channel.session.dbg_log(fn:FUNCTION_NAME, level:DEBUG1, message:obj_ch_id +
            "Same command ran previously using privilege escalation, forcing privilege escalation.");
          use_priv_escl = TRUE;
        }
      }

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
    # @param raw Run a command raw in the default shell. No escalation or
    #             wrapping is done
    # @param sonicwall (boolean) flag to enable checking for sonicwall
    #                   pagination. Sonicwall devices use sh shell handler
    #                   for limited shell handling through raw command.
    #
    # @return command result or NULL on failure
    # @category SSH
    ##
    public function run_command(channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min, raw, sonicwall)
    {
      # Check shell state
      var obj_ch_id = 'sh_shell_handler_misc [channel '+channel.local_channel+']: ';
      if(last_cmd_error)
      {
        return channel.session.set_error(obj_ch_id +
          'ERROR - shell is in unknown state from last interaction, ' +
          'no additional commands via this shell will be executed.');
      }

      # Initialize variables and determine if escalation should be used
      set_timeouts(inactivity_timeout_min:inactivity_timeout_min,
          cmd_timeout_min:cmd_timeout_min);

      var cmd_logger = new("sshlib::cmd_logger");
      this.command_result_found = FALSE;


      var saved_cmd = command;
      var fn = 'sh_shell_handler_misc.run_command';
      cur_user = channel.session.user;
      escl_user = "";
      escl_method = "";

      if(isnull(force_priv_escl)) force_priv_escl = FALSE;
      if(isnull(raw)) raw = FALSE;

      if(!raw)
        setup_escl(force_priv_escl:force_priv_escl, command:command, cmd_logger:cmd_logger, channel:channel);
      else
      {
        channel.session.dbg_log(fn:fn,
            level:DEBUG3,
            message:"Running raw command. No escalation or command wrapping "+
                    "will be used.");
        use_priv_escl = FALSE;
      }

      var item, kb_id, tmp_bad_escl_kb, msg, ran_with_priv_escl;
      var priv_escl_failed, cb;

      kb_id = channel.session.get_kb_connection_id();
      tmp_bad_escl_kb = "tmp/"+kb_id+"/ssh_bad_priv_escl/"+priv_escalation_type;
      kb_id = SSH_LIB_KB_PREFIX + kb_id;

      this.sent_priv_escl_timeout_warning = FALSE;

      # Get command prompt

      var send_stty = FALSE;
      if(fresh_shell)
      {
        send_stty = TRUE;
        post_login_buffer = get_kb_blob(kb_id + "/post_login_buffer");
        this.cmd_prompt = get_kb_blob(kb_id + "/cmd_prompt");
        this.settings['cmd_prompt'] = this.cmd_prompt;
        channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
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
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using command prompt from previous login to find cmd prompt.");
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @sh_shell_handler_misc_at_prompt3_or_timeout,
            channel        : channel,
            timeout        : initial_recv_timeout
          );
        }
        else
        {
          channel.session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
            "Waiting for inactivity period to find command prompt.");
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @sh_shell_handler_misc_on_channel_buffer_inactivity,
            channel        : channel,
            timeout        : initial_recv_timeout);
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
        if("password has expired" >< channel.data_buf)
        {
          channel.session.set_error(obj_ch_id +
            "Account password has expired.");
          last_cmd_error = TRUE;
          return NULL;
        }
        if(channel.state == CHANNEL_STATE_CLOSED)
        {
          spad_log(message:fn+' [channel ' + channel.local_channel +
            ']: Channel is closed.');
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

        channel.session.dbg_log(level:DEBUG2, fn:fn, message:obj_ch_id +
          'Detected command prompt  "' + cmd_prompt + '".');

        if(strlen(cmd_prompt) == 0)
        {
          channel.session.set_cmd_error(obj_ch_id +
            "Unable to detect command prompt on shell.");
          last_cmd_error = TRUE;
          return NULL;
        }
      }

      # Construct command string

      if(!raw)
        command = this.add_command_tokens(command:command);

      this.escl_method_in_use = get_supported_escalation_method();
      if(!isnull(this.escl_method_in_use) && use_priv_escl)
      {
        if(force_priv_escl)
        {
          channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            "Running command using privilege escalation (force_priv_escl = TRUE)");
        }
        else
        {
          channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            "Running command using privilege escalation");
        }

        password_prompt_locations_in_buffer = NULL;
        if( get_kb_item(tmp_bad_escl_kb) ==
            hexstr(MD5(serialize(priv_escalation_extra))) )
        {
          channel.session.set_error(obj_ch_id + "Not using '" +
            escl_method_in_use + "' due to failure in a previous session.");
          this.escl_method_in_use = NULL;
          this.use_priv_escl = FALSE;
        }
        else
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Using the '" + escl_method_in_use + "' privilege escalation method.");
          this.escl_method = this.escl_method_in_use;
          command = this.add_priv_escl_to_command(command:command,
            saved_cmd:saved_cmd, escl_type:this.escl_method_in_use);
        }
      }
      else if(!isnull(this.escl_method_in_use))
      {
        channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
          "Running command *without* using privilege escalation");
      }
      # Set LANG=C while running command to ensure any prompts are
      # able to be parsed
      if(!raw)
        command = "LANG=C; " + command;

      # Disable echoing before running command
      # 20180918: Can no longer confirm that echoing is strictly necessary when on sh with sudo
      #if(this.escl_method_in_use == "sudo")
      #  send_stty = FALSE;
      if(send_stty && !raw) command = 'stty raw -echo\n' + command;
      command += '\n';

      # Run command and receive response, sending password as prompted
      channel.session.reset_cmd_interrupted();

      channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
        "Sending constructed command: " + command);
      _PAGINATION_SONICWALL = FALSE;
      #Use a 256 character line length limit for HP-UX and SunOS
      this.send_command_by_line_length(cmd:command, max_cmd_len:256, channel:channel);

      if(SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED &&
         use_priv_escl &&
         this.escl_method_in_use == "sudo" &&
         !raw)
        cb = @sh_shell_handler_misc_password_prompt_or_timeout;
      else if(!raw)
        cb = @sh_shell_handler_misc_start_marker_or_end_marker_or_password_prompt_or_timeout;
      else if(sonicwall)
        cb = @sh_shell_handler_misc_at_prompt2_or_timeout_sonicwall;
      else
        cb = @sh_shell_handler_misc_at_prompt2_or_timeout;

      this.last_buffer_update_ts = unixtime();
      this.timeout_check = inactivity_timeout;
      this.found_password_prompt = FALSE;
      channel.session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        check_callback : cb,
        channel        : channel,
        timeout        : recv_timeout,
        cmd_timeout    : cmd_timeout
      );

      if(channel.state == CHANNEL_STATE_CLOSED)
      {
        spad_log(message:'sh_shell_handler_misc [channel ' +
          channel.local_channel + ']: ' + fn + ': Channel is closed.');
        this.last_cmd_error = TRUE;
        return NULL;
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
        if(use_priv_escl) ran_with_priv_escl = 1;
        return cmd_logger.log_error(
          cmd                : command,
          error              : channel.session.cmd_error,
          ran_with_priv_escl : ran_with_priv_escl,
          forced_escl        : force_priv_escl,
          user               : channel.session.user,
          escl_user          : escl_user,
          escl_method        : escl_method
        );
      }

      if(this.found_password_prompt)
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Password prompt received for privilege escalation. " +
          "Sending password...");
        if( !this.sent_priv_escl_timeout_warning &&
            unixtime() - this.last_buffer_update_ts >= this.priv_escl_warning_timeout
        )
        {
          channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
            'Privilege escalation (using ' + this.escl_method_in_use +
            ') has taken over '+(unixtime() - this.last_buffer_update_ts) +
            's, ' + 'which may be indicative of a misconfigured host ' +
            'or domain name.');
          this.sent_priv_escl_timeout_warning = TRUE;
        }
        channel.session.set_redact(TRUE);
        if(this.escl_method_in_use == "sudo")
          channel.window_send_data(
            data : priv_escalation_extra["sudo_pass"] + '\n');
        else if(
          this.escl_method_in_use == "su" ||
          this.escl_method_in_use == "su_sudo"
        )
          channel.window_send_data(
            data : priv_escalation_extra["su_pass"] + '\n');
        else if(this.escl_method_in_use == "pbrun")
          channel.window_send_data(
            data : priv_escalation_extra["pbrun_pass"] + '\n');
        else channel.window_send_data(data:'\n'); # should never happen
        channel.session.set_redact(FALSE);
      }
      else {
        # We didn't get an escalation prompt that we recognized.  If the target
        # sent something unexpected, let's mark escalation failed and send
        # a CTRL-C to get back from the escalation prompt.
        if(("priv_escl_start_" + escl_marker_start_rand_str) >< channel.data_buf &&
           (SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED || ("command_start_" + start_rand_str) >!< channel.data_buf) &&
           ("priv_escl_end_" + escl_marker_end_rand_str) >!< channel.data_buf &&
           (this.timed_out || TAP_MODE) &&
           this.escl_method_in_use)
        {
          #Mark the escalation "bad" so we don't retry it.
          replace_kb_item(name:tmp_bad_escl_kb, value:hexstr(MD5(serialize(priv_escalation_extra))));
          priv_escl_failed = TRUE;

          channel.session.set_cmd_error(obj_ch_id +
            "ERROR - Attempted privilege escalation but got an " +
            "unexpected response. Sending CTRL+C and removing " +
            "privilege escalation from credential set.");

          channel.window_send_data(data:'\x03');
          this.last_buffer_update_ts = unixtime();
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @sh_shell_handler_misc_callback_end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout,
            channel        : channel,
            timeout        : recv_timeout
          );
        }
      }

      this.found_password_prompt = FALSE;
      priv_escl_bad_password = FALSE;
      priv_escl_failed = FALSE;

      if(!raw)
      {
        this.last_buffer_update_ts = unixtime();
        channel.session.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          check_callback : @sh_shell_handler_misc_callback_end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout,
          channel        : channel,
          timeout        : recv_timeout,
          cmd_timeout    : cmd_timeout
        );

        var max_loops = 0;
        if (this.escl_method_in_use == "su_sudo")
          max_loops = 1;
        if (SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED &&
            use_priv_escl &&
            this.escl_method_in_use == "sudo")
          max_loops = this.num_cmds;
        i = 0;
        # handle second password prompt (if found) for su+sudo
        # or multiple password prompts for individually escalated
        # sudo commands
        while(this.found_password_prompt && i < max_loops)
        {
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            "Sending sudo password...");
          channel.session.set_redact(TRUE);
          channel.window_send_data(
            data:priv_escalation_extra["sudo_pass"] + '\n');
          channel.session.set_redact(FALSE);
          this.found_password_prompt = FALSE;

          this.last_buffer_update_ts = unixtime();
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @sh_shell_handler_misc_callback_end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout,
            channel        : channel,
            timeout        : recv_timeout,
            cmd_timeout    : cmd_timeout
          );
          i++;
        }
      }

      # Check command result
      if(!this.command_result_found &&
          (tolower(channel.buf_tail.get()) =~ "incorrect password" ||
           tolower(channel.buf_tail.get()) =~ "sorry, try again.*password:\s*$"))
        priv_escl_bad_password = TRUE;

      if(priv_escl_bad_password)
      {
        priv_escl_failed = TRUE;
        channel.session.set_cmd_error(obj_ch_id +
          "ERROR - Bad privilege escalation password. Sending CTRL+C" +
          " and removing privilege escalation from credential set.");

        channel.window_send_data(data:'\x03');

        this.last_buffer_update_ts = unixtime();
        channel.session.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          check_callback : @sh_shell_handler_misc_callback_end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout,
          channel        : channel,
          timeout        : recv_timeout
        );

        # set tmp kb so we don't try escalating with this credential
        # set on the same host again
        replace_kb_item(
          name  : tmp_bad_escl_kb,
          value : hexstr(MD5(serialize(priv_escalation_extra)))
        );
      }
      else if (this.did_priv_escl_fail(cmd_res:channel.data_buf))
        priv_escl_failed = TRUE;

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
        if(use_priv_escl) ran_with_priv_escl = 1;
        return cmd_logger.log_error(
          cmd                : command,
          error              : channel.session.cmd_error,
          ran_with_priv_escl : ran_with_priv_escl,
          forced_escl        : force_priv_escl,
          user               : channel.session.user,
          escl_user          : escl_user,
          escl_method        : escl_method
        );
      }

      if (
        ("command_done_" + end_rand_str) >!< channel.data_buf &&
        ("priv_escl_end_" + escl_marker_end_rand_str) >!< channel.data_buf &&
        this.escl_method_in_use != "su_sudo" &&
        !raw
      )
      {
        channel.session.set_cmd_error(obj_ch_id +
          "ERROR - unable to reach command end marker.");

        if(use_priv_escl) ran_with_priv_escl = 1;

        if(!ran_with_priv_escl &&
           is_priv_escl_required(cmd_res:channel.data_buf))
        {
          if(!isnull(this.escl_method_in_use) && get_kb_item(tmp_bad_escl_kb) != hexstr(MD5(serialize(priv_escalation_extra))))
          {
            channel.session.set_cmd_error(obj_ch_id +
              "ERROR - Command results indicate need for privilege escalation. Sending ctrl + c and re-running command.");
            channel.window_send_data(data:'\x03');
            this.last_buffer_update_ts = unixtime();
            channel.session.sshrecv_until(
              end_states     : make_list("SOC_CLOSED"),
              check_callback : @sh_shell_handler_misc_callback_end_marker_in_buf_or_second_pass_prompt_or_escl_failed_or_timeout,
              channel        : channel,
              timeout        : recv_timeout
            );
            use_priv_escl = TRUE;
            return run_command(
              channel                : channel,
              command                : saved_cmd,
              cmd_timeout_min        : cmd_timeout_min,
              inactivity_timeout_min : inactivity_timeout_min
            );
          }
          else
          {
            last_cmd_error = TRUE;
            channel.session.set_cmd_error(obj_ch_id +
              "ERROR - Command results indicate need for privilege escalation, but escalation credentials have not been provided.");
            return cmd_logger.add(
              cmd               : saved_cmd,
              escl_cmd          : command,
              response          : channel.data_buf,
              error             : channel.session.cmd_error,
              failed_needs_escl : TRUE,
              user              : channel.session.user,
              escl_user         : escl_user,
              escl_method       : escl_method
            );
          }
        }
        else
        {
          last_cmd_error = TRUE;
          return cmd_logger.add(
            cmd                : saved_cmd,
            escl_cmd           : command,
            response           : channel.data_buf,
            error              : channel.session.cmd_error,
            ran_with_priv_escl : ran_with_priv_escl,
            forced_escl        : force_priv_escl,
            priv_escl_failed   : priv_escl_failed,
            user               : channel.session.user,
            escl_user          : escl_user,
            escl_method        : escl_method
          );
        }
      }

      var cmd_res = "";
      var to_remove;

      # parse out command results between start and end markers
      if (
        ("priv_escl_end_" + escl_marker_end_rand_str) >< channel.data_buf &&
        ("command_start_" + start_rand_str) >!< channel.data_buf &&
        "priv_escl_start_" + escl_marker_start_rand_str >< channel.data_buf
      )
      {
        # most likely priv escalation error in this case
        priv_escl_failed = TRUE;
        cmd_res = substr(
          channel.data_buf,
          stridx(channel.data_buf, "priv_escl_start_"+escl_marker_start_rand_str) + strlen("priv_escl_start_"+escl_marker_start_rand_str),
          stridx(channel.data_buf, "priv_escl_end_" + escl_marker_end_rand_str) - 1
        );
        to_remove = stridx(channel.data_buf, "priv_escl_end_" + escl_marker_end_rand_str) + 
                      strlen('priv_escl_end_') + 
                      strlen(escl_marker_end_rand_str);

        if(this.escl_method_in_use == "pbrun")
          item = pregmatch(
            pattern : "Authenticate " + cur_user + ":[^\n]*\n([\s\S]*)$",
            string  : cmd_res
          );
        else
          item = pregmatch(
            pattern : "[Pp]assword\s*:[^\n]*\n([\s\S]*)$",
            string  : cmd_res
          );
        if(!isnull(item) && !isnull(item[1]))
          cmd_res = item[1];

        if(this.escl_method_in_use == "su_sudo")
        {
          item = pregmatch(
            pattern : "[Pp]assword\s*:[^\n]*\n([\s\S]*)$",
            string  : cmd_res
          );
          if(!isnull(item) && !isnull(item[1]))
            cmd_res = item[1];
        }

        # set tmp kb so we don't try escalating with this credential
        # set on the same host again
        if ("not allowed to execute" >< channel.data_buf)
        {
          channel.session.set_cmd_error(obj_ch_id +
            "A privilege escalation error occurred which appears to be " +
            "command-specific.");
        }
        else if ("syntax error" >< tolower(channel.data_buf))
        {
          priv_escl_failed = FALSE;
          channel.session.set_cmd_error(obj_ch_id +
            "A syntax error occurred.");
        }
        else
        {
          channel.session.set_cmd_error(obj_ch_id +
            "Privilege escalation appears to have failed. " +
            "Removing privilege escalation from credential set.");
          replace_kb_item(
            name  : tmp_bad_escl_kb,
            value : hexstr(MD5(serialize(priv_escalation_extra)))
          );
        }
      }
      else if(
        "command_start_" + start_rand_str >< channel.data_buf &&
        "command_done_" + end_rand_str >< channel.data_buf
      )
      {
        cmd_res = substr(
          channel.data_buf,
          stridx(channel.data_buf, "command_start_" + start_rand_str)+strlen("command_start_"+start_rand_str),
          stridx(channel.data_buf, "command_done_" + end_rand_str)-1
        );
        to_remove = stridx(channel.data_buf, "command_done_" + end_rand_str) + 13 + 8;
      }
      else
      {
        cmd_res = '';

        var multiline_set;
        # pregmatch will throw a "pcre_exec() failed"  exception if the input string
        # returns too many matches.
        # SonicWall command returned a length of 1235985 which was enough to trigger this.
        # If result exceeds a threshold anywhere close to this value - we set multiline to TRUE to avoid this error
        # Keep multiline set to default (FALSE) otherwise to avoid breaking existing plugins that use this function
        if(strlen(channel.data_buf) >= 500000)
          multiline_set = TRUE;
        else
          multiline_set = FALSE;

        item = pregmatch(
          pattern : "[Pp]assword\s*:[^\n]*\n(((?![Pp]assword\s*:)[\s\S])*)\n.*$",
          string  : channel.data_buf,
          multiline : multiline_set
        );

        if(!isnull(item) && !isnull(item[1]) && !raw)
          cmd_res = item[1];
        else if(raw)
          cmd_res = channel.data_buf;
        to_remove = 0;
      }

      # remove the first password prompt
      item = pregmatch(
        pattern : "^(.*[Pp]assword\s*:)[^\n]*\n([\s\S]*)$",
        string  : cmd_res
      );
      if(!isnull(item) && !isnull(item[2]) && " -p Password: " >!< item[1])
        cmd_res = item[2];

      # remove other prompts if multiple commands are escalted
      if(this.escl_method_in_use == "sudo" &&
           use_priv_escl && SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED)
      {
        lines = split(cmd_res, sep:'\n', keep:TRUE);
        var tmp_out = '';

        for(i = 0; i < max_index(lines); i++)
        {
          if(!preg(pattern:"^\s*[Pp]assword\s*:\s*[\r\n]?$", string:lines[i]))
          {
            tmp_out += lines[i];
          }
        }
        cmd_res = tmp_out;

      }

      # If SonicWall command result is too large truncate so it does not take up
      # unreasonable amount of space in logs.
      # Some SonicWall commands can return over 20k lines of output that make logging difficult
      if(sonicwall && strlen(cmd_res) > 3300)
      {
        var count_sonicwall, line_sw, cmd_res_new;
        count_sonicwall = 0;
        foreach line_sw(split(cmd_res, keep:FALSE))
        {
          line_sw = chomp(line_sw);
          count_sonicwall++;
          if(count_sonicwall > 100) break;
          cmd_res_new += line_sw + '\n';
        }
        cmd_res_new += " [...] <command result truncated>";
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Extracted cmd result: " + cmd_res_new);
      }
      else
      {
        channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
          "Extracted cmd result: " + cmd_res);
      }

      channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
        "Removing " + to_remove + " bytes from buffer.");

      channel.clear_data_buf(len:to_remove);

      var check_len = 3;
      if(strlen(cmd_prompt) < 3) check_len = strlen(cmd_prompt);
      # Unless we've previously identified that we can't reach the
      # command prompt after executing a command,
      # recv up to two more times until we get to cmd prompt if we
      # aren't already
      var prompt_timeout_kb = SSH_LIB_KB_PREFIX + "cmd_prompt_timeouts";
      if (get_kb_item(prompt_timeout_kb) >= 3)
      {
        channel.session.set_cmd_error(obj_ch_id +
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
          # if a sonicwall command is determined to use pagination
          # send an empty line break to help shell handler find prompt
          if(_PAGINATION_SONICWALL)
          {
            channel.session.dbg_log(fn:fn, level:DEBUG3,
              message:"SonicWall pagination detected. Cannot find prompt. Sending empty line break.");
            channel.window_send_data(data:'\n');
          }
          # to ensure long sonicwall commands return to command prompt
          # send line break to help shell handler find prompt
          else if(sonicwall)
          {
            sleep(15); # sleep to give sonicwall more time to get back to prompt
                       # there can be a lag sometimes (because sonicwall devies can be slow to react over SSH)
                       # which the shell handler interprets as a failure.
            channel.session.dbg_log(fn:fn, level:DEBUG3,
              message:"SonicWall device detected. Cannot find prompt. Sending empty line break.");
            channel.window_send_data(data:'\n');
          }
          channel.session.sshrecv_until(
            end_states     : make_list("SOC_CLOSED"),
            check_callback : @sh_shell_handler_misc_on_channel_buffer_update_or_timeout,
            channel : channel,
            timeout : recv_timeout
          );
          i++;
        }

        if(at_cmd_prompt(buf:channel.data_buf, check_len:check_len))
          channel.session.dbg_log(fn:fn, level:DEBUG2, message:obj_ch_id +
            'Back at command prompt.');

        if(!at_cmd_prompt(buf:channel.data_buf, check_len:check_len))
        {
          last_cmd_error = TRUE;
          var prompt_timeout_count = get_kb_item(prompt_timeout_kb);
          if (!isnull(prompt_timeout_count))
            replace_kb_item(name:prompt_timeout_kb, value:prompt_timeout_count+1);
          else set_kb_item(name:prompt_timeout_kb, value:1);
          channel.session.set_cmd_error(obj_ch_id +
            "ERROR - unable to get back to command prompt.");
        }
      }

      channel.clear_data_buf();

      if(use_priv_escl)
      {
        if (priv_escl_failed)
          channel.session.dbg_log(fn:fn, level:DEBUG3, message:obj_ch_id +
            'Command results indicate privilege escalation failed.\n' +
            '  Command  : ' + saved_cmd + '\n' +
            '  Response : ' + cmd_res + '\n');
        cmd_logger.add(
          cmd                : saved_cmd,
          escl_cmd           : command,
          response           : cmd_res,
          error              : channel.session.cmd_error,
          ran_with_priv_escl : 1,
          forced_escl        : force_priv_escl,
          priv_escl_failed   : priv_escl_failed,
          user               : channel.session.user,
          escl_user          : escl_user,
          escl_method        : escl_method
        );
        use_priv_escl = FALSE;
        if(!empty_or_null(cmd_res)) return cmd_res;
        else return NULL;
      }
      else
      {
        if(is_priv_escl_required(cmd_res:cmd_res))
        {
          if(!isnull(this.escl_method_in_use) && get_kb_item(tmp_bad_escl_kb) != hexstr(MD5(serialize(priv_escalation_extra))))
          {
            channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
              "Command results indicate need for privilege escalation, re-running command");
            use_priv_escl = TRUE;
            return run_command(
              channel                : channel,
              command                : saved_cmd,
              cmd_timeout_min        : cmd_timeout_min,
              inactivity_timeout_min : inactivity_timeout_min
            );
          }
          else
          {
            channel.session.dbg_log(fn:fn, level:DEBUG1, message:obj_ch_id +
              "Command results indicate need for privilege escalation, but escalation credentials are not available. Unable to re-run command with escalation.");
            use_priv_escl = FALSE;
            cmd_logger.add(
              cmd               : saved_cmd,
              escl_cmd          : command,
              response          : cmd_res,
              error             : channel.session.cmd_error,
              failed_needs_escl : TRUE,
              user              : channel.session.user,
              escl_user         : escl_user,
              escl_method       : escl_method
            );
            if(!empty_or_null(cmd_res)) return cmd_res;
            else return NULL;
          }
        }
        else
        {
          use_priv_escl = FALSE;
          cmd_logger.add(
            cmd         : saved_cmd,
            escl_cmd    : command,
            response    : cmd_res,
            error       : channel.session.cmd_error,
            user        : channel.session.user,
            escl_user   : escl_user,
            escl_method : escl_method
          );
          if(!empty_or_null(cmd_res)) 
          {
            if(raw)
            {
              cmd_res = str_replace(find:command, replace:'', string:cmd_res);
              cmd_res = str_replace(find:cmd_prompt, replace:'', string:cmd_res);
              cmd_res = strip(cmd_res);
            }
            return cmd_res;
          }
          else return NULL;
        }
      }
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
      var fn = 'sh_shell_handler_misc.test_private_function';
      if (isnull(name))
      {
        spad_log(message:fn + ': Missing name parameter');
        return;
      }
      switch (name)
      {
        case "is_priv_escl_required":
          return is_priv_escl_required(cmd_res:args["cmd_res"]);
        case "send_command_by_line_length":
          var old_mode = TAP_MODE;
          TAP_MODE = FALSE;
          var result = send_command_by_line_length(cmd:args["cmd"],
                                                   max_cmd_len:args["max_cmd_len"],
                                                   channel:args["channel"]);
          TAP_MODE = old_mode;
          return result;
        default:
          spad_log(message:fn + ': "'+name+'()" is not yet implemented for testing with this function');
          return NULL;
      }
    }
  }
}
