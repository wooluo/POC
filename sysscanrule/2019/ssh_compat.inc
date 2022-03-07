#TRUSTED 59ac203c5352c34c4ad303071cc1e0525a0320f8f2af65c7f756e6669ae806791b682df517cda3ce5ca981e4d62a6697e37fc272d9ea9d6b7bbb1a245005b066c59cd2fbb6b9afde7b5f195746da45741c3a7e1db2c517df09fd1bac0360480f593a9cdc4618a1b188ebde8aa606d7beaa103ba14de111c2a39faf82bd55d230470b1a460cde6f19f4ae1666610faf45989c790054665e880399346c0cce7ced2ba93c9d3d7af84cedbb0f4929b8e02b1d12e0787809d60a20a8ce8530b5b90c9d90e73a5c66221243102dd19aa028e815cf25ec2415b0a7557b10902e0017b08c063b9f28cba37d81142ffa51f8b69868e2cfab08fe3efe64836546e4aaf9b2e304b4a489b7d62f4f162450b162497b96c49c28149021680ad26eda62cdc34304a6aa5d2fa39ce4b167bf1e75335726372b5064e0f93f053059b749bfcdfe946af232b472b515375e99a0b277cb116cb83a303a21dd63d56cdd4d88873a9314dc63b5ee334ec133fb4cdbf671758c9dab0bba7cc3feaa9354cf68aaa084764ceababdf4706968eaededfdef9df0f709a3c96abe13d0b1364991256850d459b93c5721489df6d69c5164ce85eb088a9503e353691c10414788a7db03aea82003e3d1880526a0597230625ae03ff7b2baeefaf13c7b38be2b9497c674d95c527152a4c3b333e2627810388da899578cae98ebe8e2260511fa43231d17e757f289
global_var _DEBUG = TRUE;
include("byte_func.inc");
include("ssh_lib.inc");

namespace sshlib
{
global_var _compat_session;

  function ssh_open_connection_wrapper(exit_on_disconnect)
  {
    local_var host, ret, sock, fn;
    fn = 'ssh_open_connection_wrapper';
    _compat_session = new('sshlib::session');
    _compat_session.dbg_log(level:DEBUG3, fn:fn, message:'Entering wrapper.');

    ret = try_ssh_kb_settings_login(session:_compat_session, accept_none_auth:FALSE); # ?
    ## DEBUGGING
    if (!ret)
    {
      if (_compat_session.legacy_data[USE_LEGACY])
        disable_ssh_wrappers(); # defined in ssh_func.inc
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
          message:'Failed to establish SSH connection.'+
          ' Returning 0.');
      _compat_session.close_connection();
      return 0;
    }
    _ssh_socket = _compat_session.socket;
    _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:'Successfully established SSH connection.'+
        ' Returning 1.');
    return 1;
  }

  function ssh_wrapper_escl_type()
  {
    local_var su, su_method;

    if(get_kb_item(SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_success"))
    {
      return get_kb_item(SSH_LIB_KB_PREFIX +
        _compat_session.get_kb_connection_id() + "/escalation_type");
    }

    su = get_kb_item("Secret/SSH/sudo");
    if(su && su != SU_NONE)
    {
      su_method = get_kb_item("Secret/SSH/sudo_method");
      if(su_method == "Cisco 'enable'")
        su_method = 'cisco_enable';
    }

    return su_method;
  }

  function ssh_wrapper_load_legacy_escl(escl_type)
  {
    local_var sulogin, supass, supath, root, fn, escl_extra;

    fn = 'ssh_wrapper_load_legacy_escl';

    escl_extra = make_array();

    sulogin = get_kb_item("Secret/SSH/su-login");
    supass = get_kb_item("Secret/SSH/sudo-password");
    supath = get_kb_item("Secret/SSH/sudo_path");
    root = get_kb_item("Secret/SSH/root");

    if (isnull(supath)) supath = "";
    if (isnull(root)) root = "root";

    switch (escl_type)
    {
      case "su+sudo":
        escl_extra["sudo_user"] = root;
        escl_extra["sudo_dir"]  = supath;
      case "su":
        escl_extra["su_user"] = sulogin;
        escl_extra["su_pass"] = supass;
        escl_extra["su_dir"]  = supath;
        break;
      case "sudo":
        escl_extra["sudo_user"] = root;
        escl_extra["sudo_pass"] = supass;
        escl_extra["sudo_dir"]  = supath;
        break;
      case "pbrun":
        escl_extra["pbrun_user"] = root;
        escl_extra["pbrun_pass"] = supass;
        escl_extra["pbrun_dir"]  = supath;
        break;
      case "dzdo":
        escl_extra["dzdo_user"] = root;
        escl_extra["dzdo_pass"] = supass;
        escl_extra["dzdo_dir"]  = supath;
        break;
      case "cisco_enable":
        escl_extra["enable_pass"] = get_kb_item("Secret/SSH/enable-password");
        break;
      default:
        _compat_session.dbg_log(fn:fn, message:'Unknown escalation type '+escl_type+'.');
        return NULL;
    }

    return escl_extra;

  }

  function ssh_wrapper_load_escl()
  {
    local_var escl_extra, fn, escl_type;
    fn = 'ssh_wrapper_load_escl';


    # Get sshlib stored escl creds if present
    escl_extra = get_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX +
                  _compat_session.get_kb_connection_id() + "/escalation_extra");

    # If stored creds exist, we are done here
    if(!empty_or_null(escl_extra))
    {
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:'Retrieved previously saved escalation information.');
      return escl_extra;
    }

    # We don't have creds, if sshlib was previously used, we already know that
    # there were no escl creds provided, so don't check for them.
    if(get_kb_item(SSH_LIB_KB_PREFIX + "try_ssh_kb_settings_login_success"))
    {
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:'No escalation information was provided for the credential set used to successfully log in to the target.');
      return NULL;
    }

    # Fall back to legacy KB items
    escl_type = ssh_wrapper_escl_type();
    _compat_session.dbg_log(level:DEBUG3, fn:fn,
      message:'Retrieving escalation information from legacy KB items.');
    return ssh_wrapper_load_legacy_escl(escl_type:escl_type);
  }

  function ssh_wrapper_state_check()
  {
    if (isnull(_compat_session) || !_compat_session.socket )
      exit(1, 'Attempted to send SSH command without establishing an active session.');
    if (_compat_session.cur_state.val == "SOC_CLOSED")
    {
      var msg = "Socket is closed.";
      if(_compat_session.error)
        msg += " Error details : " + _compat_session.error;
      exit(1, msg);
    }

    return TRUE;
  }

  function ssh_wrapper_use_legacy(nosh, term, no53, shell_handler)
  {
    var sh_type, sh_term, fn, sh_opts, use_legacy;

    fn = 'ssh_wrapper_use_legacy';

    # Check variables that may be passed to ssh_cmd() to see if they
    # match the settings of the selected shell handler
    sh_type = get_kb_item(SSH_LIB_KB_PREFIX + 'shell_handler');
    use_legacy = FALSE;
    if(nosh && sh_type == "sshlib::sh_shell_handler")
    {
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:"ssh_cmd() call specified 'nosh' but shell handler '"+sh_type+"' retrieved from KB uses 'sh'.");
      return TRUE;
    }

    sh_term = shell_handler.get_pty_term();
    if(term && term != sh_term)
    {
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:"ssh_cmd() call specified 'term' as '"+term+"' but the shell handler '"+sh_type+"' retrieved from the KB sends 'term' as '"+sh_term+"'.");
      return TRUE;
    }

    sh_opts = shell_handler.get_pty_opts();
    if(no53 && sh_opts[53] != NULL)
    {
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:"ssh_cmd() call specified 'no53' but the shell handler '"+sh_type+"' retrieved from the KB sends option 53 (enable echo).");
      return TRUE;
    }

    return FALSE;
  }

  function ssh_wrapper_use_escl(nosudo, cisco, escl_extra)
  {
    # If no escalation is provided, no need to use escl. If nosudo is set then
    # escalation should not be used unless cisco is set, in which case nosudo
    # should be ignored.
    return escl_extra && (isnull(nosudo) || nosudo == FALSE || cisco);
  }

  function ssh_wrapper_open_shell_handler(shell_handler)
  {
    local_var chan, handler_string, fn;

    fn = 'ssh_wrapper_open_shell_handler';

    if(!shell_handler)
      shell_handler = get_kb_shell_handler();

    if(!shell_handler)
    {
      handler_string = get_kb_item(SSH_LIB_KB_PREFIX + 'shell_handler');
      _compat_session.dbg_log(fn:fn, level:DEBUG1,
        message:"Failed to get shell handler '"+handler_string+"'.");
      return NULL;
    }

    chan = _compat_session.open_shell(shell_handler:shell_handler);
    if(!chan)
    {
      _compat_session.dbg_log(level:DEBUG1, fn:fn,
        message:"Failed to open shell.");
      return NULL;
    }


    return chan;
  }

  function ssh_wrapper_use_shell_handler(use_escl, noexec, cisco, nosetup)
  {
    # use_escl has already been updated to take nosudo and
    # missing escalation credentials into account
    return use_escl || noexec || cisco || nosetup;
  }


  function ssh_cmd_wrapper(cmd, timeout, nosudo, nosh, noexec, cisco,
                           nosetup, noclose, term, no53, force_priv_escl,
                           cmd_timeout_min, inactivity_timeout_min)
  {
    local_var fn, shell_handler, use_shell_handler, chan, ret;
    local_var escl_extra, use_escl;

    fn = 'session.ssh_cmd_wrapper';

    # Ensure that there is a valid session before continuing
    ssh_wrapper_state_check();

    # Escalation is usually used, and it is helpful to attempt to load it first
    # so that it is known from the beginning if escalation should be taken into
    # consideration in the case that no escalation credentials are provided.
    escl_extra = ssh_wrapper_load_escl();

    use_escl = ssh_wrapper_use_escl(nosudo:nosudo, cisco:cisco, escl_extra:escl_extra);

    use_shell_handler = ssh_wrapper_use_shell_handler(use_escl:use_escl, noexec:noexec, cisco:cisco, nosetup:nosetup);

    if (use_shell_handler)
    {
      shell_handler = get_kb_shell_handler();

      if(shell_handler && ssh_wrapper_use_legacy(nosh:nosh, term:term, no53:no53, shell_handler:shell_handler))
      {
        delete(shell_handler);
        _compat_session.use_legacy();
        return NULL;
      }

      if (!nosetup)
      {
        _compat_session.dbg_log(level:DEBUG3, fn:fn,
            message:'Setting up shell_handler.');

        chan = ssh_wrapper_open_shell_handler(shell_handler: shell_handler);

        if(!chan)
          return NULL;

        if(escl_extra)
          chan.shell_handler.set_priv_escalation(type:ssh_wrapper_escl_type(), extra:escl_extra);

      } # end of !nosetup branch
      # 'nosetup' should not be 'TRUE' because it is checked in ssh_cmd()
      # before calling this wrapper. This is a double-check/placeholder.
      else
        exit(1, fn+': "nosetup" option not yet implemented.');
    }
    else if(!escl_extra)
    {
      _compat_session.dbg_log(level:DEBUG1, fn:fn,
        message:"Failed to retrieve valid escalation information. Defaulting to using 'exec' rather than a shell handler.");
    }

    # To support legacy timeouts, if only timeout is supplied then
    # apply it to both command timeout and inactivity timeout
    if (timeout)
    {
      if (!cmd_timeout_min) cmd_timeout_min = timeout;
      if (!inactivity_timeout_min) inactivity_timeout_min = timeout;
    }
    ret = _compat_session.run_command(
            use_shell_handler      : use_shell_handler,
            channel                : chan,
            command                : cmd,
            force_priv_escl        : force_priv_escl,
            cmd_timeout_min        : cmd_timeout_min,
            inactivity_timeout_min : inactivity_timeout_min);

    _compat_session.dbg_log(level:DEBUG3, fn:fn,
        message:'Ran command: "'+cmd+'"\nReturned: '+ret);

    if (!noclose && !isnull(chan))
    {
      _compat_session.dbg_log(level:DEBUG3, fn:fn,
          message:'Closing channel.');
      chan.close();
    }
    return ret;
  }

  function ssh_exchange_identification_wrapper(existing_socket)
  {
    if(isnull(_compat_session))
      _compat_session = new("sshlib::session");

    if(_compat_session.open_connection(existing_socket:existing_socket))
    {
      _ssh_protocol = 2;
      return _compat_session.remote_version;
    }
    else
      return FALSE;
  }

  function ssh_login_public_key_only_wrapper(pub, login, existing_socket)
  {
    # Multiple tests may be run with this function in the same plugin,
    # so we don't want to use the _compat_session in this case, we want a
    # fresh session every time
    local_var session = new("sshlib::session");
    if(!session.open_connection(existing_socket:existing_socket))
      return FALSE;

    local_var ret = ssh_public_key_accepted(login:login, pub:pub, session:session);
    session.close_connection();
    delete(session);
    if(ret) return TRUE;
    else return FALSE;
  }

  function get_ssh_error_wrapper()
  {
    return last_error;
  }

  function get_ssh_read_timeout_wrapper()
  {
    return 30;
  }

  function set_ssh_read_timeout_wrapper()
  {
    var tmp = _FCT_ANON_ARGS[0];
    return TRUE;
  }

  function get_ssh_supported_authentication_wrapper()
  {
    # The new lib initializes supported_auth_methods to an empty list and
    # stores the values as a list
    # The old lib initializes _ssh_supported_authentication to "" and stores
    # values as a comma-separated string
    if( !isnull(_compat_session) &&
        max_index(_compat_session.supported_auth_methods) > 0
    )
      return join(_compat_session.supported_auth_methods, sep:",");
    else
      return "";
  }

  function get_ssh_server_version_wrapper()
  {
    # The new lib initializes remote_version to FALSE
    # The old lib initializes _ssh_server_version to ""
    if(!isnull(_compat_session) && _compat_session.remote_version)
      return _compat_session.remote_version;
    else
      return "";
  }

  function get_ssh_banner_wrapper()
  {
    # The new lib declares userauth_banner without initializing
    # The old lib initializes _ssh_banner to ""
    if(!isnull(_compat_session) && !isnull(_compat_session.userauth_banner))
      return _compat_session.userauth_banner;
    else
      return "";
  }

  function get_server_public_key_wrapper()
  {
    # The new lib initializes remote_host_key as NULL
    # The old lib declares server_host_key_blob without initializing
    if(!isnull(_compat_session))
      return _compat_session.remote_host_key;
    else
      return NULL;
  }

  function init_wrapper()
  {
    # Legacy function init() sets (or resets) sequence numbers, channel
    # number, and other global variables
    if(!isnull(_compat_session))
      delete(_compat_session);

    _compat_session = new("sshlib::session");
  }

  function send_ssh_packet_wrapper(code, payload)
  {
    if(isnull(_compat_session))
      return NULL;

    if(typeof(code) != "int") code = ord(code);
    _compat_session.sshsend(code:code, data:payload);
  }

  function ssh_window_send_data_wrapper(data, redact)
  {
    if(isnull(_compat_session))
      return NULL;

    var channel = _compat_session.channel_manager.channels[local_channel];
    channel.window_send_data(data:data, redact:redact);
  }

  function recv_ssh_packet_wrapper(timeout)
  {
    # Old lib initializes payload to raw_int8(i:0) which is returned for any
    # errors prior to the payload being extracted
    if(isnull(_compat_session))
      return mkbyte(0);

    if(isnull(_compat_session.sshrecv(timeout:timeout)))
      return mkbyte(0);

    # Old lib returns the full packet
    return mkbyte(_compat_session.last_packet.type) + _compat_session.last_packet.payload;
  }

  function init_crypto_data_wrapper()
  {
    if(isnull(_compat_session))
      _compat_session = new("sshlib::session");

    if(isnull(_compat_session.new_cipherset))
      _compat_session.set_new_cipherset(new("sshlib::cipherset"));
  
    if (isnull(_crypto_algo))
    {
      _compat_session.dbg_log(fn:'init_crypto_data_wrapper',
          level:DEBUG1,
          message:'_crypto_algo must be set before calling init_crypto_data_wrapper()'
          );
      return -1;
    }

    _compat_session.new_cipherset.set_crypto_alg(_crypto_algo, mode:MODE_IN);
    _compat_session.new_cipherset.set_crypto_alg(_crypto_algo, mode:MODE_OUT);
  }

  function dh_gen_key_wrapper(p, g)
  {
    # Old lib returns uninitialized variable if(!p)
    if(!p) return NULL;

    # Old lib returns -1 for failure, 0 for success
    if(isnull(_compat_session)) return -1;

    _compat_session.kex_handler.set_dh_groups(p:p, g:g);

    # New lib returns FALSE for failure, TRUE for success
    if (_compat_session.kex_handler.dh_gen_key())
    {
      dh_pub = _compat_session.kex_handler.dh_local_pub;
      return 0;
    }
    else
      return -1;
  }

  function ssh_kex2_wrapper(server_version, nofingerprint)
  {
    local_var fn = "ssh_kex2_wrapper";
    # Old lib returns -1 for failure, 0 for success
    if(isnull(_compat_session)) return -1;

    # If key exchange is already done, return
    if(_compat_session.cur_state.oneof(state_list:make_list("KEX_DONE")))
      return 0;

    # We expect one of these states if key exchange is not yet done
    if(!_compat_session.cur_state.oneof(state_list:make_list("SOC_OPENED", "KEX_BEGIN")))
    {
      _compat_session.dbg_log(message:"Current state is not SOC_OPENED or KEX_BEGIN, unable to complete key exchange.", fn:fn);
      return -1;
    }

    # Disable checking against known_hosts
    if(nofingerprint) _compat_session.ignore_known_hosts();

    # Pass through the server_version
    _compat_session.set_remote_version(server_version);

    # Key exchange is handled automatically by callbacks
    _compat_session.sshrecv_until(end_states:make_list("KEX_DONE", "SOC_CLOSED"));

    if(_compat_session.cur_state.val != "KEX_DONE")
    {
      _compat_session.dbg_log(message:"Current state is not KEX_DONE, key exchange failed.", fn:fn);
      return -1;
    }
    # Set the global _crypto_algo variable
    if (!isnull(_compat_session.kex_handler.cipherset.crypto_alg))
      _crypto_algo = _compat_session.kex_handler
                                    .cipherset
                                    .crypto_alg;
    return 0;
  }

  function get_public_key_from_cert_wrapper()
  {
    local_var tmp_session = new("sshlib::session");
    local_var tmp_kex_handler = new("sshlib::kex_handler", tmp_session);
    local_var ret = tmp_kex_handler.get_pub_key_from_cert(_FCT_ANON_ARGS[0]);
    tmp_session.cur_state.set("SOC_OPENED");
    tmp_session.close_connection();
    delete(tmp_kex_handler);
    delete(tmp_session);
    return ret;
  }

  function parse_ssh_cert_wrapper()
  {
    local_var tmp_session = new("sshlib::session");
    local_var tmp_kex_handler = new("sshlib::kex_handler", tmp_session);
    local_var ret = tmp_kex_handler.parse_ssh_cert(cert:_FCT_ANON_ARGS[0]);
    tmp_session.cur_state.set("SOC_OPENED");
    tmp_session.close_connection();
    delete(tmp_kex_handler);
    delete(tmp_session);
    return ret;
  }

  function ssh_auth_supported_wrapper(method, user)
  {
    local_var supported_method;

    if(isnull(_compat_session)) return NULL;

    if(!_compat_session.get_supported_auth_methods(username:user))
      return NULL;

    if(_compat_session.supported_auth_methods[0] == "none")
      return SSH_MSG_USERAUTH_SUCCESS;

    if(_compat_session.supported_auth_methods[0] == "unknown")
      return NULL;

    if(isnull(method))
      return TRUE;

    foreach supported_method (_compat_session.supported_auth_methods)
    {
      if (supported_method == method)
        return TRUE;
    }

    _compat_session.set_error("Error : Remote server does not support the '" + method + "' authentication method. It supports : " + get_ssh_supported_authentication_wrapper() + ".");
    return FALSE;
  }

  function ssh_open_channel_wrapper()
  {
    if(isnull(_compat_session)) return -1;

    local_var channel = _compat_session.get_channel();

    if(!channel) return -1;

    # Set ssh_func.inc globals
    local_channel  = channel.local_channel;
    remote_channel = channel.remote_channel;
    r_window_size = channel.remote_window;
    r_packet_size = channel.remote_maxpacket;
    l_window_size = channel.local_window;
    max_packet_size = channel.local_maxpacket;

    _compat_session.dbg_log(level:DEBUG1, message:"Opened channel. Local = "+local_channel+
        " remote = "+remote_channel);

    return 0;
  }

  function ssh_close_channel_wrapper()
  {
    if(isnull(_compat_session)) return -1;

    local_var channel;
    channel = _compat_session.channel_manager.channels[local_channel];

    channel.close();
    _compat_session.channel_manager.remove_channel(channel:channel);
    return 0;
  }

  function ssh_request_channel_wrapper(type, want_reply, extra)
  {
    if(isnull(_compat_session)) return 0;

    local_var channel;
    channel = _compat_session.channel_manager.channels[local_channel];

    channel.make_request(type:type, want_reply:want_reply, extra:extra);
    return 1;
  }

  function ssh_login_wrapper(login, password, pub, priv, passphrase, realm, host, nofingerprint, cert, existing_socket)
  {
    local_var fn = "ssh_login_wrapper";

    init_wrapper();
    if(nofingerprint) _compat_session.ignore_known_hosts();

    if (!_compat_session.open_connection(existing_socket:existing_socket))
    {
      _compat_session.dbg_log(message:"Failed to open connection", fn:fn);
      return -1;
    }

    _compat_session.get_supported_auth_methods(username:login);
    if(_compat_session.supported_auth_methods[0] == "none" &&
       strlen(password) == 0 && isnull(priv) && isnull(pub) && isnull(cert)
    )
      return 0;

    local_var extra = make_array();

    extra["username"] = login;
    if (password && realm)
    {
      extra["password"] = password;
      extra["realm"]    = realm;
      extra["host"]     = host;
      if(_compat_session.login(method:"gssapi", extra:extra)) return 0;
      else
      {
        _compat_session.dbg_log(message:"Failed to log in with 'gssapi' authentication", fn:fn);
        return -1;
      }
    }
    else if (password)
    {
      extra["password"] = password;
      if (_compat_session.login(method:"keyboard-interactive", extra:extra))
        return 0;
      else
      {
        _compat_session.dbg_log(message:"Failed to log in with 'keyboard-interactive' authentication", fn:fn, level:DEBUG3);
        if (_compat_session.login(method:"password", extra:extra))
          return 0;
        else
        {
          _compat_session.dbg_log(message:"Failed to log in with 'password' authentication", fn:fn);
          return -1;
        }
      }
    }
    else if (priv)
    {
      extra["privatekey"] = priv;
      if(!isnull(cert)) extra["cert"] = cert;
      if(!isnull(passphrase)) extra["passphrase"] = passphrase;
      if(_compat_session.login(method:"publickey", extra:extra)) return 0;
      else
      {
        _compat_session.dbg_log(message:"Failed to log in with 'publickey' authentication", fn:fn);
        return -1;
      }
    }
    else
    {
      _compat_session.dbg_log(message:"Unable to determine authentication method", fn:fn);
      return -1;
    }
  }

  function update_window_size_wrapper(size)
  {
    if(isnull(_compat_session)) return -1;
    if(isnull(local_channel)) return -1;

    local_var channel;
    channel = _compat_session.channel_manager.channels[local_channel];

    if(isnull(channel)) return -1;

    channel.window_adjust_packet(minimumsize:size);
    return 0;
  }

  function ssh_cmd_error_wrapper()
  {
    if(isnull(_compat_session)) return NULL;
    return _compat_session.cmd_error;
  }

  function ssh_cmd_interrupted_wrapper()
  {
    if(isnull(_compat_session)) return NULL;
    return _compat_session.last_cmd_interrupted();
  }

  function ssh_req_svc_wrapper()
  {
    if(isnull(_compat_session)) return FALSE;

    _compat_session.sshsend(code:PROTO_SSH_MSG_SERVICE_REQUEST, data:mk_ssh_string(_FCT_ANON_ARGS[0]));
    _compat_session.sshrecv_until(end_states:make_list("SERVICE_REQUEST_SUCCESS", "SOC_CLOSED"));
    if(_compat_session.cur_state.val != "SERVICE_REQUEST_SUCCESS")
    {
      _compat_session.set_error("Did not receive SERVICE_REQUEST_SUCCESS for ssh-userauth authentication.");
      return FALSE;
    }

    return TRUE;
  }

  function ssh_close_connection_wrapper()
  {
    if(isnull(sshlib::_compat_session)) return NULL;
    _compat_session.close_connection();
    delete(_compat_session);
    return NULL;
  }
}
