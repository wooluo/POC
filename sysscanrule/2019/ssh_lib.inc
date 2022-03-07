#TRUSTED 4c5558797d7202b156f3c06afbdd8890ed54669d4bdb888d2fb100b0338ca715c4ceee2cbfddda1b83a84be7a9a367239e5f3f3e19fd5986534367d540e8d9b16fc79aab07936c440f89f43de7b29b2f11ea58d8018736a1487ddc5cf06ba3becb909f231a39b494744eb282566f9f5b629489d8129b3eba6efa8da7d9465ec48b573a7704891e52f5847b5395135100dc234e4cbd15154ed14bd1fafb41823f7fe826f9bf92731ae66f4cc35da8f35226aaa1f8ad7d05c8f58d3f7afd8b882907674d58b80a8f445df211bd99bf47725ebc6e10e6a82b9eb87f90884a90d69a573f2cdbf710a7f5cd69e9709aad671d069b38871b413d93d455058b5333703ef761de5bf6cdf93857c89391551d3bb5bcbec509e9603ea4b82184d3c086f4fbf71bb77ebff81c326ecf28e15f67bb58f9098bc7b7ac14bcb65eb9a700e58df27da586f06d29271c613abffcd90c0941e7960e9080ac7db4e0bb83e4316e82f44641a4226dafd739063ba9f0609c80d78c9feb3cd92ea1a754c008057bafce56f62a9ab8152cc93800f1f51f93f44b8c26bbf751db4b2e984814a481b9185f42aa81e296dca6836530f1c415bc2d015691e1afc3b73073baca1672a01d84fecaf8033f9e540319c8682b8fbe041ba95098f04d369c274b28b578c0390f2967f419c8344920149ead5f711772784a47f95ea3bded519e6dff818d0a303c4bb7c2
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.24
#
# <at:var at:name="NOGPL" />
#
# @include dump.inc
# @include kerberos_func.inc
# @include x509_func.inc
# @include spad_log_func.inc
# @include string.inc
# @include ssh_lib_util.inc
# @include ssh_lib_kex.inc
# @include ssh_lib_cipherset.inc
# @include ssh_lib_client_cb.inc
# @include ssh_lib_state.inc
# @include ssh_lib_channel.inc
# @include ssh_lib_cmd_logger.inc
# @include ssh_lib_shell_handler.inc
# @include ssh_lib_timos_shell_handler.inc
# @include ssh_lib_sftp.inc
###

include("dump.inc");
include("math64.inc");
include("kerberos_func.inc");
include("x509_func.inc");
include("spad_log_func.inc");
include("string.inc");
include("ecc.inc");
include("ssh_lib_util.inc");
include("ssh_lib_kex.inc");
include("ssh_lib_cipherset.inc");
include("ssh_lib_client_cb.inc");
include("ssh_lib_state.inc");
include("ssh_lib_channel.inc");
include("ssh_lib_cmd_logger.inc");
include("ssh_lib_shell_handler.inc");
include("ssh_lib_shell_handler_misc.inc");
include("ssh_lib_basic_shell_handler.inc");
include("ssh_lib_tmsh_shell_handler.inc");
include("ssh_lib_ios_shell_handler.inc");
include("ssh_lib_timos_shell_handler.inc");
include("ssh_lib_exos_shell_handler.inc");
include("ssh_lib_netapp_shell_handler.inc");
include("ssh_lib_firepower_shell_handlers.inc");
include("ssh_lib_sftp.inc");
include("lcx.inc");

global_var last_error, info_t;
global_var checking_default_account_dont_report;

##
#
#  Namespace sshlib
#    Provides an encapsulated naming scope for sshlib functions and objects
#
##
namespace sshlib {

  global_var USE_LEGACY, CRED_SETS;
  global_var _SCRATCH_PAD_MIRROR = make_list();
  global_var _SESSION_NUMBER_COUNTER = 0;
  global_var IS_SONICWALL = FALSE;
  USE_LEGACY = "use legacy";
  CRED_SETS  = "cred sets";
  default_local_version = "WebRAYRocks";

  ##
  #
  # Object sshpacket
  #   Data and functions for processing SSH packets
  #
  ##

  object sshpacket
  {
    var raw;        # Raw unencrypted packet data

    var length;     # Length of entire packet
    var pad_length; # Length of random padding
    var payload;    # Payload minus the packet type byte
    var padding;    # Random padding
    var mac;        # MAC string (if applicable)

    var type;       # ord(packet type byte)

    var error;      # errors

    ##
    # Constructs an sshpacket object instance
    #
    # @anonparam <First> Binary string of raw unencrypted packet bytes
    # @anonparam Second zlib inflate stream for packet decompression
    # @category SSH
    ##
    function sshpacket()
    {
      raw = _FCT_ANON_ARGS[0];

      if(!isnull(raw))
        parse(infl_strm:_FCT_ANON_ARGS[1]);

      return NULL;
    }

    ##
    # Sets the packet payload
    #
    # @anonparam <First> Binary string representation of the payload
    # @category SSH
    ##
    public function set_payload()
    {
      payload = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Records an error.  Appends new error to current error state
    # and sets last_error to the new error.
    #
    # @anonparam <First> A string description of the error that occurred.
    # @category SSH
    ##
    function set_error()
    {
      if(isnull(error) || error == "")
        error = _FCT_ANON_ARGS[0];
      else
        error += '\n' + _FCT_ANON_ARGS[0];

      # get_ssh_error() in ssh_func.inc expects only the last error
      last_error = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Validates a raw unencrypted packet and decompresses it if it was compressed.
    #
    # @param <infl_strm> A zlib inflate stream for packet decompression
    # @category SSH
    ##
    function parse(infl_strm)
    {
      local_var payload_length;
      local_var pos = 0;

      # Length fields add up to 5 bytes
      if(strlen(raw) < 5)
        return set_error("Premature end of packet when reading length fields.");

      # Packet length is first 4 bytes
      length = getdword(blob:raw, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
      pos += 4;

      # If the remaining packet size after the packet length field is less than the
      # packet length, then the packet is malformed
      if(strlen(raw) - pos < length)
        return set_error("Premature end of packet when reading payload.");

      # Padding length is next 1 byte
      pad_length = getbyte(blob:raw,pos:pos);
      pos += 1;

      # If the remaining packet size after the padding length field is less than the
      # padding length, then the packet is malformed
      if(strlen(raw) - pos < pad_length)
        return set_error("Premature end of packet when reading padding.");

      # Payload length is the packet length minus the padding length minus the 1 byte
      # padding length field
      payload_length = length - pad_length - 1;

      # Payload
      payload = substr(raw, pos, (pos+payload_length)-1);
      pos += payload_length;

      # If the remaining packet size after the payload is less than the padding length,
      # then the packet is malformed
      if(strlen(raw) - pos < pad_length)
        return set_error("Premature end of packet when reading padding.");

      # Padding
      padding = substr(raw, pos, (pos+pad_length)-1);
      pos += pad_length;

      # There should be no data remaining after the padding, since we have not yet
      # received the MAC
      if(strlen(raw) - pos > 0)
        return set_error("Unexpected data after end of packet.");

      # Decompress payload
      if(!isnull(infl_strm))
      {
        payload = gzip_inflate(data:payload, flush:Z_PARTIAL_FLUSH, stream:infl_strm);
        if(empty_or_null(payload))
          return set_error("Could not decompress packet.");
      }

      # Strip type byte out of payload
      type = ord(payload[0]);
      payload = substr(payload, 1, strlen(payload));

      return NULL;
    }
  }

  ##
  #
  # Object session
  #   Data and functions for handling a SSH session.
  #
  ##

  object session {

    var number;
    var debug = FALSE;
    var recv_timeout = 30;
    var legacy_data = make_array();

    var kex_handler;

    var channel_manager;

    var remote_host = '';

    var ignore_known_hosts = FALSE;

    var redact = FALSE; # set to redact displaying sensitive packets in debug log
    var user = "";
    var password = "";
    var login_method = "";
    var kerb_host, realm;

    var supported_auth_methods = make_list();

    var authenticated = FALSE;

    var compression_alg_s_to_c, compression_alg_c_to_s;

    var cur_state = new("sshlib::ssh_client_state");
    var packet_handler_callbacks = NULL;
    var compression_enabled_c_to_s = FALSE;
    var compression_enabled_s_to_c = FALSE;

    var interactive_login_cb = NULL;

    var socket = NULL;
    var port = 22;
    var remote_version = FALSE;
    var remote_host_key = NULL;
    var local_version = NULL;
    var encrypted = FALSE;
    var error = NULL;
    var cmd_error = NULL;
    var cmd_interrupted = FALSE;
    var seqn_w = 0; # Sent sequence number
    var seqn_r = 0; # Receive sequence number

    var infl_strm, defl_strm;

    var userauth_banner;

    var bugged_sshd_ver = FALSE;

    var post_login_error = FALSE;

    var objname = 'session.';

    ##
    # Sets the compression algorithm to be used for the SSH session.
    # Each direction of communication can have its own compression algorithm or none.
    #
    # @param <mode> An integer signifying the direction of communication to set a
    #        compression algorithm for.  MODE_IN = 0, MODE_OUT = 1
    # @param <alg> A string denoting the compression algorithm to set.  Currently:
    #        "none", "zlib" and "zlib.openssh.com"
    #        are supported.
    # @category SSH
    ##
    public function set_compression_alg(mode, alg)
    {
      var fn = 'session.set_compression_alg';
      if(mode == MODE_IN)
      {
        dbg_log(fn:fn, level:DEBUG1, message:'setting compression for MODE_IN to ' + alg + '\n');
        compression_alg_s_to_c = alg;
      }
      else if(mode == MODE_OUT)
      {
        dbg_log(fn:fn, level:DEBUG1, message:'setting compression for MODE_OUT to ' + alg + '\n');
        compression_alg_c_to_s = alg;
      }

      return NULL;
    }

    ##
    # Sets a timeout value for receiving data.
    #
    # @anonparam <First> An integer timeout in seconds.
    # @category SSH
    ##
    public function set_recv_timeout()
    {
      this.recv_timeout = int(_FCT_ANON_ARGS[0]);

      return NULL;
    }

    ##
    # Enables compression in the indicated direction.
    #
    # @param <mode> An integer signifying the direction of communication to enable
    #        compression for.  MODE_IN = 0, MODE_OUT = 1
    # @category SSH
    ##
    public function enable_compression(mode)
    {
      local_var fn = 'session.enable_compression';
      dbg_log(fn:fn, level:DEBUG1, message:'Compression enabled at level 6 [MODE ' + mode + '].\n');
      if(mode == MODE_OUT)
      {
        compression_enabled_c_to_s = TRUE;
        defl_strm = gzip_deflate_init(windowBits:15, level:6);
      }
      else if(mode == MODE_IN)
      {
        compression_enabled_s_to_c = TRUE;
        infl_strm = gzip_inflate_init(windowBits:15);
      }

      return NULL;
    }

    ##
    # Disables compression in the indicated direction.
    # This function also closes any gzip stream that might be open in the
    # indicated direction.
    #
    # @param <mode> An integer signifying the direction of communication to disable
    #        compression for.  MODE_IN = 0, MODE_OUT = 1
    # @category SSH
    ##
    public function disable_compression(mode)
    {
      local_var fn = 'session.disable_compression';
      dbg_log(fn:fn, level:DEBUG1, message:'Compression disabled. [ MODE ' + mode + '].\n');

     if(mode == MODE_OUT)
      {
        compression_enabled_c_to_s = FALSE;
        gzip_deflate_end(defl_strm);
        defl_strm = NULL;
      }
      else if(mode == MODE_IN)
      {
        compression_enabled_s_to_c = FALSE;
        gzip_inflate_end(infl_strm);
        infl_strm = NULL;
      }

      return NULL;
    }

    ##
    # Sets a parameter to control whether or not to use the legacy SSH library
    #
    # @anonparam <First> A boolean (TRUE or FALSE).
    #    TRUE means use the legacy SSH library.
    #    FALSE means do not use the legacy SSH library.
    # @category SSH
    ##
    public function use_legacy()
    {
      if (!isnull(_FCT_ANON_ARGS[0]) && _FCT_ANON_ARGS[0] == FALSE)
      {
        dbg_log(fn:'use_legacy', level:DEBUG3,
          message:"Setting legacy_data[USE_LEGACY] to FALSE.");
        legacy_data[USE_LEGACY] = FALSE;
      }
      else
      {
        dbg_log(fn:'use_legacy', level:DEBUG3,
          message:"Setting legacy_data[USE_LEGACY] to TRUE.");
        legacy_data[USE_LEGACY] = TRUE;
      }

      return NULL;
    }

    ##
    # Stores which credentials sets have already been tried so that if
    # the library fails over to legacy code they won't have to be tried
    # again.
    #
    # @anonparam <First> An array of boolean values with TRUE indicating the
    #    index of a credential set that has already been tried.
    # @category SSH
    ##
    public function set_legacy_cred_sets()
    {
      var sets = _FCT_ANON_ARGS[0];
      if(isnull(sets)) return NULL;

      legacy_data[CRED_SETS] = sets;

      return NULL;
    }


    ##
    # Sets a flag that determines whether log messages will be replaced with
    # [REDACTED]
    # This is to prevent the logging of sensitive data such as passwords.
    #
    # @anonparam <First> A boolean value.  TRUE means comments will be redacted.
    # @category SSH
    ##
    public function set_redact ()
    {
      redact = _FCT_ANON_ARGS[0];

      return NULL;
    }

    var pkt_data;
    var pkt_raw;
    var last_packet;

    var cipherset = NULL;
    var new_cipherset = NULL;

    var nosetup_shell_handler = NULL;

    ##
    # Turns on SSH host verification.
    #
    # @category SSH
    ##
    public function check_known_hosts()
    {
      ignore_known_hosts      = FALSE;

      return NULL;
    }

    ##
    # Turns off SSH host verification.
    #
    # @category SSH
    ##
    public function ignore_known_hosts()
    {
      ignore_known_hosts      = TRUE;

      return NULL;
    }

    ##
    # Sets the SSH port
    #
    # @anonparam <First> Integer value of the current SSH port
    # @category SSH
    ##
    public function set_port()
    {
      port                    = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Gets the SSH port
    #
    # @return Integer port value.
    # @category SSH
    ##
    public function get_port()                    { return this.port; }

    ##
    # Supplies a TCP socket to use for communication
    #
    # @anonparam <First> A TCP socket handle
    # @category SSH
    ##
    public function set_socket()
    {
      socket                  = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Stores the contents of the SSH_MSG_USERAUTH_BANNER message.  This banner
    # is sometimes used in host fingerprinting.
    #
    # @anonparam <First> The text contents of the SSH_MSG_USERAUTH_BANNER message.
    # @category SSH
    ##
    public function set_userauth_banner()
    {
      userauth_banner         = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Stores the remote server's SSH protocol version.
    #
    # @anonparam <First> A string representation of the SSH protocol version.
    # @category SSH
    ##
    public function set_remote_version()
    {
      remote_version          = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Stores the local client's SSH protocol version.
    #
    # @anonparam <First> A string representation of the SSH protocol version.
    # @category SSH
    ##
    public function set_local_version()
    {
      local_version           = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Stores a set of ciphers to be used in key negotiation.
    #
    # @anonparam <First> A sshlib::cipherset object instance.
    # @category SSH
    ##
    public function set_new_cipherset()
    {
      new_cipherset           = _FCT_ANON_ARGS[0];

      return NULL;
    }

    ##
    # Stores a remote host key to be used with host verification.
    #
    # @anonparam <First> A public host key identifying the remote host.
    # @category SSH
    ##
    public function set_remote_host_key()
    {
      remote_host_key = _FCT_ANON_ARGS[0];
      dbg_log(fn:'session.set_remote_host_key', level:DEBUG3,
              message:'Remote host key in base64:', base64:remote_host_key);

      return NULL;
    }

    ##
    # Turns on debug logging at the specified debug level.
    #
    # @anonparam <First> The debug level: 1, 2, or 3 - may also be
    #    DEBUG1, DEBUG2 or DEBUG3 as defined in ssh_lib_util.inc
    #   This function turns on global debugging so it should not be used
    #   with 0 to disable debug logging.
    # @category SSH
    ##
    public function set_debug()
    {
      # only to be called by plugin dev on in debug plugins, so we can go ahead and set this
      replace_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);
      debug = _FCT_ANON_ARGS[0];
      dbg_log(fn:'session.set_debug', message: "Debugging enabled at level DEBUG" + debug + '\n');

      return NULL;
    }

    ##
    # Adds a message to the GizaNE debug log if the current debug level is
    # greater or equal to the log level of the message.  Options are available
    # to log additional data in base64 or as a hex string If the session is
    # set to redact messages, hex data content will be replaced by the
    # string '[REDACTED]'
    #
    # @param <message:string> A description of the event being logged.
    # @param <level:int> The debug level of the logged message.  The message will not be logged
    #        if the session debug level is less than the message level when this is
    #        supplied.  The debug level: 0, 1, 2, or 3 - may also be
    #        DEBUG_DISABLED, DEBUG1, DEBUG2 or DEBUG3 as defined in ssh_lib_util.inc
    # @param <fn:string> String that provides a function scope for the log message.
    # @param <base64:data> A binary string to be encoded in base64 and appended to the log message.
    # @param <ddata:data> A binary string representing data to be encoded in hexadecimal and appended
    #        to the log message.  This data is subject to redaction.
    # @param <sftp:string> name of the sftp specific log
    # @param <sftp_channel:int> number indicating channel number used by sftp
    # @anonparam <First:string> The debug message if the message named parameter is not set
    # @return Returns the entire log message as formed or NULL if the current log
    #         level is insufficient for the message.
    # @category SSH
    ##
    public function dbg_log(message, level, fn, base64, ddata, sftp, sftp_channel)
    {
      var s;
      if (!isnull(level) && this.debug < level) return NULL;
      if (isnull(message)) message = _FCT_ANON_ARGS[0];
      if (isnull(fn)) fn = '';
      else fn += ': ';
      if(sftp && !isnull(sftp_channel))
        s = '[session ' + this.get_number() + ':' + sftp_channel + '] '+ fn + message;
      else
        s = '[session ' + this.get_number() + '] '+ fn + message;
      if (!isnull(base64))
        s += base64(str:base64) + '\n';
      if (!isnull(ddata))
      {
        if (this.redact) s += '\n[REDACTED]';
        else s += '\n' + hexdump(ddata:ddata);
      }
      if (s[strlen(s)-1] != '\n') s += '\n';
      spad_log(message:s);
      if (sftp)
        spad_log(name:sftp, message:s);
      if (TAP_MODE)
        _SCRATCH_PAD_MIRROR[max_index(_SCRATCH_PAD_MIRROR)] = s;
      return s;
    }

    ##
    # Records an error.  Appends new error to session's current error state
    # and sets last_error to the new error.  The new error is logged at
    # debug level 2.
    #
    # @anonparam <First> A string description of the error that occurred.
    # @category SSH
    ##
    public function set_error()
    {
      error += _FCT_ANON_ARGS[0] + '\n';

      # get_ssh_error() in ssh_func.inc expects only the last error
      last_error = _FCT_ANON_ARGS[0];

      dbg_log(fn:'session.set_error', level:DEBUG2, message:_FCT_ANON_ARGS[0]);

      return NULL;
    }

    ##
    # Records authentication errors for reporting.
    #
    # @param <user>  User id.
    # @param <port>  Integer SSH port number.
    # @param <msg>   Authentication error description.
    # @return NULL
    # @category SSH
    ##
    public function set_auth_failure_error(user, port, msg)
    {
      this.set_error(msg);

      if(checking_default_account_dont_report) return NULL;

      if(isnull(port)) port = sshlib::kb_ssh_transport();
      var prefix = "Host/Auth/SSH/" + port + "/";
      replace_kb_item(name:prefix + "Failure", value:TRUE);

      if(isnull(user) || strlen(user) == 0) user = "Unknown User";
      if(isnull(msg) || strlen(msg) == 0) msg = "No details available";

      lcx::log_issue(type:lcx::ISSUES_AUTH, msg:msg, port:port,
        proto:lcx::PROTO_SSH, user:user);

      return NULL;
    }

    ##
    # Records errors per command that is run locally using SSH.  Command
    # errors are also recorded as an error in the session.
    #
    # @anonparam <First> A string description of the error that occurred.
    # @category SSH
    ##
    public function set_cmd_error()
    {
      cmd_error += '\n' + _FCT_ANON_ARGS[0];
      set_error(_FCT_ANON_ARGS[0]);

      return NULL;
    }

    ##
    # Clears the current per-command error.  This is to be run before
    # executing a new local command on the target.
    #
    # @anonparam <First> A string description of the error that occurred.
    # @category SSH
    ##
    public function clear_cmd_error()
    {
      cmd_error = NULL;

      return NULL;
    }

    ##
    # Reports if the last command timed out.
    #
    # @category SSH
    ##
    public function last_cmd_interrupted()
    {
      return cmd_interrupted;
    }

    ##
    # Resets the cmd_interrtupted .
    #
    # @category SSH
    ##
    public function reset_cmd_interrupted()
    {
      cmd_interrupted = FALSE;
      return NULL;
    }


    ##
    # Called after a successful key exchange with the SSH server, this function
    # establishes the newly negotiated cipherset object as the working
    # cipher set for the current session.
    #
    # @category SSH
    ##
    public function new_keys()
    {
      cipherset = new_cipherset;
      new_cipherset = NULL;

      encrypted = TRUE;

      return NULL;
    }

    ##
    # Initializes new cipherset for session with algorithms negotiated at the start
    # of key exchange.  Associates the current session with the new cipher set.
    #
    # @category SSH
    ##
    public function init_new_crypto()
    {
      new_cipherset.set_crypto_alg(mode:MODE_OUT, this.kex_handler.encryption_alg_c_to_s);
      new_cipherset.set_crypto_alg(mode:MODE_IN, this.kex_handler.encryption_alg_s_to_c);

      new_cipherset.set_mac_alg(mode:MODE_OUT, this.kex_handler.mac_alg_c_to_s);
      new_cipherset.set_mac_alg(mode:MODE_IN, this.kex_handler.mac_alg_s_to_c);

      new_cipherset.set_session(this);

      return NULL;
    }

    ##
    # Closes the socket associated with the current session, set the session state
    # to closed and deletes objects associated with the session.  If an error message
    # is supplied it set as an error in the session state.
    #
    # @param <error> String describing any error associated with closing the socket.
    # @return NULL
    # @category SSH
    ##
    public function close_socket(error)
    {
      var fn = 'session.close_socket';

      if(!isnull(error)) set_error(error);

      # Verify that socket is still open
      if(cur_state.val == "SOC_CLOSED")
      {
        dbg_log(fn:fn, level:DEBUG3, message:
          "Socket has already been closed.");
        return NULL;
      }

      if(compression_enabled_s_to_c)
        disable_compression(mode:MODE_IN);
      if(compression_enabled_c_to_s)
        disable_compression(mode:MODE_OUT);
      encrypted = FALSE;
      seqn_r = 0;
      seqn_w = 0;

      if (typeof(kex_handler) == 'object') delete(kex_handler);
      if (typeof(channel_manager) == 'object') delete(channel_manager);
      if (!isnull(cipherset.cipher_s_to_c) && typeof(cipherset.cipher_s_to_c) == 'object') delete(cipherset.cipher_s_to_c);
      if (!isnull(cipherset.cipher_c_to_s) && typeof(cipherset.cipher_c_to_s) == 'object') delete(cipherset.cipher_c_to_s);
      if (typeof(cipherset) == 'object') delete(cipherset);
      if (!isnull(new_cipherset) && typeof(new_cipherset) == 'object') delete(new_cipherset);

      if(!TAP_MODE && nasl_level() >= 6900 && !is_sock_open(socket))
      {
        dbg_log(fn:fn, level:DEBUG3, message:
          "Socket is no longer open - possibly closed by the remote host.");
        cur_state.set("SOC_CLOSED");
        close(socket);
        return NULL;
      }

      dbg_log(fn:fn, level:DEBUG3, message:"Closing socket.");
      cur_state.set("SOC_CLOSED");
      if (TAP_MODE) tap_mode_close_socket(socket);
      else close(socket);

      return NULL;
    }

    ##
    # Constructs a session object: Initializes the session state.
    #
    # @category SSH
    ##
    function session()
    {
      # if GUI debugging is enabled, go ahead and set highest debug level
      this.number = _SESSION_NUMBER_COUNTER;
      _SESSION_NUMBER_COUNTER += 1;

      if(get_kb_item("global_settings/enable_plugin_debugging"))
        set_debug(DEBUG3);

      last_error = "";
      packet_handler_callbacks = SSH_CLIENT_HANDLERS;

      cur_state.set_session(this);
      cur_state.set("SOC_CLOSED");

      return NULL;
    }

    ##
    # Returns the number of the current session.  The session number is assigned
    # when the session is created from a global variable counter.  So the number
    # means that this is the nth session created in a given plugin run.
    #
    # @return Integer number of the current session
    # @category SSH
    ##
    public function get_number()
    {
      return this.number;
    }

    ##
    # Return the default channel object.  This is usually the first channel created
    # for a connection.
    #
    # @return The default channel object of the current connection's channel manager.
    # @category SSH
    ##
    public function get_default_channel()
    {
      return this.channel_manager.get_default_channel();
    }

    ##
    # Return the shell handler object owned by the default channel.
    #
    # @return The shell handler of the default channel
    # @category SSH
    ##
    public function get_default_shell_handler()
    {
      local_var dc = this.get_default_channel();
      return dc.shell_handler;
    }

    ##
    # This function initiates a new SSH session by requesting that the server open
    # a channel.  The channel particulars are extracted from the SSH messages and
    # stored in a new channel object.
    #
    # @param <type> String denoting a channel type per definition of SSH_MSG_CHANNEL_REQUEST - see IETF RFC4254
    # @param <options> Binary string representing options for the selected channel type.
    # @param <window> Integer local window size. The window size specifies how many bytes the other party can send
    #                 before it must wait for the window to be adjusted.
    # @param <maxpacket> Integer size of the largest packet that we can handle.
    # @return A new channel object if the request is successful, FALSE otherwise.
    # @category SSH
    ##
    public function get_channel(type, options, window, maxpacket)
    {
      if(cur_state.val == "SOC_CLOSED")
        return set_error("Socket closed, unable to obtain channel.");

      if(isnull(type)) type = "session";
      var channel = channel_manager.open_new_channel(type      : type,
                                                     options   : options,
                                                     window    : window,
                                                     maxpacket : maxpacket);

      channel.open_channel();

      var cb = @client_cb_check_channel_not_pending;
      sshrecv_until(end_states:make_list("SOC_CLOSED"), check_callback:cb, channel:channel);

      if(channel.state == CHANNEL_STATE_ACCEPTED)
        return channel;

      # If the remote SSH server denied the channel open request with
      # a packet of type CHANNEL_OPEN_FAILURE, then the channel state
      # will have been set to CHANNEL_STATE_DENIED.
      # There's a race condition in OpenSSH that results in channel
      # open failure if MaxSessions is set to 1, so try one more time
      # to open a channel.
      if (channel.state != CHANNEL_STATE_DENIED)
        return FALSE;

      channel_manager.remove_channel(channel:channel);
      delete(channel);

      channel = channel_manager.open_new_channel(type      : type,
                                                 options   : options,
                                                 window    : window,
                                                 maxpacket : maxpacket);

      channel.open_channel();

      sshrecv_until(end_states:make_list("SOC_CLOSED"), check_callback:cb, channel:channel);

      if(channel.state == CHANNEL_STATE_ACCEPTED)
        return channel;
      else return FALSE;
    }


    ##
    # Sends a packet over an open SSH connection to the remote server.
    # Handles client to server compression and encryption if they are connfigured.
    #
    # @param <data> SSH packet data
    # @param <code> The SSH message code.  Message code enumerations are defined in
    #               ssh_lib_util.inc (i.e. PROTO_SSH2_MSG_CHANNEL_DATA)
    # @return NULL
    # @category SSH
    ##
    public function sshsend(data, code)
    {
      local_var pkt_len, pad, pad_len, pkt_data, padding_len, payload, i;
      local_var fn = 'session.sshsend';
      local_var send_status;

      # Verify socket is still open before sending
      if (!check_socket()) return NULL;

      if(isnull(code))
      {
        if (strlen(data))
          dbg_log(fn:fn, level:DEBUG3, message:'Outgoing Unencrypted packet:\n', ddata:data);

        if(TAP_MODE)
        {
          send_status = tap_mode_send(socket:socket,data:data);
          if(!send_status || send_status < 0)
            handle_socket_error();
          return send_status;
        }
        else
        {
          send_status = send(socket:socket,data:data);
          if(!send_status || send_status < 0)
            handle_socket_error();
          return send_status;
        }
      }
      if(compression_enabled_c_to_s && strlen(raw_string(code) + data))
        dbg_log(fn:fn, level:DEBUG3, message:'Outgoing Uncompressed Payload ['
          + ssh2_packet_type_labels[code] + '] : \n', ddata:raw_string(code) + data);

      if(compression_enabled_c_to_s)
        payload  = gzip_deflate(data:raw_string(code) + data, flush:Z_PARTIAL_FLUSH, stream:defl_strm);
      else
        payload = raw_string(code) + data;

      pkt_len = strlen(payload) + 1; # payload + padding length

      #If we are using an ETM MAC, don't add length bytes to encryption length
      var pkt_len_len = 4;
      if(encrypted && (cipherset.is_etm(mode:MODE_OUT)|| cipherset.is_gcm(mode:MODE_OUT)))
        pkt_len_len = 0;

      if (!encrypted)
      {
        pad_len = 8 - ((pkt_len + pkt_len_len) % 8);
        if(pad_len < 4) pad_len += 8;
      }
      else
      {
        pad_len = cipherset.get_block_size(mode:MODE_OUT) - ((pkt_len + pkt_len_len) % cipherset.get_block_size(mode:MODE_OUT));
        if(pad_len < 4) pad_len += cipherset.get_block_size(mode:MODE_OUT);
      }

      pkt_len += pad_len;

      pad = "";
      for (i = 0; i < pad_len; i++)
        pad += mkbyte(rand() % 256);

      #Packet length is outside of encryption for ETM MACs
      if(!encrypted || (!cipherset.is_etm(mode:MODE_OUT) && !cipherset.is_gcm(mode:MODE_OUT)))
        pkt_data = mkdword(pkt_len, order:BYTE_ORDER_BIG_ENDIAN);
      else
        pkt_data = '';

      pkt_data += mkbyte(pad_len)  +
                  payload +
                  pad;

      if(strlen(pkt_data))
      {
        var tmp = '';
        if(compression_enabled_c_to_s) tmp = '/Compressed';
        dbg_log(fn:fn, level:DEBUG3, message:'Outgoing Raw Unencrypted' + tmp + ' packet ['
            + ssh2_packet_type_labels[code] + '] :', ddata:pkt_data);
      }

      if (encrypted)
      {
        local_var mac;
        local_var enc_pkt_len;

        mac = '';
        if(!cipherset.is_etm(mode:MODE_OUT) && !cipherset.is_gcm(mode:MODE_OUT))
          mac = cipherset.mac_compute(mode:MODE_OUT, data:pkt_data);

        if(cipherset.is_gcm(mode:MODE_OUT))
        {
          enc_pkt_len = mkdword(strlen(pkt_data));

          var cipher_result = cipherset.encrypt(data:pkt_data);
          pkt_data = cipher_result[0] + cipher_result[1];
          pkt_data = enc_pkt_len + pkt_data;
        }
        else
        {
          pkt_data = cipherset.encrypt(data:pkt_data);
        }

        if(cipherset.is_etm(mode:MODE_OUT) && !cipherset.is_gcm(mode:MODE_OUT))
        {
          enc_pkt_len = mkdword(strlen(pkt_data));
          pkt_data = enc_pkt_len + pkt_data;

          mac = cipherset.mac_compute(mode:MODE_OUT, data:pkt_data);
        }

        pkt_data += mac;
      }

      if(encrypted && strlen(pkt_data))
      {
        dbg_log(fn:fn, level:DEBUG3, message:'Outgoing Encrypted packet [' + ssh2_packet_type_labels[code] + '] :',
          ddata:pkt_data);
      }

      if(TAP_MODE)
      {
        send_status = tap_mode_send(socket:socket, data:pkt_data);
        if(!send_status || send_status < 0)
          handle_socket_error();
        seqn_w++;
        return NULL;
      }

      send_status = send(socket:socket, data:pkt_data);
      if(!send_status || send_status < 0)
        handle_socket_error();
      seqn_w++;

      return NULL;
    }

    ##
    # Waits on the SSH socket, reading packets and dispatching them to
    # callbacks based on the SSH message code until one of the designated
    # end states is reached, the specified check callback returns true or
    # the socket is closed due to error or handling a message.
    #
    # @param <endstates> An array of strings describing SSH communication end
    #        states.  Possible end states are enumerated in ssh_lib_state.inc
    #        in the global list ssh_client_allowed_states.
    # @param <check_callback> A reference to a callback function that designates
    #        criteria for the end of message processing by returning TRUE
    # @param <channel> The current channel object instance.
    # @param <timeout> Seconds that may elapse waiting for a reply from the SSH server.
    # @param <cmd_timeout> Seconds that may elapse during the processing of messages.
    # @param <track_keepalives> Boolean flag to enable timeout via tracking "keepalive@openssh.com"
    #                           messages. Used for sonicwall devices. (optional)
    # @category SSH
    ##
    public function sshrecv_until(end_states, check_callback, &channel, timeout, cmd_timeout, track_keepalives)
    {
      var func;
      var type_label;
      var fn = 'session.sshrecv_until';

      var ts;
      var keepalives = 0;

      if((isnull(timeout) || cmd_timeout < timeout) && !isnull(cmd_timeout))
        timeout = cmd_timeout;

      if(TAP_MODE && !cmd_timeout) cmd_timeout = 2;

      if (cmd_timeout) ts = unixtime();
      while ((!cmd_timeout) || ((unixtime() - ts) < cmd_timeout))
      {

        if(!isnull(end_states) && cur_state.oneof(state_list:end_states)) break;
        if(!isnull(check_callback) && check_callback(session:this, channel:channel)) break;

        if(track_keepalives)
        {
          if("keepalive@openssh.com" >< last_packet.payload) keepalives++;
          if(keepalives > 10) break;
        }

        last_packet = NULL;
        sshrecv(timeout:timeout);

        if(cur_state.val == "SOC_CLOSED" || channel.state == CHANNEL_STATE_CLOSED) break;

        if(isnull(last_packet))
        {
          func = packet_handler_callbacks[-1];
          type_label = ssh2_packet_type_labels[-1];
        }
        else
        {
          func = packet_handler_callbacks[last_packet.type];
          type_label = ssh2_packet_type_labels[last_packet.type];
        }

        dbg_log(fn:fn, level:DEBUG1, message:'Handling packet.type: ' + last_packet.type + ' [' + type_label + ']');
        if(!func)
        {
          this.close_connection();
          exit(1,"No handler for packet type " + last_packet.type + " [" + type_label +"].");
        }

        func(session:this);
      }
      if(cmd_timeout && (unixtime() - ts) >= cmd_timeout)
        dbg_log(fn:fn, level:DEBUG1, message:'cmd_timeout reached');

      return NULL;
    }

    ##
    # Creates and returns an identifier unique to the remote host and port.
    #
    # @return String representation of a MD5 hash of the remote host and port.
    # @category SSH
    ##
    public function get_kb_connection_id()
    {
      return hexstr(MD5(remote_host)) + "/" + port;
    }


    ##
    # Opens connection and does initial banner exchange to trigger binary protocol
    # transport.
    #
    # @param <host> String host name or ip address of the remote SSH server
    # @param <port> Listening port of the remote SSH server
    # @param <existing_socket> Socket descriptor
    # @return Returns TRUE if the attempt to open a connection succeeds, FALSE otherwise
    # @category SSH
    ##
    public function open_connection(host, port, existing_socket)
    {
      local_var version;
      local_var fn = "session.open_connection";

      if(!isnull(port)) this.port = port;

      if(!isnull(host)) this.remote_host = host;

      if(empty_or_null(this.remote_host)) this.remote_host = get_host_name();

      if(cur_state.val != "SOC_CLOSED")
        return set_error("Error - expected SOC_CLOSED state of open_connection(), got " + cur_state.val);

      if(!isnull(existing_socket))
      {
        # Verify socket is a valid integer
        if(typeof(existing_socket) != "int" || existing_socket < 1)
          return set_error("Error - invalid existing_socket value '"+existing_socket+"'.");

        # Verify socket is still open
        if(!TAP_MODE && nasl_level() >= 6900 && !is_sock_open(existing_socket))
        {
          set_error("Error - existing_socket '"+existing_socket+"' is no longer open.");
          # Call close_socket() so that objects are properly cleaned up
          close_socket();
          return NULL;
        }
        set_socket(existing_socket);
        dbg_log(fn:fn, level:DEBUG1, message:"Using existing socket.");
      }
      else
      {
        if(isnull(port) || port == "")
          return set_error("Error - no port specified.");

        if(typeof(port) != "int")
          return set_error("Error - non integer port specified.");

        if(TAP_MODE) set_socket(tap_mode_get_socket());
        else if(!isnull(host))
        {
          if(nasl_level() >= 6600 && !rules_validate_target(target:host, port:port))
            return set_error("Connecting to host "+host+" port "+port+" violates user-defined rules.");
          dbg_log(message:"Connecting to host '"+host+"', port "+port+".", fn:fn, level:DEBUG3);
          set_socket(open_sock2(host:host, port:port));
        }
        else
        {
          dbg_log(message:"Connecting to port "+port+".", fn:fn, level:DEBUG3);
          set_socket(open_sock_tcp(port));
        }

        if(!socket)
          return set_error("Failed to open a socket on port "+port+".");

        dbg_log(fn:fn, level:DEBUG1, message:"Socket opened on port " + port + '.\n');
      }

      cur_state.set("SOC_OPENED");

      # Reset remote_version so that sshrecv() does not expect a packet
      remote_version = FALSE;

      # it's possible that a server may try to send banner + first kex packet in first request
      # it's not RFC compliant, but it came up as a test case from QA, so the code below
      # only recvs until the newline and leaves the rest in the buffer for later
      version = '';
      var tmp_chr = '';
      # initial connection may be slow on some devices
      tmp_chr = sshrecv(timeout:30, length:1);
      var i = 0;
      while(tmp_chr != '' && !isnull(tmp_chr) && tmp_chr != '\n' &&
            cur_state.val == "SOC_OPENED" && i < 512)
      {
        version += tmp_chr;
        tmp_chr = sshrecv(timeout:5, length:1);
        i++;
      }

      if(!version)
        return close_socket(error:"No remote version received");

      dbg_log(fn:fn, level:DEBUG1, message: "Received server version " + version);

      local_var ver_num_match;
      ver_num_match = pregmatch(pattern:"^SSH-(2\.0|1\.\d+)-", string:version);
      if (isnull(ver_num_match))
        return close_socket(error:"Bad remote version string received '"+version+"'");

      remote_version = chomp(version);

      ## We should check to see if the version is < 1.99 here. If so, we should
      ## fall back to legacy code, if we arrived here *through* legacy code
      ## (through one of the wrapper functions).
      if (ver_compare(ver:ver_num_match[1], fix:'1.99', strict:TRUE) < 0)
      {
        legacy_data[USE_LEGACY] = TRUE;
        close_socket(error:"Based on its reported version '"+remote_version+"', the remote SSH server does not support SSH 2.0.");
        return FALSE;
      }

      # If compression has been tried and disabled from a previous test, supress it here.
      if (get_kb_item(SSH_LIB_KB_PREFIX + "disable_compression"))
      {
         KEX_SUPPORTED_NAME_LISTS["compression_algorithms_server_to_client"] = "none";
         KEX_SUPPORTED_NAME_LISTS["compression_algorithms_client_to_server"] = "none";
      }

      kex_handler = new("sshlib::kex_handler", this);
      kex_handler.set_supported_namelists(KEX_SUPPORTED_NAME_LISTS);
      channel_manager = new("sshlib::ChannelManager", this);

      if(isnull(local_version))
        local_version = get_ssh_client_ver();

      sshsend(data:local_version+'\n');

      return TRUE;
    }

    ##
    # Calls handle_socket_error() to check the socket for errors and
    # close the socket if appropriate and then checks if the socket is
    # still open. This should be called before every call to send(),
    # recv(), or close().
    #
    # @return TRUE if the socket is open
    # @return FALSE if the socket is not open
    ##
    function check_socket()
    {
      var fn = 'check_socket';
      if(cur_state.val == "SOC_CLOSED")
      {
        dbg_log(fn:fn, message:"Socket has already been closed.");
        return FALSE;
      }
      if(!TAP_MODE && nasl_level() >= 6900 && !is_sock_open(socket))
      {
        dbg_log(fn:fn, message:"Socket is no longer open.");
        # Call close_socket() so that objects are properly cleaned up
        close_socket();
        return FALSE;
      }
      return TRUE;
    }

    ##
    # Receives and validates a SSH packet over the current SSH connection.
    # Encrypted packets are decrypted and compressed packets are decompressed.
    #
    # @param <timeout> The number of seconds that may elapse while the function
    #                  waits to receive a packet from the remote SSH server.
    # @param <length> The expected packet length.
    # @return Returns a binary string representation of the packet if a valid
    #         SSH packet was received, NULL otherwise.
    # @category SSH
    ##
    public function sshrecv(timeout, length)
    {
      local_var fn = 'session.sshrecv';

      # Verify socket is still open before receiving
      if (!check_socket()) return NULL;

      if(isnull(timeout)) timeout = this.recv_timeout;

      # Respect the policy value for the recv timeout if it is higher
      var policy_timeout = int(get_preference("checks_read_timeout"));
      if (policy_timeout && policy_timeout > timeout)
        timeout = policy_timeout;

      var need, mac, computed_mac, payload;

      if(isnull(length))
        length = MAX_PACKET_SIZE;

      # Versions not exchanged
      if(!remote_version)
      {
        if(TAP_MODE)
          pkt_data = tap_mode_recv(socket:socket, length:length);
        else
          pkt_data = recv(socket:socket, length:length, timeout:timeout);

        if(isnull(pkt_data))
          handle_socket_error();
        return pkt_data;
      }
      if (!encrypted)
      {
        if(TAP_MODE)
          pkt_raw = tap_mode_recv(socket:socket, length:4, min:4);
        else
          pkt_raw = recv(socket:socket, length:4, min:4, timeout:timeout);

        if(strlen(pkt_raw) < 4)
        {
          if(isnull(pkt_raw))
            handle_socket_error();
          dbg_log(fn:fn, message:"Invalid packet, less than 4 bytes received.");
          return NULL;
        }

        var pktlen = getdword(blob:pkt_raw, pos:0, order:BYTE_ORDER_BIG_ENDIAN);
        if(pktlen <= 0)
          return close_socket(error:"Invalid packet length '"+pktlen+"'.");
        else if(pktlen > MAX_PACKET_SIZE)
          return close_socket(error:"Packet length '"+pktlen+"' is larger than MAX_PACKET_SIZE.");

        # Verify socket is still open before receiving again
        if (!check_socket()) return NULL;

        if(TAP_MODE)
          pkt_data = tap_mode_recv(socket:socket, length:pktlen, min:pktlen);
        else
          pkt_data = recv(socket:socket, length:pktlen, min:pktlen, timeout:timeout);
        if(isnull(pkt_data))
          handle_socket_error();

        pkt_raw += pkt_data;

        if(strlen(pkt_raw))
          dbg_log(fn:fn, level:DEBUG3, message:'Incoming Unencrypted packet:',
            ddata:pkt_raw);
        last_packet = new("sshlib::sshpacket",pkt_raw);
      }
      else
      {
        var initial_read_len, len;

        #Read in the etm mac data len (aadlen)
        if(cipherset.is_etm(mode:MODE_IN) || cipherset.is_gcm(mode:MODE_IN))
        {
          if(TAP_MODE)
            len = tap_mode_recv(socket:socket, length:4, min:4);
          else
            len = recv(socket:socket, length:4, min:4, timeout:timeout);
          if(isnull(len))
            handle_socket_error();

          initial_read_len = getdword(blob:len, pos:0, order:BYTE_ORDER_BIG_ENDIAN);

          #Add the MAC/Tag length for authenticated ciphers like aes-gcm
          initial_read_len += cipherset.get_tag_len(mode:MODE_IN);

          dbg_log(fn:fn, level:DEBUG3, ddata:len, message:'Incoming packet length for ETM or GCM ciphers:');

          len = initial_read_len;
        }
        else
          initial_read_len = cipherset.get_block_size(mode:MODE_IN);

        # Verify socket is still open before receiving again
        if (!check_socket()) return NULL;
        if(TAP_MODE)
          pkt_raw  = tap_mode_recv(socket:socket, length:initial_read_len, min:initial_read_len);
        else
          pkt_raw  = recv(socket:socket, length:initial_read_len, min:initial_read_len, timeout:timeout);
        if(isnull(pkt_raw))
          handle_socket_error();

        if(strlen(pkt_raw) == 0) return pkt_raw;

        pkt_data = cipherset.decrypt(data:pkt_raw);
        if(!cipherset.is_etm(mode:MODE_IN) && !cipherset.is_gcm(mode:MODE_IN))
          len = getdword(blob:pkt_data, pos:0, order:BYTE_ORDER_BIG_ENDIAN);

        if(len <= 0)
        {
          close_socket(error:"Invalid packet length '"+len+"' after decrypting packet.");
          if(strlen(pkt_raw))
            dbg_log(fn:fn, level:DEBUG3, ddata:pkt_raw,
              message:'Incoming Raw Encrypted data:');
          if(strlen(pkt_data))
            dbg_log(fn:fn, level:DEBUG3, ddata:pkt_data,
              message:'Incoming Decrypted data:');
          return NULL;
        }
        else if(len > MAX_PACKET_SIZE)
        {
          close_socket(error:"Packet length '"+len+"' after decrypting packet is larger than MAX_PACKET_SIZE.");
          if(strlen(pkt_raw))
            dbg_log(fn:fn, level:DEBUG3, ddata:pkt_raw,
              message:'Incoming Raw Encrypted data:');
          if(strlen(pkt_data))
            dbg_log(fn:fn, level:DEBUG3, ddata:pkt_data,
              message:'Incoming Decrypted data:');
          return NULL;
        }

        if(cipherset.is_etm(mode:MODE_IN) && !cipherset.is_gcm(mode:MODE_IN))
        {
          pkt_data = mkdword(len) + pkt_data;
        }
        else if(cipherset.is_gcm(mode:MODE_IN))
        {
          pkt_data = mkdword(len - cipherset.get_tag_len(mode:MODE_IN)) + pkt_data;
        }
        else
        {
          need = 4 + len - cipherset.get_block_size(mode:MODE_IN);

          # Verify socket is still open before receiving again
          if (!check_socket()) return NULL;

          if(TAP_MODE)
            var left = tap_mode_recv(socket:socket, length:need, min:need);
          else
            left = recv(socket:socket, length:need, min:need, timeout:timeout);
          if(isnull(left))
            handle_socket_error();

          if (need != 0)
          {
            pkt_data = pkt_data + cipherset.decrypt(data:left);
            pkt_raw += left;
          }
        }

        last_packet = new("sshlib::sshpacket",pkt_data,infl_strm);
        var pkt_type = "type unknown";
        if (!isnull(last_packet.type))
          pkt_type = ssh2_packet_type_labels[last_packet.type];

        if(strlen(pkt_raw))
        {
          dbg_log(fn:fn, level:DEBUG3, ddata:pkt_raw, message:
            'Incoming Raw Encrypted packet [' + pkt_type + '] :');
        }

        if(strlen(pkt_data))
        {
          dbg_log(fn:fn, level:DEBUG3, ddata:pkt_data, message:
            'Incoming Decrypted packet [' + pkt_type + '] :');
        }

        if(!isnull(infl_strm) && strlen(raw_string(last_packet.type) + last_packet.payload))
        {
          dbg_log(fn:fn, level:DEBUG3, message:
            'Incoming Decrypted Decompressed packet [' + pkt_type + '] :',
            ddata:(raw_string(last_packet.type) + last_packet.payload));
        }
        if ("Could not decompress packet" >< last_packet.error)
          return close_socket(error:"Failed to decompress packet.");

        if(cipherset.is_etm(mode:MODE_IN))
          computed_mac = cipherset.mac_compute(data:mkdword(len) + pkt_raw, mode:MODE_IN);

        # Verify socket is still open before receiving again
        if (!check_socket()) return NULL;

        #Authenticated ciphers like aes-gcm process message authentication during encryption
        if(!cipherset.is_gcm(mode:MODE_IN))
        {
          if(TAP_MODE)
            mac = tap_mode_recv(socket:socket, length:cipherset.get_mac_len(mode:MODE_IN), min:cipherset.get_mac_len(mode:MODE_IN));
          else
            mac = recv(socket:socket, length:cipherset.get_mac_len(mode:MODE_IN), min:cipherset.get_mac_len(mode:MODE_IN), timeout:timeout);
        }

        # Compute and check MAC
        if(!empty_or_null(mac))
        {
          if(!cipherset.is_etm(mode:MODE_IN))
            computed_mac = cipherset.mac_compute(data:last_packet.raw, mode:MODE_IN);

          dbg_log(fn:fn, level:DEBUG3, message:'MAC received with last packet:', ddata:mac);
          dbg_log(fn:fn, level:DEBUG3, message:'MAC computed from last packet:', ddata:computed_mac);
          if (mac != computed_mac)
            return close_socket(error:"The MAC received with the packet does not match the computed MAC.");
        }
        else if(isnull(mac))
          handle_socket_error();
      }
      seqn_r++;
      if (!isnull(last_packet) && !isnull(last_packet.type) && !isnull(last_packet.payload))
        return raw_string(last_packet.type) + last_packet.payload;
      else
        return NULL;
    }

    ##
    # Executes a local command on the target host using the open SSH connection
    #
    # @param <command> The command to be executed
    # @param <channel> A channel object for the current SSH connection
    # @param <use_shell_handler> A boolean that controls whether SSH exec or a shell
    #                            handler will be used to run the command.
    # @param <cmd_timeout_min> The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param <inactivity_timeout_min> The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    # @param <force_priv_escl> A boolean which if true will force an attempt to
    #                          escalate privileges before running the command.
    # @return Returns the target host's response to running the command as a string, or
    #         NULL if the command fails.
    # @category SSH
    ##
    public function run_command(command, &channel, use_shell_handler,
        cmd_timeout_min, inactivity_timeout_min, force_priv_escl)
    {
      var ret;
      var ts = unixtime();
      var fn = 'session.run_command';
      reset_cmd_interrupted();

      # Depending on the shell handler, timeout may be used to
      # increase the inactivity timeout for the command response,
      # and/or passed to sshrecv_until() as the cmd_timeout
      if(use_shell_handler)
        ret = run_shell_command(
          channel                : channel,
          command                : command,
          force_priv_escl        : force_priv_escl,
          cmd_timeout_min        : cmd_timeout_min,
          inactivity_timeout_min : inactivity_timeout_min
        );
      # For exec, timeout is passed to sshrecv_until() as the cmd_timeout
      # exec handling does not currently implement inactivity handling
      else
        ret = run_exec_command(
          command         : command,
          cmd_timeout_min : cmd_timeout_min
        );

      return ret;
    }

    ##
    # Run a command over the SSH connection using the facility for execution of single
    # commands without a shell.
    #
    # @param <command> The command to be executed
    # @param <cmd_timeout_min> The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @return Returns the target host's response to running the command as a string, or
    #         NULL if the command fails.
    # @category SSH
    ##
    public function run_exec_command(command, cmd_timeout_min)
    {
      var fn = 'session.run_exec_command';
      reset_cmd_interrupted();

      if(cur_state.val == "SOC_CLOSED")
        return set_error("Unable to execute command on closed ssh socket.");
      var channel = get_channel();

      if(!channel)
        return set_error("Failed to get channel.");

      # Set a default timeout; this is the cmd_timeout for sshrecv_until()
      # to receive all data, so it should be relatively high
      var cmd_timeout = 180;
      if (TAP_MODE) cmd_timeout = 0;
      if (cmd_timeout < cmd_timeout_min)
        cmd_timeout = cmd_timeout_min;

      clear_cmd_error();
      channel.make_request(type:"exec", want_reply:TRUE, extra:mk_ssh_string(command));

      var cb = @run_exec_command_cb;
      sshrecv_until(end_states:make_list("SOC_CLOSED"), check_callback:cb, channel:channel,
                    cmd_timeout:cmd_timeout);

      var cmd_logger = new("sshlib::cmd_logger");

      var failed_needs_escl = FALSE;
      if ( (!empty_or_null(channel.data_buf) &&
            is_priv_escl_required(cmd_res:channel.data_buf)) ||
           (!empty_or_null(channel.stderr) &&
            is_priv_escl_required(cmd_res:channel.stderr)) )
        failed_needs_escl = TRUE;

      if(failed_needs_escl)
        dbg_log(fn:fn, level:DEBUG3, message:'The command response or error message indicates that privilege escalation may be required to run the command "'+command+'".\nCommand response: '+channel.data_buf+'\nError: '+channel.stderr);

      if(channel.state != CHANNEL_STATE_CLOSED) channel.close();

      # If no exit-status was sent back in the channel, then the shell command
      # did not complete successfully.
      cmd_interrupted = isnull(channel.last_exit_status);
      if(cmd_interrupted)
      {
        # record error for logging
        set_cmd_error("Command did not complete due to timeout or other error.");
        dbg_log(fn:fn, level:DEBUG3,
                message:'The command "' + command + '" did not complete due to timeout or error.');
      }

      cmd_logger.add(cmd:command, response:channel.data_buf, error:cmd_error, failed_needs_escl:failed_needs_escl, user:this.user);

      if(channel.last_response && !empty_or_null(channel.data_buf))
        return channel.data_buf;
      else return NULL;
    }

    ##
    # Open a new channel, reconnecting first if necessary and copying
    # over shell handler settings if applicable
    #
    # @param <channel> A channel object for the current SSH connection
    # @return TRUE if shell is replaced successfully, else FALSE
    # @category SSH
    ##
    public function replace_shell(&channel)
    {
      var fn = this.objname + FUNCTION_NAME;
      var sh, sh_type, sh_type_ex, sh_sets, needs_new_connection;

      # If the channel is not NULL, save the shell handler type,
      # ensure the channel gets closed, re-open the connection if
      # necessary, and try to set the shell handler to the same type
      if (!isnull(channel))
      {
        # Save the shell handler info
        sh_type = typeof(channel.shell_handler);
        sh_type_ex = typeof_ex(channel.shell_handler);
        sh_sets = channel.shell_handler.settings;
        needs_new_connection = channel.shell_handler.new_channel_needs_new_connection;
        # Close the unusable channel
        if (channel.state != CHANNEL_STATE_CLOSED)
        {
          dbg_log(fn:fn, level:DEBUG3, message:
            'Closing unusable channel.');
          channel.close();
        }
      }

      # Some devices require a new connection for every new channel
      # A new connection may also be required after 10 channels
      # have been opened in the same session
      if(
        needs_new_connection ||
        this.channel_manager.next_id >= 10
      )
      {
        dbg_log(fn:fn, level:DEBUG3, message:'The shell handler ' +
          'needs a new connection. Creating new connection.');
        this.close_connection();
        if(!this.open_connection(port:port)) return FALSE;
        if(!this.login()) return FALSE;
      }

      # Try to replace channel with the same type of shell handler
      if(!isnull(channel))
      {
        if (sh_type == "object")
        {
          dbg_log(fn:fn, level:DEBUG3, message:'Setting shell ' +
            'handler for new channel to same type: "' + sh_type_ex +
            '"');
          sh = new(sh_type_ex);
        }
      }

      # If channel was NULL or a shell handler was not created,
      # default to KB shell handler
      if (!sh) sh = get_kb_shell_handler();

      # Set the sh settings before opening channel in case there
      # are dynamically set pty-opts
      if (sh_sets) sh.init(settings:sh_sets);

      # Open new channel
      dbg_log(fn:fn, level:DEBUG3, message:
          'Opening new channel.');
      var newchan = this.open_shell(shell_handler:sh);
      if(!newchan)
      {
        set_error(fn + "Failed to open shell.");
        return FALSE;
      }

      if (isnull(channel))
        this.channel_manager.set_default_channel(newchan);
      this.channel_manager.replace_channel(old_chan:channel,
                                           new_chan:newchan);
      channel = newchan;
      return TRUE;
    }

    ##
    # Executes a local command on the target host over the open SSH connection
    # using a shell handler.
    #
    # @param <channel> A channel object for the current SSH connection
    # @param <command> The command to be executed
    # @param <force_priv_escl> A boolean which if true will force an attempt to
    #                          escalate privileges before running the command.
    # @param <cmd_timeout_min> The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param <inactivity_timeout_min> The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    # @return Returns the target host's response to running the command as a string, or
    #         NULL if the command fails.
    # @category SSH
    ##
    public function run_shell_command(&channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = 'session.run_shell_command';
      reset_cmd_interrupted();

      dbg_log(fn:fn, level:DEBUG3, message:'Command to run: "'+command+'"');
      if (isnull(channel))
        channel = this.channel_manager.get_default_channel();

      # Check channel and replace if necessary; replace_shell() will
      # set applicable error if it fails
      if (
        !channel_usable_for_shell_command(channel:channel, nosetup_ok:TRUE) &&
        !this.replace_shell(channel:channel)
      )
        return set_error('Did not run command due to session error.' +
          '\nCommand : ' + command + '\nSession error : "' + last_error + '"');

      if(isnull(channel.shell_handler) && isnull(nosetup_shell_handler))
      {
        return set_error("No shell handler setup, run open_shell() before run_shell_command()");
      }

      clear_cmd_error();
      local_var cmd_result = NULL;
      if(!isnull(nosetup_shell_handler))
      {
        cmd_result = nosetup_shell_handler(
            session                : this,
            command                : command,
            force_priv_escl        : force_priv_escl,
            cmd_timeout_min        : cmd_timeout_min,
            inactivity_timeout_min : inactivity_timeout_min
          );
      }
      else
      {
        cmd_result = channel.shell_handler.run_command(
            channel                : channel,
            command                : command,
            force_priv_escl        : force_priv_escl,
            cmd_timeout_min        : cmd_timeout_min,
            inactivity_timeout_min : inactivity_timeout_min
          );
      }

      # Shell handlers have timed out and command error properties that can determine if the
      # command was interrupted.
      cmd_interrupted = channel.shell_handler.timed_out || channel.shell_handler.last_cmd_error;
      if(cmd_interrupted)
      {
        # record error for logging

        # will not be recoreded to ssh_commands.log in this case but including for log verbosity.
        set_cmd_error("Command did not complete due to timeout or other error.");

        dbg_log(fn:fn, level:DEBUG3,
                message:'The command "' + command + '" did not complete due to timeout or error.');
      }
      return cmd_result;
    }

    ##
    # Closes the SSH connection and frees the objects associated with it.
    #
    # @category SSH
    ##
    public function close_connection()
    {
      if(cur_state.val != "SOC_CLOSED")
        close_socket();
      else dbg_log(fn:'session.close_connection', level:DEBUG3,
        message:"Socket is already closed.");

      return NULL;
    }

    ##
    # Creates and returns a new SFTP session object
    #
    # @return A newly created SFTP session object initialized with this sessions's channel.
    # @category SSH
    ##
    public function get_sftp_session()
    {
      var channel = get_channel();
      if(!channel)
        return set_error("Error - unable to get a channel for SSH server on port " + port + ".");
      var sftp_session = new("sshlib::sftp_session", channel);
      return sftp_session;
    }

    ##
    # Determines whether or not the shell handler needs to check the default login
    # shell of the provided user.
    #
    # @param The shell handler object to check
    # @return TRUE if the defaul shell check is required
    # @category SSH
    ##
    public function need_shell_check(shell_handler)
    {
      var fn = this.objname + FUNCTION_NAME;
      var default_shell;
      default_shell = get_kb_item(SSH_LIB_KB_PREFIX + get_kb_connection_id() + '/default_shell');

      if(typeof_ex(shell_handler) == 'sshlib::sh_shell_handler')
      {
        if(isnull(default_shell))
        {
          dbg_log(
              fn:fn,
              level:DEBUG3,
              message:'Opening sh shell handler; default shell is NULL, shell check is required.');
          return TRUE;
        }
        else if(default_shell == 'ksh' && !shell_handler.ksh_default)
        {
          dbg_log(
              fn:fn,
              level:DEBUG3,
              message:'Opening sh shell handler; default shell is ksh, calling shell_handler.set_ksh_default()');
          shell_handler.set_ksh_default();
        }
        else
        {
          dbg_log(
              fn:fn,
              level:DEBUG3,
              message:'Opening sh shell handler; default shell is '+default_shell+', calling shell check is not required.');
        }
      }

      return FALSE;
    }

    ##
    # Opens a shell or tty on the open SSH connection by acquiring a channel and then making
    # the appropriate request depending on the shell handler.
    #
    # @param <shell_handler> A shell handler object
    # @param <skip_check_shell> A boolean flag to skip the "need_shell_check" logic. Used
    #                           when running "raw" commands via sh shell handler. (optional)
    # @return A channel object with an open request for a shell or tty on the target host.
    #         If the shell handler argument is for a no setup shell the function will return
    #         a string "nosetup" (using global var NOSETUP).  NULL is returned if an error occurs.
    # @category SSH
    ##
    # returns channel
    public function open_shell(shell_handler, skip_check_shell, reconnect_retry_on_fail)
    {
      var fn = this.objname + FUNCTION_NAME;
      var extra = '';
      var opt, opts;
      var check_shell = FALSE;

      if(cur_state.val == "SOC_CLOSED")
        return set_error("Unable to open shell on closed socket.");

      if(isnull(shell_handler))
      {
        this.close_connection();
        exit(1, "Need shell_handler for open_shell().");
      }

      if(shell_handler.is_nosetup())
      {
        this.nosetup_shell_handler = shell_handler.run_command_func;
        dbg_log(
            fn:fn,
            level:DEBUG3,
            message:'The ' +typeof_ex(shell_handler)+' shell handler is a nosetup shell.');
        return NOSETUP;
      }

      # Determine the need_shell_check before sending pty-req
      # so that the pty-opts in the shell handler will be
      # set appropriately in the shell handler object
      if(!skip_check_shell) check_shell = need_shell_check(shell_handler:shell_handler);

      var channel = get_channel();

      if(!channel && reconnect_retry_on_fail)
      {
        dbg_log(fn:fn, level:DEBUG3, message:'The shell handler ' +
          'needs a new connection. Creating new connection.');
        close_connection();
        if(!open_connection(port:port)) return NULL;
        if(!login()) return NULL;
        channel = get_channel();
      }

      if (!channel)
        return set_error("Failed to get channel.");

      channel.set_shell_handler(shell_handler);

      if(shell_handler.send_pty_req())
      {
        extra = mk_ssh_string(shell_handler.get_pty_term());

        var size_chars = shell_handler.get_pty_size_chars();
        var size_pixels = shell_handler.get_pty_size_pixels();
        extra += mkdword(size_chars[0], order:BYTE_ORDER_BIG_ENDIAN) +
          mkdword(size_chars[1], order:BYTE_ORDER_BIG_ENDIAN);
        extra += mkdword(size_pixels[0], order:BYTE_ORDER_BIG_ENDIAN) +
          mkdword(size_pixels[1], order:BYTE_ORDER_BIG_ENDIAN);

        opts = shell_handler.get_pty_opts();

        var opt_str = '';
        foreach opt (keys(opts))
          opt_str += mkbyte(opt) + mkdword(opts[opt], order:BYTE_ORDER_BIG_ENDIAN);

        opt_str += mkbyte(PTY_OPT_TTY_OP_END);

        extra += mk_ssh_string(opt_str);

        channel.make_request(type:"pty-req", want_reply:FALSE, extra:extra);
      }

      channel.make_request(type:"shell", want_reply:FALSE);

      if(check_shell)
      {
        dbg_log(
            fn:fn,
            level:DEBUG3,
            message:'Calling shell_handler.is_echo_required() to determine default shell.');
        shell_handler.is_echo_required(channel:channel, session:this);
      }

      return channel;
    }

    ##
    # Removes saved login data from the KB.  This is called when "none" auth succeeds but the library
    # is being used with compatibility wrappers for example.  In that case, "none" auth is bypassed.
    # This function clears the KB to make way for further authentication attempts.
    #
    # @category SSH
    ##
    public function clear_saved_login_info()
    {
      var extra, key;
      rm_kb_item(name:SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_method");
      extra = get_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_extra");
      foreach key (keys(extra))
        rm_kb_item(name:"Secret/" + SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_extra/" + key);

      return NULL;
    }


    ##
    # Stores information about a successful authentication.  If the 'save_login' flag is set to TRUE, the
    # function will store the login method and supporting data in the KB.
    #
    # @param <method> The authentication method: "none", "password", "keyboard-interactive", "gssapi", or "publickey"
    # @param <extra> A dictionary of data supporting the authentication method such as credentials, keys, etc.
    # @param <save_login> A flag telling the function whether or not to sae the login information in the KB.
    # @return TRUE
    # @category SSH
    ##
    private function save_login_info(method, extra, save_login)
    {
      login_method = method;
      if(save_login)
      {
        save_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_extra", args:extra);
        if(isnull(get_kb_item(SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_method")))
          set_kb_item(name:SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_method", value:method);
      }
      return TRUE;
    }


    ##
    # Stores information about a successful escalation of privileges in the KB.
    #
    # @param <type> The escalation method: "su", "sudo", "su+sudo", "pbrun", "dzdo", or "cisco_enable"
    # @param <args> A dictionary of data supporting the escalation method such as credentials, high privilege user, etc.
    # @category SSH
    ##
    public function save_escalation_info(type, args)
    {
      save_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/escalation_extra", args:args);
      if(isnull(get_kb_item(SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/escalation_type")))
        set_kb_item(name:SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/escalation_type", value:type);

      return NULL;
    }

    ##
    # Loops receiving and processing messages from the remote SSH server until KEX is complete
    # or an error occurs.
    #
    # @return TRUE if the session is already past KEX or KEX completes, FALSE on error.
    # @category SSH
    ##
    public function complete_kex()
    {
      var fn = 'session.complete_kex';
      if(!cur_state.oneof(state_list:make_list("SOC_OPENED", "KEX_BEGIN")))
        return TRUE;

      dbg_log(fn:fn, level:DEBUG3, message:"KEX is not yet complete. Attempting to complete KEX before continuing.");
      sshrecv_until(end_states:make_list("KEX_DONE", "SOC_CLOSED"));
      if(cur_state.val != "KEX_DONE")
      {
        if(cur_state.val != "SOC_CLOSED")
          return close_socket(error:"KEX failed: " + last_error);
        else return set_error("KEX failed: " + last_error);
      }

      return TRUE;
    }

    ##
    # Logs a user into the remote host using the supplied SSH authentication method and extra data. If no
    # authentication method is supplied, but data from a previous successful authentication was stored in
    # the KB the stored method and data will be used.
    #
    # @param <method> The authentication method: "none", "password", "keyboard-interactive", "gssapi", or "publickey"
    # @param <extra> A dictionary of data supporting the authentication method such as credentials, keys, etc.
    # @param <save_login> Boolean flag.  If TRUE the function will save login information
    #                     in KB as preferred login info if login is successful. Future logins
    #                     not using method/extra args will use this saved information.
    # @return Returns TRUE if the login succeeds, FALSE if it fails and NULL if an error occurs.
    # @category SSH
    ###
    public function login(method, extra, save_login, force_none_auth)
    {
      var ret_val;
      var fn = 'session.login';
      if(isnull(method))
      {
        method = get_kb_item(SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_method");
        if(isnull(method))
          return set_error("No login method specified.");

        extra = get_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/login_extra");
      }

      var payload;
      if(cur_state.val == "SOC_CLOSED")
        return set_error("SSH socket closed, unable to log in.");

      # If the session has just been opened, wait for KEX to complete
      if(!complete_kex()) return NULL;

      if(!auth_method_supported(method:method, username:extra["username"]))
        return set_error("Remote server does not support the '"+method+"' authentication method for user '"+extra["username"]+"'. It supports : "+join(supported_auth_methods,sep:",")+".");

      if(method != "none" && cur_state.val != "USERAUTH_FAILURE" && cur_state.val != "USERAUTH_INFO_REQ")
      {
        sshsend(code:PROTO_SSH_MSG_SERVICE_REQUEST, data:mk_ssh_string("ssh-userauth"));
        sshrecv_until(end_states:make_list("SERVICE_REQUEST_SUCCESS", "SOC_CLOSED"));
        if(cur_state.val != "SERVICE_REQUEST_SUCCESS")
          return set_error("Did not receive SERVICE_ACCEPT for ssh-userauth authentication.");
      }

      if(method == "password")
      {
        if(!isnull(extra["password"]))
          password = extra["password"];
        if(!isnull(extra["username"]))
          user = extra["username"];

        dbg_log(fn:fn, level:DEBUG1, message:'Trying password authentication...\n');

        redact = TRUE;
        payload =
          mk_ssh_string(user) +
          mk_ssh_string("ssh-connection") +
          mk_ssh_string("password") +
          mkbyte(0) +
          mk_ssh_string(password);
        sshsend(data:payload, code:PROTO_SSH_MSG_USERAUTH_REQUEST);
        redact = FALSE;
        cur_state.set("USERAUTH_REQUEST");

        sshrecv_until(end_states:make_list("USERAUTH_SUCCESS", "USERAUTH_FAILURE", "SOC_CLOSED"));

        if(cur_state.val == "USERAUTH_SUCCESS")
          return save_login_info(method:method, extra:extra, save_login:save_login);
        set_auth_failure_error(user:user, port:this.port, msg:"Failed to authenticate using the supplied password.");
        return FALSE;
      }
      else if(method == "keyboard-interactive")
      {
        var custom_prompt;

        if(!isnull(extra["password"]))
          password = extra["password"];
        if(!isnull(extra["username"]))
          user = extra["username"];
        if(!isnull(extra["custom_prompt"]))
          custom_prompt = extra["custom_prompt"];
        if(!isnull(extra["cb"]))
          interactive_login_cb = extra["cb"];
        else interactive_login_cb = @default_interactive_login_cb;

        dbg_log(fn:fn, level:DEBUG1, message:'Trying keyboard-interactive authentication...\n');

        ret_val = interactive_login_cb(session:this, username:user, password:password, custom_prompt:custom_prompt);

        if(ret_val)
          return save_login_info(method:method, extra:extra, save_login:save_login);
        else return ret_val;
      }
      else if(method == "gssapi")
      {
        if(!isnull(extra["password"]))
          password = extra["password"];
        if(!isnull(extra["username"]))
          user = extra["username"];
        if(!isnull(extra["realm"]))
          realm = extra["realm"];
        if(!isnull(extra["host"]))
          kerb_host = extra["host"];
        else
          kerb_host = this.remote_host;

        dbg_log(fn:fn, level:DEBUG1, message:'Trying gssapi-with-mic authentication...\n');

        ret_val = gssapi_login(user:user, password:password, realm:realm, kerb_host:kerb_host);
        if(ret_val) return save_login_info(method:method, extra:extra, save_login:save_login);
        return ret_val;
      }
      else if (method == "publickey")
      {
        dbg_log(fn:fn, level:DEBUG1, message:'Trying publickey authentication...\n');
        ret_val = publickey_login(auth_info:extra);
        if(ret_val) return save_login_info(method:method, extra:extra, save_login:save_login);
        return ret_val;
      }
      else if (method == "none")
      {
        if(!isnull(extra["username"]))
          user = extra["username"];

        # If state is already USERAUTH_SUCCESS and supported_auth_methods contains
        # the single entry "none", then we already know the "none" method is supported
        if(cur_state.val == "USERAUTH_SUCCESS" && max_index(supported_auth_methods) == 1 && supported_auth_methods[0] == "none")
          return save_login_info(method:method, extra:extra, save_login:save_login);

        # If supported_auth_methods contains the single entry "unknown", then we
        # already know the "none" method is not supported
        if(max_index(supported_auth_methods) == 1 && supported_auth_methods[0] == "unknown")
           return FALSE;

        # Otherwise, get_supported_auth_methods() will try the "none" authentication
        # and populate the supported_auth_methods list
        get_supported_auth_methods(username:user, force:force_none_auth);
        if(cur_state.val == "USERAUTH_SUCCESS" && max_index(supported_auth_methods) == 1 && supported_auth_methods[0] == "none")
          return save_login_info(method:method, extra:extra, save_login:save_login);
        else
          return FALSE;
      }
    }

    ##
    # GSSAPI login handler.   This gets run right after ssh-userauth service request.
    #
    # @param <user> The user id
    # @param <password> The password
    # @param <realm> The Kerberos domain
    # @param <kerb_host> The KDC
    # @return Returns TRUE if the login succeeds, FALSE if it fails and NULL if an error occurs.
    # @category SSH
    ##
    function gssapi_login(user, password, realm, kerb_host)
    {
      var code, kerb_data, krb5, message, mic, oid, payload, seq;

      # OID for Kerberos v5
      krb5 = "1.2.840.113554.1.2.2";

      # Ask the server if it supports the specific authentication method
      # we're planning on attempting.
      payload =
        mk_ssh_string(user) +
        mk_ssh_string("ssh-connection") +
        mk_ssh_string("gssapi-with-mic") +
        mkdword(1, order:BYTE_ORDER_BIG_ENDIAN) +
        mk_ssh_string(der_encode_oid(oid:krb5));
      sshsend(code:PROTO_SSH_MSG_USERAUTH_REQUEST, data:payload);

      cur_state.set("USERAUTH_GSSAPI_REQUEST");
      sshrecv_until(end_states:make_list("USERAUTH_GSSAPI_RESPONSE", "USERAUTH_FAILURE", "SOC_CLOSED"));

      if(cur_state.val != "USERAUTH_GSSAPI_RESPONSE")
        return set_auth_failure_error(user:user, port:this.port, msg:"Did not receive SSH_MSG_USERAUTH_GSSAPI_RESPONSE for gssapi-with-mic authentication.");

      # Ensure the selected method matches the one we sent.
      oid = der_parse_oid(oid:get_ssh_string(buffer:this.last_packet.payload, pos:0));
      if (isnull(oid))
        return set_auth_failure_error(user:user, port:this.port, msg:"Server did not select a mechanism OID for gssapi-with-mic authentication.");
      else if (oid != krb5)
        return set_auth_failure_error(user:user, port:this.port, msg:"Server selected mechanism OID " + oid + " for gssapi-with-mic authentication.");

      # Send first authentication request
      seq = rand();
      kerb_data = kerberos_ssh(
        login    : user,
        password : password,
        realm    : realm,
        host     : kerb_host,
        seqnum   : seq
      );

      if (isnull(kerb_data))
        return set_auth_failure_error(user:user, port:this.port, msg:"Did not receive ticket from KDC for gssapi-with-mic authentication.");

      payload = mk_ssh_string(kerb_data[1]);
      sshsend(code:PROTO_SSH_MSG_USERAUTH_GSSAPI_TOKEN, data:payload);

      sshrecv_until(end_states:make_list("USERAUTH_GSSAPI_TOKEN", "SSH_MSG_USERAUTH_FAILURE", "SOC_CLOSED"));

      if(cur_state.val != "USERAUTH_GSSAPI_TOKEN")
        return set_auth_failure_error(user:user, port:this.port, msg:"Did not receive SSH_MSG_USERAUTH_GSSAPI_TOKEN for gssapi-with-mic authentication.");

      # Parse ticket from server's response.
      if (! check_gssapi_token(
              data      : get_ssh_string(buffer:this.last_packet.payload, pos:0),
              key       : kerb_data[0],
              realm     : realm,
              principal : user
            )
      )
        return set_auth_failure_error(user:user, port:this.port, msg:"Checking GSSAPI token failed.");

      # Send second authentication request.
      message =
        mk_ssh_string(this.kex_handler.id) +
        raw_string(0x32) +
        mk_ssh_string(user) +
        mk_ssh_string("ssh-connection") +
        mk_ssh_string("gssapi-with-mic");
      mic = gssapi_ssh_get_mic(data:message, key:kerb_data[0], seqnum:seq, enc_type:kerb_data[2]);
      payload = mk_ssh_string(mic);
      sshsend(code:PROTO_SSH_MSG_USERAUTH_GSSAPI_MIC, data:payload);

      sshrecv_until(end_states:make_list("USERAUTH_SUCCESS", "USERAUTH_FAILURE", "SOC_CLOSED"));

      if(cur_state.val == "USERAUTH_SUCCESS")
        return TRUE;

      set_auth_failure_error(user:user, port:this.port, msg:"GSSAPI authentication failed : credentials not accepted.");
      return FALSE;
    }

    ##
    # The public key authentication handler.
    #
    # @param <auth_info> Dictionary of data required for public key authentication; user id,
    #                    private key, passphrase, certificate
    # @return Returns TRUE if the login succeeds, FALSE if it fails and NULL if an error occurs.
    # @category SSH
    ##
    private function publickey_login(auth_info)
    {
      local_var key, payload, hash, signature;
      local_var fn = 'session.publickey_login';

      if (!auth_info.privatekey || !auth_info.username)
        return set_auth_failure_error(user:NULL, port:this.port, msg:"Missing publickey authentication arguments.");
      else
        user = auth_info.username;

      # Check for private key format RSA1, which is only supported by SSHv1
      # This library only supports SSHv2
      if ('SSH PRIVATE KEY FILE FORMAT 1.1\n\0' >< auth_info.privatekey)
        return set_auth_failure_error(user:user, port:this.port, msg:"The private key type is RSA1, which is only supported by SSHv1. This library only supports SSHv2.");

      dbg_log(fn:fn, level:DEBUG1, message:'Attempting to parse ssh keys...\n');

      key = parse_ssh_keys(
        privatekey:auth_info.privatekey,
        passphrase:auth_info.passphrase,
        cert:auth_info.cert
      );

      if (!key) return set_auth_failure_error(user:user, port:this.port, msg:"Failed to parse ssh keys.");

      # Build base of payload
      payload =
        mk_ssh_string(user) +
        mk_ssh_string("ssh-connection") +
        mk_ssh_string("publickey") +
        mkbyte(1) +
        mk_ssh_string(key.type) +
        mk_ssh_string(key.pub);

      var to_hash = mk_ssh_string(this.kex_handler.id) +
                    mkbyte(PROTO_SSH_MSG_USERAUTH_REQUEST) +
                    payload;

      if(key.type !~ '^ecdsa')
      {
        hash = SHA1(to_hash);

        # Obtain signature
        if ("ssh-rsa" >< key.type || "sign-rsa" >< key.type)
        {
          signature = rsa_sign(
            e : key.e,
            n : key.n,
            d : key.priv,
            data : hash
          );
        }
        else if ("ssh-dss" >< key.type)
        {
          signature = dsa_do_sign(
            p    : key.p,
            q    : key.q,
            g    : key.g,
            pub  : key.y,
            priv : key.priv,
            data : hash
          );
        }
        else return set_auth_failure_error(user:user, port:this.port, msg:"Invalid key type. Could not create signature with given information.");

        if (!signature) return set_auth_failure_error(user:user, port:this.port, msg:"Failed to create signature.");

        # Finalize payload
        signature = mk_ssh_string(key.alg) + mk_ssh_string(signature);
        payload += mk_ssh_string(signature);
      }
      else
      {
        if(key.alg == "ecdsa-sha2-nistp256")
          hash = SHA256(to_hash);
        else if(key.alg == "ecdsa-sha2-nistp384")
          hash = SHA384(to_hash);
        else if(key.alg == "ecdsa-sha2-nistp521")
          hash = SHA512(to_hash);
        else
          return set_auth_failure_error(user:user, port:this.port, msg:"Unknown ECDSA key algorithm: " + key.type);

        signature = ecdsa_sign(
            priv   : key.priv,
            nid    : key.nid,
            digest : hash
        );

        if(isnull(signature))
          return set_auth_failure_error(user:user, port:this.port, msg:"Failed to compute ECDSA signature.");

        payload += mk_ssh_string(mk_ssh_string(key.alg) + mk_ssh_string(signature));
      }

      dbg_log(fn:fn, level:DEBUG2, message:'Sending publickey authentication payload...\n');
      sshsend(data:payload, code:PROTO_SSH_MSG_USERAUTH_REQUEST);
      cur_state.set("USERAUTH_REQUEST");

      sshrecv_until(end_states:make_list("USERAUTH_SUCCESS", "USERAUTH_FAILURE", "SOC_CLOSED"));

      if(cur_state.val == "USERAUTH_SUCCESS")
        return TRUE;

      set_auth_failure_error(user:user, port:this.port, msg:"Failed to authenticate using publickey authentication.");
      return FALSE;
    }


    ##
    # Parses an SSH key and returns the key cryptographic parameters.
    #
    # @param <privatekey> The private key
    # @param <passphrase> Passphrase for passphrase protected keys
    # @param <cert> An optional digital certificate for public key parameters
    # @return Returns crytographic parameters for the supplied private key or NULL if an error happens.
    # @category SSH
    ##
    private function parse_ssh_keys(privatekey, passphrase, cert)
    {
      local_var rsa_key, dsa_key, ecdsa_key;
      local_var key = {};

      if (isnull(cert))
      {
        rsa_key = pem_to_rsa2(priv:privatekey, passphrase:passphrase);
        if (!isnull(rsa_key))
        {
          key.e = normalize_mpint(rsa_key.e);
          key.n = normalize_mpint(rsa_key.n);
          key.priv = rsa_key.d;
          key.type = "ssh-rsa";
          key.alg = "ssh-rsa";
          key.pub =
            mk_ssh_string('ssh-rsa') +
            mk_ssh_mpint(key.e) +
            mk_ssh_mpint(key.n);
        }
        else
        {
          dsa_key = pem_to_dsa2(priv:privatekey, passphrase:passphrase);
          if (!isnull(dsa_key))
          {
            key.p = normalize_mpint(dsa_key.p);
            key.q = normalize_mpint(dsa_key.q);
            key.g = normalize_mpint(dsa_key.g);
            key.y = normalize_mpint(dsa_key.pub_key);
            key.priv = dsa_key.priv_key;
            key.type = "ssh-dss";
            key.alg = "ssh-dss";
            key.pub =
              mk_ssh_string("ssh-dss") +
              mk_ssh_mpint(key.p) +
              mk_ssh_mpint(key.q) +
              mk_ssh_mpint(key.g) +
              mk_ssh_mpint(key.y);
          }
          else
          {
            key = pem_to_ecdsa(priv:privatekey, passphrase:passphrase, session:this);
            if (empty_or_null(key))
              return set_auth_failure_error(user:user, port:this.port, msg:"Failed to parse the given key information.");
          }
        }
      }
      else
      {
        key = parse_public_key_only(pub:cert);

        if (isnull(key)) return set_auth_failure_error(user:user, port:this.port, msg:"Failed to parse the given certificate information.");

        if ("ssh-rsa" >< key.type) key.priv = pem_to_rsa(priv:privatekey, passphrase:passphrase);
        else if ("ssh-dss" >< key.type) key.priv = pem_to_dsa(priv:privatekey, passphrase:passphrase);
        else if ("ecdsa" >< key.type)
        {
          var priv_params = pem_to_ecdsa(priv:privatekey, passphrase:passphrase, session: this);
          key.priv = priv_params.priv;
          key.nid = priv_params.nid;
        }

        if("sign-rsa" >< key.type)
        {
          var tmp_rsa_key = pem_to_rsa2(priv:privatekey, passphrase:passphrase);
          key.e = tmp_rsa_key["e"];
          key.n = tmp_rsa_key["n"];
          key.priv = tmp_rsa_key["d"];
        }
      }

      if (!key.priv) return set_auth_failure_error(user:user, port:this.port, msg:"Failed to get private key information.");

      return key;
    }

    ##
    # Parses a public key or certificate and returns the associated cryptographic parameters
    #
    # @param <pub> A public key or certificate
    # @return A dictionary of the key parameters or NULL if an error happens.
    # @category SSH
    ##
    public function parse_public_key_only(pub)
    {
      local_var blob, errmsg, line, lines, next, nonce, tmp;
      local_var key = {};

      # SSH Public Key File Format
      if ("---" >< pub)
      {
        blob = '';
        lines = split(pub, sep:'\n');

        foreach line (lines)
        {
          if ("---" >< line || ':' >< line) continue;
          if ('\r' >< line) line -= '\r';

          blob += line;
        }
      }
      # OpenSSH Public Key File Format
      else
      {
        blob = ereg_replace(pattern:"[^ ]* ([^ ]*)( .*)?$", string:chomp(pub), replace:"\1");
      }

      # Convert to workable encoding
      if (strlen(blob)) blob = base64_decode(str:blob);
      if (strlen(blob) == 0) return set_auth_failure_error(user:user, port:this.port, msg:"Failed to parse the given certificate.");

      # Start adding key data
      key.pub = blob;

      if(pub =~ "^x509v3-sign-rsa")
        key.type = "x509v3-sign-rsa";
      else
      {
        key.type = get_ssh_string(buffer:blob, pos:0);
        next = 4 + strlen(key.type);
      }

      # Skip nonce field
      # if v00, not necessary, the nonce is after relevant data
      # if v01, nonce immediately follows the key type
      if (
        key.type !~ "-cert-v00@openssh.com$" &&
        (
          key.type == 'ssh-rsa-cert-v01@openssh.com' ||
          key.type == 'ssh-dss-cert-v01@openssh.com' ||
          key.type == 'ecdsa-sha2-nistp256-cert-v01@openssh.com' ||
          key.type == 'ecdsa-sha2-nistp384-cert-v01@openssh.com' ||
          key.type == 'ecdsa-sha2-nistp521-cert-v01@openssh.com' ||
          key.type == 'ssh-ed25519-cert-v01@openssh.com'
        )
      )
      {
        nonce = get_ssh_string(buffer:blob, pos:next);
        next += 4 + strlen(nonce);
      }
      # Set remaining key data
      if ("ssh-rsa" >< key.type)
      {
        key.alg = "ssh-rsa";

        tmp = get_ssh_mpint(buffer:blob, pos:next);
        if(isnull(tmp))
        {
          return set_error('Could not get ssh-rsa key e value.');
        }
        key.e = tmp['value'];
        next += int(tmp['length']);

        tmp = get_ssh_mpint(buffer:blob, pos:next);
        if(isnull(tmp))
        {
          return set_error('Could not get ssh-rsa key n value.');
        }
        key.n = tmp['value'];
        next += int(tmp['length']);
      }
      else if ("ssh-dss" >< key.type)
      {
        key.alg = "ssh-dss";

        tmp = get_ssh_mpint(buffer:blob, pos:next);
        if(isnull(tmp))
        {
          return set_error('Could not get ssh-dss key p value.');
        }
        key.p = tmp['value'];
        next += int(tmp['length']);

        tmp = get_ssh_mpint(buffer:blob, pos:next);
        if(isnull(tmp))
        {
          return set_error('Could not get ssh-dss key q value.');
        }
        key.q = tmp['value'];
        next += int(tmp['length']);

        tmp = get_ssh_mpint(buffer:blob, pos:next);
        if(isnull(tmp))
        {
          return set_error('Could not get ssh-dss key g value.');
        }
        key.g = tmp['value'];
        next += int(tmp['length']);

        tmp = get_ssh_mpint(buffer:blob, pos:next);
        if(isnull(tmp))
        {
          return set_error('Could not get ssh-dss key g value.');
        }
        key.y = tmp['value'];
      }
      else if("x509v3-sign-rsa" >< key.type)
      {
        key.alg = "x509v3-sign-rsa";
      }
      else if("ecdsa" >< key.type)
      {
        key.alg = ereg_replace(string:key.type, pattern: "(ecdsa-.*)-cert-.*@openssh.com", replace: "\1");
      }
      else
      {
        errmsg = "Invalid or unsupported certificate";
        if (key.type =~ "^[A-Za-z0-9-@.]+$")
          errmsg += " with a key type of " + key.type;
        return set_auth_failure_error(user:user, port:this.port, msg:errmsg + '.');
      }

      return key;
    }

    ##
    # Retrieves a list of supported authentication methods from the remote server.
    # Works by first requesting the authentication service with a SSH_MSG_SERVICE_REQUEST.
    # If the request succeeds the function will attempt a "none" authentication
    # for the supplied user (may also try without a user if none was supplied).  The
    # supported authentication methods are returned in the response message whether
    # or not 'none' auth succeeds.
    #
    # @param <username> The user name
    # @return Returns TRUE if the function succeeds or NULL if there was an error.
    # @category SSH
    ##
    public function get_supported_auth_methods(username, force)
    {
      local_var payload, supported_auth, user_supported_auth_methods;
      var fn = 'session.get_supported_auth_methods';

      dbg_log(fn:fn, level:DEBUG3, message:"Entering get_supported_auth_methods()");

      # If a username wasn't passed, try to set it using the 'user'
      # global var that may have already been set
      # If 'user' is still empty, the server will still return a
      # list of supported auth methods, but subsequent login attempts
      # in the same session will fail if the username is different
      # than what is set here
      if(!username)
      {
        dbg_log(fn:fn, level:DEBUG3, message:'get_supported_auth_methods: No username passed, using username "'+user+'".');
        username = user;
      }

      # If we already have the list of supported_auth_methods, return
      user_supported_auth_methods = get_kb_item(SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/"+username+"/supported_login_methods");
      if(!isnull(user_supported_auth_methods) && !force)
      {
        supported_auth_methods = split(user_supported_auth_methods, sep:",", keep:FALSE);
        dbg_log(fn:fn, level:DEBUG3, message:'get_supported_auth_methods: This function has already run and set the supported_auth_methods for user "'+username+'" : '+serialize(supported_auth_methods));
        return TRUE;
      }

      if(cur_state.val == "SOC_CLOSED")
        return set_error("SSH socket closed, unable to log in.");

      # If the session has just been opened, wait for KEX to complete
      if(!complete_kex()) return NULL;

      # Request ssh-userauth service
      sshsend(code:PROTO_SSH_MSG_SERVICE_REQUEST, data:mk_ssh_string("ssh-userauth"));

      sshrecv_until(end_states:make_list("SERVICE_REQUEST_SUCCESS", "SOC_CLOSED"));

      if(cur_state.val != "SERVICE_REQUEST_SUCCESS")
        return set_error("Did not receive SERVICE_REQUEST_SUCCESS for ssh-userauth service request.");

      # Request 'none' authentication method
      payload =
        mk_ssh_string(username) +
        mk_ssh_string("ssh-connection") +
        mk_ssh_string("none");
      sshsend(code:PROTO_SSH_MSG_USERAUTH_REQUEST, data:payload);
      cur_state.set("USERAUTH_REQUEST");

      sshrecv_until(end_states:make_list("USERAUTH_SUCCESS", "USERAUTH_FAILURE", "SOC_CLOSED"));

      # If the 'none' authentication method was accepted, we expect
      # SSH_MSG_USERAUTH_SUCCESS
      # The server sends only the code with no list of authentications
      # that can continue
      if(cur_state.val == "USERAUTH_SUCCESS")
      {
        supported_auth = get_ssh_string(buffer:last_packet.payload, pos:0);
        if (isnull(supported_auth))
        {
          supported_auth_methods[0] = "none";
          replace_kb_item(name:SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/"+username+"/supported_login_methods", value:"none");
          return TRUE;
        }
        else
          return set_error("Server accepted the 'none' authentication method but there was an unexpected value for authentications that can continue: " + supported_auth);
      }

      # Unexpected code; we expect either SSH_MSG_USERAUTH_SUCCESS or
      # SSH_MSG_USERAUTH_FAILURE
      if(cur_state.val != "USERAUTH_FAILURE")
        return set_error("Server did not accept or reject the 'none' authentication method. Received code was : " + last_packet.type + ".");

      # If we got this far, the 'none' authentication method was
      # rejected with SSH_MSG_USERAUTH_FAILURE
      # The server MAY have included a list of supported auth methods
      # that can continue in the response
      supported_auth = get_ssh_string(buffer:last_packet.payload, pos:0);
      if(empty_or_null(supported_auth))
      {
        supported_auth_methods[0] = "unknown";
        replace_kb_item(name:SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/"+username+"/supported_login_methods", value:"unknown");
        return set_error("Server rejected the 'none' authentication method but did not provide a list of authentications that can continue.");
      }

      # Split the list of auth methods and store in the supported_auth_methods list
      # The empty_or_null() check above should ensure there is at least one list item,
      # so the else here is just a failsafe
      supported_auth_methods = split(supported_auth, sep:',', keep:FALSE);
      if(max_index(supported_auth_methods) > 0)
      {
        replace_kb_item(name:SSH_LIB_KB_PREFIX + get_kb_connection_id() + "/"+username+"/supported_login_methods", value:supported_auth);
        dbg_log(fn:fn, level:DEBUG3, message:'get_supported_auth_methods: Server returned supported auth methods for user "'+username+'" : '+serialize(supported_auth_methods));
        return TRUE;
      }
      else
        return set_error("Unable to parse authentication methods from authentications that can continue: " + supported_auth);
    }


    ##
    # Wraps get_supported_auth_methods and returns whether a given authentication method
    # is supported for a given user on the remote system.
    #
    # @param <method> The authentication method: "none", "password", "keyboard-interactive", "gssapi", or "publickey"
    # @param <username> User id
    # @return Returns TRUE if the authentication method is supported, FALSE if it isn't.
    # @category SSH
    ##
    public function auth_method_supported(method, username)
    {
      local_var supported_auth_method;
      var fn = 'session.auth_method_supported';

      # This will set global supported_auth_methods to the values for the
      # specified user
      if(!get_supported_auth_methods(username:username) || supported_auth_methods[0] == "unknown" || supported_auth_methods[0] == "none")
      {
        dbg_log(fn:fn, level:DEBUG1, message:'Unable to determine supported authentication methods.');
        return TRUE;
      }

      foreach supported_auth_method (supported_auth_methods)
      {
        if (method >< supported_auth_method)
        {
          dbg_log(fn:fn, level:DEBUG3, message:'auth_method_supported: The authentication method "'+method+'" is supported.');
          return TRUE;
        }
      }
      dbg_log(fn:fn, level:DEBUG1, message:'auth_method_supported: The authentication method "'+method+'" is not supported.');
      return FALSE;
    }


    ##
    # Handles an error on the current SSH socket by retrieving the error code,
    # crafting and logging a message for the error and closing the socket.
    #
    # @return Returns NOERR (a GizaNE built-in that equals 0) if there is no error, NULL otherwise.
    # @category SSH
    ##
    function handle_socket_error()
    {
      local_var socket_error, socket_error_message;
      local_var fn = 'session.handle_socket_error';

      if(cur_state.val == "SOC_CLOSED")
      {
        dbg_log(fn:fn, message:"Socket has already been closed.");
        return NULL;
      }

      if(TAP_MODE) socket_error = tap_mode_get_socket_error(socket);
      else socket_error = socket_get_error(socket);
      socket_error_message = "Socket error: ";

      switch(socket_error)
      {
        case NOERR:
          return NOERR;
          break;
        case ETIMEDOUT:
          return set_error("Connection timed out (probably ok)");
          break;
        case ECONNRESET:
          socket_error_message += "Connection reset by peer";
          break;
        case EUNREACH:
          socket_error_message += "Host or network unreachable";
          break;
        case ESSL:
          socket_error_message += "No such device";
          break;
        case EINPROGRESS:
          socket_error_message += "Operation in progress";
          break;
        case ECONNREFUSED:
          socket_error_message += "Connection refused";
          break;
        case ENOBUFS:
          socket_error_message += "No buffer space available";
          break;
        case EACCES:
          socket_error_message += "Permission denied";
          break;
        case EUNKNOWN:
        default:
          socket_error_message += "Unknown error";
          break;
      }

      dbg_log(fn:fn, message:socket_error_message);
      # Call close_socket() so that objects are properly cleaned up
      close_socket();
      return set_error(socket_error_message);
    }


    ##
    # Provides access to private functions for unit testing.
    #
    # @param <name> Name of a private function to call
    # @param <args> A dictionary of arguments names and values for the private function to test.
    # @return The return value of the private function being tested or NULL if an error happens.
    # @category SSH
    ##
    public function test_private_function(name, args)
    {
      var fn = 'test_private_function';

      if(empty_or_null(name))
      {
        dbg_log(fn:fn, message:"Missing 'name' argument");
        return NULL;
      }

      switch (name)
      {
        case "parse_ssh_keys":
          return parse_ssh_keys(
            privatekey : args['privatekey'],
            passphrase : args['passphrase'],
            cert       : args['cert']
          );
        default:
          dbg_log(fn:fn, message:"'name' argument '"+name+"' has not been implemented for testing with this function.");
          return NULL;
      }
    }

    ##
    # Sets the post login error
    #
    # @category SSH
    ##
    public function found_post_login_error()
    {
      post_login_error = TRUE;
      return NULL;
    }

    ##
    # Clears the post login error
    #
    # @category SSH
    ##
    public function clear_post_login_error()
    {
      post_login_error = FALSE;
      return NULL;
    }
  }

  ##
  # Determines whether the supplied public key will be accepted by the remote SSH server by
  # attempting to authenticate the supplied user using the key.  Used by the SSH compatibility
  # library for static/default keys testing.
  #
  # @param <login> User id
  # @param <pub> A public key to test
  # @param <session> Reference to an sshlib::session object
  # @return Returns TRUE if the server will accept the key, NULL otherwise.
  # @category SSH
  ##
  function ssh_public_key_accepted(login, pub, &session)
  {
    local_var payload;

    local_var key = session.parse_public_key_only(pub:pub);
    if(!key) return session.set_error("ssh_public_key_accepted: Unable to parse public key.");

    # If the session has just been opened, wait for KEX to complete
    if(!session.complete_kex()) return NULL;

    # Request service
    session.sshsend(code:PROTO_SSH_MSG_SERVICE_REQUEST, data:mk_ssh_string("ssh-userauth"));
    session.sshrecv_until(end_states:make_list("SERVICE_REQUEST_SUCCESS", "SOC_CLOSED"));
    if(session.cur_state.val != "SERVICE_REQUEST_SUCCESS")
      return session.set_error("Did not receive SERVICE_ACCEPT for ssh-userauth authentication.");

    # Create connection request with public key only
    payload =
      mk_ssh_string(login) +
      mk_ssh_string("ssh-connection") +
      mk_ssh_string("publickey") +
      mkbyte(0) +
      mk_ssh_string(key.type) +
      mk_ssh_string(key.pub);

    session.sshsend(code:PROTO_SSH_MSG_USERAUTH_REQUEST, data:payload);
    session.cur_state.set("USERAUTH_PK_REQUEST");
    session.sshrecv_until(end_states:make_list("SOC_CLOSED", "USERAUTH_INFO_REQ", "USERAUTH_FAILURE", "USERAUTH_PK_OK"));

    if (session.last_packet.type != PROTO_SSH_MSG_USERAUTH_PK_OK)
      return session.set_error("Server did not reply with SSH_MSG_USERAUTH_PK_OK.");
    else
      return TRUE;
  }


  ##
  # Default generic interactive login handler, designed to handle interactive
  # authentication that prompts for passwords on most devices.
  # This gets run right after ssh-userauth service request
  #
  # @param <session>  A sshlib::session object.
  # @param <username> The user id.
  # @param <password>  The password
  # @param <custom_prompt> A non-standard password prompt supplied by the credential. (optional)
  # @return Returns TRUE if login succeeds, FALSE if it fails and NULL if an error happens.
  # @category SSH
  ##
  function default_interactive_login_cb(session, username, password, custom_prompt)
  {
    var tmp, prompts, prompt, inst, max_requests, request_num;
    var fn = 'session.default_interactive_login_cb';

    max_requests = 5;

    tmp =
        mk_ssh_string(username) +
        mk_ssh_string("ssh-connection") +
        mk_ssh_string("keyboard-interactive") +
        mk_ssh_string("en-US") +
        mk_ssh_string("");

    session.sshsend(data:tmp, code:PROTO_SSH_MSG_USERAUTH_REQUEST);
    session.cur_state.set("USERAUTH_REQUEST");

    session.sshrecv_until(end_states:make_list("SOC_CLOSED", "USERAUTH_INFO_REQ", "USERAUTH_FAILURE", "USERAUTH_SUCCESS"));

    # If an empty password was provided and we received PROTO_SSH_MSG_USERAUTH_SUCCESS
    # without sending a password, return TRUE
    if (
      session.cur_state.val == "USERAUTH_SUCCESS" &&
      ((!isnull(password) && strlen(password) == 0) || isnull(password))
    )
      return TRUE;

    if (session.cur_state.val != "USERAUTH_INFO_REQ")
      return session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Server did not reply with SSH_MSG_USERAUTH_INFO_REQUEST during keyboard-interactive exchange.");

    for(request_num = 0; request_num < max_requests; request_num++)
    {
      session.dbg_log(
          fn:fn,
          level:DEBUG3,
          message:'Processing SSH_MSG_USERAUTH_INFO_REQUEST '+request_num+'/'+
          max_requests+' (max)');
      var pos = 0;

      # Skip over name.
      tmp = get_ssh_string(buffer:session.last_packet.payload, pos:pos);
      pos += 4 + strlen(tmp);

      # instruction
      inst = get_ssh_string(buffer:session.last_packet.payload, pos:pos);
      pos += 4 + strlen(inst);

      # Skip over language.
      tmp = get_ssh_string(buffer:session.last_packet.payload, pos:pos);
      pos += 4 + strlen(tmp);

      if(strlen(tmp))
        session.dbg_log(fn:fn, level:DEBUG1, message:'Keyboard-interactive server language: ' + tmp + '\n');

      # Parse number of prompts.
      prompts = getdword(blob:session.last_packet.payload, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
      pos += 4;

      session.dbg_log(fn:fn, level:DEBUG1, message:'Number of keyboard-interactive prompts: ' + prompts + '\n');

      if(prompts <= 0)
        return session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Remote server's keyboard-interactive method did not return any prompts.");

      var test_prompt;
      var test_prompts = make_list(
        # Strange prompts
        'Enter PASSCODE:',
        "Password for "+username+"@",
        'Enter password for '+username+':',
        'Please Enter Authentication Password',
        'Passcode:',
        # Language variants of "password:" we should add more here in the future
        # this is the most common
        'password:',
        'contrase'+'\xc3\xb1'+'a:', # Spanish UTF-8 for password
        'contrase'+'\x11'+'a:' # Spanish ISO-8859-1 for password
      );

      if(!isnull(custom_prompt))
      {
        session.dbg_log(fn:fn, level:DEBUG1, message:'Adding the custom value: "' +
                                             custom_prompt +
                                             '" to the list of recognized password prompts.\n');
        test_prompts = make_list(test_prompts, custom_prompt);
      }

      prompt = get_ssh_string(buffer:session.last_packet.payload, pos:pos);
      session.dbg_log(fn:fn, level:DEBUG2, message:'Keyboard-interactive login prompt: "' + prompt + '"\n');

      if(prompt =~ "\(?[yY]/[nN]\)?$")
      {
        session.sshsend(data:mk_ssh_string("y"), code:PROTO_SSH_MSG_USERAUTH_INFO_RESPONSE);
        session.cur_state.set("USERAUTH_INFO_RES");
        session.sshrecv_until(end_states:make_list("SOC_CLOSED", "USERAUTH_INFO_REQ", "USERAUTH_FAILURE", "USERAUTH_SUCCESS"));
        continue;
      }

      var found_password_prompt = FALSE;

      foreach test_prompt (test_prompts)
      {
        if(tolower(test_prompt) >< tolower(prompt))
        {
          found_password_prompt = TRUE;
          break;
        }
      }
      if(found_password_prompt) break;
    }




    if(!found_password_prompt && prompt == " " &&
        "'s password for keyboard-interactive method:" >< inst
    )
      found_password_prompt = TRUE;

    if(!found_password_prompt)
      return session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Did not find expected password prompt using keyboard-interactive authentication.");

    session.set_redact(TRUE);
    tmp = mkdword(1, order:BYTE_ORDER_BIG_ENDIAN) + mk_ssh_string(password);
    session.sshsend(data:tmp, code:PROTO_SSH_MSG_USERAUTH_INFO_RESPONSE);
    session.set_redact(FALSE);
    session.cur_state.set("USERAUTH_INFO_RES");

    session.sshrecv_until(end_states:make_list("SOC_CLOSED", "USERAUTH_INFO_REQ", "USERAUTH_SUCCESS", "USERAUTH_FAILURE"));

    if (session.cur_state.val != "USERAUTH_INFO_REQ")
    {
      if(session.cur_state.val == "USERAUTH_SUCCESS")
        return TRUE;

      if(session.cur_state.val == "USERAUTH_FAILURE")
      {
        session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Failed to authenticate with supplied password using keyboard-interactive authentication.");
        return FALSE;
      }

      if(!isnull(session.last_packet.type))
        tmp = ssh2_packet_type_labels[session.last_packet.type];
      else tmp = ssh2_packet_type_labels[-1];

      if(isnull(tmp)) tmp = session.last_packet.type;
        return session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Received unexpected response during interactive authentication [" + tmp + "]");
    }

    if (
      "Changing password for " >< session.last_packet.payload ||                    # HPUX
      "Password change requested" >< session.last_packet.payload ||                 # SuSE 10
      "Password changing requested" >< session.last_packet.payload ||               # SuSE 9
      "Your password has expired" >< session.last_packet.payload ||                 # Solaris
      "New Password" >< session.last_packet.payload ||                              # FreeBSD
      "You are required to change your password" >< session.last_packet.payload     # Gentoo
    )
    {
      return session.set_auth_failure_error(user:username, port:session.get_port(), msg:"The password for the user '" + username + "' must be changed.");
    }

    session.sshsend(data:mkdword(0, order:BYTE_ORDER_BIG_ENDIAN), code:PROTO_SSH_MSG_USERAUTH_INFO_RESPONSE);
    session.sshrecv_until(end_states:make_list("SOC_CLOSED", "USERAUTH_SUCCESS", "USERAUTH_FAILURE"));

    if(session.cur_state.val == "USERAUTH_SUCCESS")
      return TRUE;
    if(session.cur_state.val == "USERAUTH_FAILURE")
    {
      session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Failed to authenticate with supplied password using keyboard-interactive authentication.");
      return FALSE;
    }

    if(!isnull(session.last_packet.type))
      tmp = ssh2_packet_type_labels[session.last_packet.type];
    else tmp = ssh2_packet_type_labels[-1];

    if(isnull(tmp)) tmp = session.last_packet.type;
      return session.set_auth_failure_error(user:username, port:session.get_port(), msg:"Received unexpected response during interactive authentication [" + tmp + "]");
  }

  ##
  # Attempts to find a shell handler that will work with the target host.  Loops
  # over the supplied shell handler classes, instantiating the handler and running each
  # of the supplied checks against the host.  If a handler produces the expected result
  # for a given check then that becomes the shell handler for this connection.
  #
  # @param <host> Target host (optional) Only required if different
  #               from scan target
  # @param <port> SSH listening port on target host.
  # @param <shell_handlers> A list of strings each representing a shell handler object class.
  # @param <cmd_list> A list of lists of commands and callbacks for checking various host types.
  #                   cmd_list looks like this:
  #                   [
  #                      {'test_cmd': 'uname', 'test_cmd_regex': "^Linux\s", 'cmd_success_cb': @handle_linux_os},
  #                      {'test_cmd': 'uname', 'test_cmd_regex': "^Mac OS\s", 'cmd_success_cb': @handle_mac_os}
  #                   ]
  # @return Returns list (success [TRUE,FALSE], error_message)
  # @category SSH
  ##
  function try_ssh_shell_handlers(host, port, shell_handlers, cmd_list)
  {
    var cmd_set, tmp_session, tmp_channel, tmp_channel1, escl_type, escl_extra, res, tmp_sh, tmp_sh1;
    var i, j, shell_handler, tmp_cb, fn, kb_id, escl_failed, item, checks;
    var tmp_bad_escl_kb, escl_hexstr, err_msg;

    fn = 'try_ssh_shell_handlers';

    # Open connection and retrieve/set escalation information
    tmp_session = new("sshlib::session");
    if(!tmp_session.open_connection(host:host, port:port))
    {
      if(!empty_or_null(tmp_session.error))
        return make_list(FALSE, tmp_session.error);
      else return make_list(FALSE, "open_connection() failed.");
    }

    kb_id = tmp_session.get_kb_connection_id();

    escl_type = get_kb_item(SSH_LIB_KB_PREFIX + kb_id + "/escalation_type");

    if(!isnull(escl_type))
    {
      escl_extra = get_kb_args(kb_prefix:("Secret/" + SSH_LIB_KB_PREFIX + kb_id + "/escalation_extra"));
    }

    tmp_bad_escl_kb = "tmp/" + kb_id + "/ssh_bad_priv_escl/" + escl_type;
    escl_hexstr = hexstr(MD5(serialize(escl_extra)));

    for (i = 0; i < max_index(shell_handlers); i++)
    {
      sleep(2);
      shell_handler = shell_handlers[i];
      tmp_session.dbg_log(fn:fn, level:DEBUG3, message:
        "Trying shell handler: "+shell_handler+".");

      if(!tmp_session.login())
      {
        tmp_session.close_connection();
        if(!empty_or_null(tmp_session.error))
          return make_list(FALSE, tmp_session.error);
        else return make_list(FALSE, "login() failed.");
      }

      tmp_sh = new(shell_handler);
      if(!isnull(escl_type))
        tmp_sh.set_priv_escalation(type:escl_type, extra:escl_extra);

      tmp_channel = tmp_session.open_shell(shell_handler:tmp_sh);
      if(isnull(tmp_channel))
      {
        tmp_session.close_connection();
        return make_list(FALSE, "unable to open channel for shell handler.");
      }
      tmp_session.channel_manager.set_default_channel(tmp_channel);

      checks = cmd_list[shell_handler];
      for (j = 0; j < max_index(checks); j++)
      {
        cmd_set = checks[j];

        tmp_cb = cmd_set['pre_check_fail_cb'];
        if (tmp_cb) tmp_session.dbg_log(fn:fn, message:
            "Calling pre-check callback for next check.");
        if(!isnull(tmp_cb) && tmp_cb())
        {
          tmp_session.dbg_log(fn:fn, level:DEBUG3, message:
            "Pre-check failed for command '" + cmd_set['test_cmd'] +
            "', skipping check.");
          continue;
        }

        # Run test_cmd
        tmp_session.dbg_log(fn:fn, level:DEBUG3, message:
          "Trying command '" + cmd_set['test_cmd'] +
          "' using shell handler '" + shell_handler + "'. " +
          "Looking for regex '"+cmd_set['test_cmd_regex']+"'.");
        if(tmp_channel == NOSETUP)
          res = tmp_session.run_shell_command(command:cmd_set['test_cmd']);
        else
          res = tmp_session.run_shell_command(channel:tmp_channel, command:cmd_set['test_cmd']);

        escl_failed = FALSE;
        var old_res = res;
        var old_err = tmp_session.cmd_error;
        if(empty_or_null(old_res) && empty_or_null(old_err))
          old_err = "Unknown error";

        # If res doesn't match the test_cmd_regex and we were testing
        # with escalation, retry without escalation
        if(res !~ cmd_set['test_cmd_regex'] && !isnull(escl_type))
        {
          if (get_kb_item(tmp_bad_escl_kb) == escl_hexstr)
          {
            tmp_session.dbg_log(fn:fn, level:DEBUG3, message:"Privilege escalation failed, retrying without privilege escalation.");
            tmp_sh.unset_priv_escalation();
            escl_failed = TRUE;
            err_msg = old_res + old_err;

            if(tmp_channel == NOSETUP)
              res = tmp_session.run_shell_command(command:cmd_set['test_cmd']);
            else
              res = tmp_session.run_shell_command(channel:tmp_channel, command:cmd_set['test_cmd']);
          }
        }

        # If res matches the test_cmd_regex, set KB items and return TRUE
        if(res =~ cmd_set['test_cmd_regex'])
        {
          tmp_cb = cmd_set['cmd_success_cb'];

          replace_kb_item(name:SSH_LIB_KB_PREFIX + "cmd_method", value:"shell_handler");
          replace_kb_item(name:SSH_LIB_KB_PREFIX + "shell_handler", value:shell_handler);

          if(!isnull(tmp_cb))
            tmp_cb(session:tmp_session, use_shell_handler:TRUE, channel:tmp_channel, cmd_res:res);
          tmp_session.close_connection();


          if (!escl_failed && get_kb_item(tmp_bad_escl_kb) == escl_hexstr)
          {
            tmp_session.dbg_log(fn:fn, level:DEBUG3, message:
              "Privilege escalation failed.");
            tmp_sh.unset_priv_escalation();
            escl_failed = TRUE;
            err_msg = old_err;
          }

          if(!escl_failed) return make_list(TRUE);

          rm_kb_item(name:SSH_LIB_KB_PREFIX + kb_id + "/escalation_type");
          foreach item (keys(escl_extra))
            rm_kb_item(name:"Secret/" + SSH_LIB_KB_PREFIX + kb_id + "/escalation_extra/" + item);

          if(isnull(err_msg)) err_msg = "";

          return make_list(TRUE, "Privilege escalation failed, but the command was successful without privilege escalation.", err_msg);
        }
        # If res does not match test_cmd_regex, call the cmd_fail_cb
        else
        {
          tmp_session.dbg_log(fn:fn, message:
            'Command response does not match expected regex.'+
            '\n  Regex    : ' + cmd_set['test_cmd_regex'] +
            '\n  Response :\n' + res);
          tmp_cb = cmd_set['cmd_fail_cb'];
          if(!isnull(tmp_cb))
            tmp_cb(session:tmp_session, use_shell_handler:TRUE, channel:tmp_channel, cmd_res:res);
        }

        # Clear any existing errors before trying next command
        tmp_session.clear_cmd_error();
      }

      # If there are more shell handlers to try, close and re-open the
      # connection in case previous shell handler left the connection
      # in a bad state
      if(i+1 < len(shell_handlers) && tmp_channel != NOSETUP)
      {
        tmp_session.close_connection();
        tmp_session = new("sshlib::session");

        if(!tmp_session.open_connection(host:host, port:port))
        {
          if(!empty_or_null(tmp_session.error))
            return make_list(FALSE, tmp_session.error);
          else return make_list(FALSE, "open_connection() failed.");
        }
      }
    }

    tmp_session.close_connection();
    return make_list(FALSE, "unable to identify host.");
  }


  ##
  # Tries to identify the target host using SSH exec.  Loops over the supplied command list
  # executing checks.  If a command result matches the expected regular expression the host
  # will be identified as the type associated with that check.
  #
  # @param <host> Target host (optional) Only required if different
  #               from scan target
  # @param <port> SSH listening port on target host.
  # @param <cmd_list> A list of lists of commands and callbacks for checking various host types.
  #                   cmd_list looks like this:
  #                   [
  #                     {'test_cmd': 'uname', 'test_cmd_regex': "^Linux\s", 'cmd_success_cb': @handle_linux_os},
  #                     {'test_cmd': 'uname', 'test_cmd_regex': "^Mac OS\s", 'cmd_success_cb': @handle_mac_os}
  #                   ]
  # @return Returns list (success [TRUE,FALSE], error_message)
  # @category SSH
  ##
  function try_ssh_exec(host, port, cmd_list)
  {
    var cmd_set, tmp_session, res, tmp_cb;
    var fn = 'try_ssh_exec';

    tmp_session = new("sshlib::session");

    if(!tmp_session.open_connection(host:host, port:port))
    {
      if(!empty_or_null(tmp_session.error))
        return make_list(FALSE, tmp_session.error);
      else return make_list(FALSE, "open_connection() failed.");
    }

    if(!tmp_session.login())
    {
      tmp_session.close_connection();
      if(!empty_or_null(tmp_session.error))
        return make_list(FALSE, tmp_session.error);
      else return make_list(FALSE, "login() failed.");
    }

    foreach cmd_set(cmd_list)
    {
      tmp_cb = cmd_set['pre_check_fail_cb'];
      if (tmp_cb) tmp_session.dbg_log(fn:fn, message:
          "Calling pre-check callback for next check.");
      if(!isnull(tmp_cb) && tmp_cb())
      {
        tmp_session.dbg_log(fn:fn, level:DEBUG3, message:
          "Pre-check failed for command '" + cmd_set['test_cmd'] +
          "', skipping check.");
        continue;
      }

      tmp_session.dbg_log(fn:fn, level:DEBUG3, message:
        "Trying command '" + cmd_set['test_cmd'] + "' using exec. " +
        "Looking for regex '"+cmd_set['test_cmd_regex']+"'.");
      res = tmp_session.run_exec_command(command:cmd_set['test_cmd']);

      if(res =~ cmd_set['test_cmd_regex'])
      {
        tmp_cb = cmd_set['cmd_success_cb'];
        if(!isnull(tmp_cb))
          tmp_cb(session:tmp_session, use_shell_handler:FALSE, cmd_res:res);

        tmp_session.close_connection();

        replace_kb_item(name:SSH_LIB_KB_PREFIX + "cmd_method", value:"exec");

        return make_list(TRUE);
      }
      else
      {
        tmp_session.dbg_log(fn:fn, message:
          'Command response does not match expected regex.'+
          '\n  Regex    : ' + cmd_set['test_cmd_regex'] +
          '\n  Response :\n' + res);
        tmp_cb = cmd_set['cmd_fail_cb'];
          if(!isnull(tmp_cb))
            tmp_cb(session:tmp_session, use_shell_handler:FALSE, cmd_res:res);
      }
    }
    tmp_session.close_connection();
    return make_list(FALSE, "unable to identify host.");
  }

  ##
  # Wrapper function to run open_connection on current session.
  #
  # @param <session> session object passed by reference from try_ssh_kb_settings_login()
  # @param <fn> function name from caller
  # @param <host> host
  # @param <port> port
  #
  # @return return TRUE if connection successful
  # @category SSH
  #
  ##
  function open_connection_wrapper(&session, fn, host, port)
  {
    local_var ret;

    # Open connection
    if(!empty_or_null(host))
    {
      session.dbg_log(level:DEBUG3, fn:fn, message:'Opening a connection to host \''+host+'\', port '
        +port+' to test \'none\' authentication...');
      ret = session.open_connection(host:host, port:port);
    }
    else
    {
      session.dbg_log(level:DEBUG3, fn:fn, message:'Opening a connection to port '
        +port+' to test \'none\' authentication...');
      ret = session.open_connection(port:port);
    }
    return ret;
  }

  ##
  # Wrapper function to reconnect session. Used in try_ssh_kb_settings_login().
  #
  # @param <session> session object
  # @param <fn> function name from caller
  # @param <host> host
  # @param <port> port
  # @param <sleep_value> number of seconds to sleep before starting new session (default: 2).
  #
  # @return TRUE if reconnect successful
  #
  ##
  function reconnect_wrapper(&session, fn, host, port, sleep_value)
  {
    local_var ret;

    # reconnect session since we opened a channel before
    # and we want to ensure other credential methods can be tried on this connection.
    session.dbg_log(fn:fn, message:'Reconnecting SSH session.');
    session.close_connection();
    delete(session);
    if(isnull(sleep_value)) sleep_value = 2;
    sleep(sleep_value);
    session = new("sshlib::session");
    # Open connection
    ret = open_connection_wrapper(session:session, fn:fn, host:host, port:port);
    # If for some reason the session state is still SOC_CLOSED or connection failed, remove the creds.
    if(session.cur_state.val == "SOC_CLOSED" || !ret)
    {
      session.dbg_log(level:DEBUG3, fn:fn, message:
      'Unable to re-establish SSH session.');
      session.clear_saved_login_info();
      session.close_connection();
      return FALSE;
      # The calling function will have to do something based on ret value
      # such as calling continue or break in credentials loop in try_ssh_kb_settings_login().
    }
    return TRUE;
  }

  ##
  # Attempt SonicWall "none" authentication. If it's not identified as SonicWall device
  # then return and instruct calling function (try_ssh_kb_settings_login()) to continue trying
  # other credential methods.
  # If it is identified as a sonicwall device accepting none authentication then
  # open a shell and send password and check for login.
  #
  # @param <tmp_session> session object passed by reference from try_ssh_kb_settings_login()
  # @param <new_channel> channel object passed by reference from try_ssh_kb_settings_login()
  # @param <fn> function name from caller
  # @param <jindex> index value from credentials loop in try_ssh_kb_settings_login()
  # @param <username> username from current credential set
  # @param <host> host
  # @param <port> port
  # @param <sh> shell handler
  #
  # @return string to tell calling function whether to "break" or "continue" in loop
  #
  ##
  function sonicwall_none_auth(&tmp_session, &new_channel, fn, jindex, username, host, port, sh)
  {
    local_var password, ret_recon_wrapper;
    password = get_kb_item("Secret/SSH"+jindex+"password");
    if(isnull(password)) password = "";
    new_channel = tmp_session.open_shell(shell_handler:sh, skip_check_shell:TRUE);
    if(new_channel)
    {
      tmp_session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        channel        : new_channel,
        check_callback : @rate_limiting_check_password_prompt_cb,
        cmd_timeout    : 40,
        track_keepalives : FALSE
      );

      if("sonicwall, inc." >< tolower(new_channel.data_buf))
      {
        tmp_session.dbg_log(fn:fn, message:'Detected SonicWall device using "none" authentication.');
        IS_SONICWALL = TRUE; # global session var
        new_channel.clear_data_buf();
        new_channel.window_send_data(data:password + '\n', redact:TRUE);
        tmp_session.sshrecv_until(
          end_states     : make_list("SOC_CLOSED"),
          channel        : new_channel,
          check_callback : @sonicwall_is_password_success_cb,
          cmd_timeout    : 40,
          track_keepalives : TRUE # track keepalive messages that we see
                                  # on sonicwall devices as a failsafe timeout feature.
        );
        # incorrect login - break out of credentials loop and report login failure
        if("must be changed" >< tolower(new_channel.data_buf))
        {
          tmp_session.dbg_log(fn:fn, message:'Login failed to SonicWall device because password must be changed.');
          tmp_session.clear_saved_login_info();
          new_channel.close();
          tmp_session.close_connection();
          sleep(3); # sleep a few seconds to allow sonicwall devices to register that the connection is closed
          return "break";
        }
        # incorrect login - clear saved info so other login attempts can be made and continue trying credentials
        else if("access denied" >< tolower(new_channel.data_buf))
        {
          tmp_session.dbg_log(fn:fn, message:'Login failed to SonicWall device due to incorrect credentials.');
          tmp_session.clear_saved_login_info();
          new_channel.close();
          tmp_session.close_connection();
          sleep(3); # sleep a few seconds to allow sonicwall devices to register that the connection is closed
          return "continue";
        }
        # Successful login to SonicWall
        # login_res is already TRUE so break out of loop to report success
        else if("@" >< new_channel.data_buf && "access denied" >!< tolower(new_channel.data_buf))
        {
          tmp_session.dbg_log(fn:fn, message:'Login to SonicWall device successful using "none" authentication method.');
          tmp_session.dbg_log(fn:fn, message:'user: ' + username);
          set_kb_item(name:SSH_LIB_KB_PREFIX + "sonicwall/none", value:TRUE);
          return "break";
        }
      }
      # not a sonicwall device but it's accepting "none" auth.
      # ignore this and continue trying to authenticate with other methods
      else
      {
        tmp_session.dbg_log(fn:fn, message:'"none" authentication accepted but not identified as SonicWall device.');
        tmp_session.dbg_log(fn:fn, message:'Proceed to trying different auth method.');
        tmp_session.clear_saved_login_info();
        new_channel.close();
        ret_recon_wrapper = reconnect_wrapper(session:tmp_session, fn:fn, host:host, port:port);
        if(!ret_recon_wrapper)
        {
          return "continue"; # if reconnect failed continue trying next credential set
        }
      }
    }
    # Failed to open a channel for rate limit check
    else
    {
      tmp_session.dbg_log(fn:fn, message:'Failed to open channel in rate limit check for "none" authentication.');
      tmp_session.clear_saved_login_info();
      # reconnect session
      ret_recon_wrapper = reconnect_wrapper(session:tmp_session, fn:fn, host:host, port:port);
      if(!ret_recon_wrapper)
      {
        return "continue"; # if reconnect failed continue trying next credential set
      }
    }
  }

  ##
  # Called in try_ssh_kb_settings_login() after authentication method determined. Used to authenticate
  # and identify a Junos or SonicWall device using a non "none" authentication method (password / public key)
  #
  # @param <tmp_session> session object passed by reference from try_ssh_kb_settings_login()
  # @param <new_channel> channel object passed by reference from try_ssh_kb_settings_login()
  # @param <fn> function name of caller
  # @param <username> used in log output
  # @param <host> target host
  # @param <port> port
  # @param <sh> shell handler
  #
  # @return TRUE if login success, FALSE if failed.
  # calling function should use this ret value as 'login_res'
  #
  # @category SSH
  ##
  function sonicwall_junos_auth(&tmp_session, &new_channel, fn, username, host, port, sh)
  {
    local_var login_check, ret_recon_wrapper, login_res;

    login_res = TRUE;
    tmp_session.dbg_log(fn:fn, message:'Checking for SonicWall or Junos rate limited devices.');
    new_channel = tmp_session.open_shell(shell_handler:sh, skip_check_shell:TRUE);
    if(new_channel)
    {
      tmp_session.dbg_log(fn:fn, message:'Successfully opened channel for rate limit check.');
      tmp_session.sshrecv_until(
        end_states     : make_list("SOC_CLOSED"),
        channel        : new_channel,
        check_callback : @rate_limiting_check_cb,
        cmd_timeout    : 40
       );
      if("sonicwall" >< tolower(new_channel.data_buf))
      {
        tmp_session.dbg_log(fn:fn, message:'Detected SonicWall device.');
        IS_SONICWALL = TRUE;
        set_kb_item(name:SSH_LIB_KB_PREFIX + "sonicwall_prompt", value:new_channel.data_buf);
        set_kb_item(name:SSH_LIB_KB_PREFIX + "sonicwall/passwordauth", value: TRUE);
        if ("access denied" >< tolower(new_channel.data_buf))
        {
          tmp_session.dbg_log(fn:fn, message:'Login failed to SonicWall device due to incorrect credentials.');
          tmp_session.clear_saved_login_info();
          login_res = FALSE;
          new_channel.close();
          if(!isnull(tmp_session.channel_manager))
            tmp_session.channel_manager.remove_channel(channel:new_channel);
        }
      }
      else if("junos" >< tolower(new_channel.data_buf) || "juniper" >< tolower(new_channel.data_buf))
      {
        tmp_session.dbg_log(fn:fn, message:'Detected JUNOS device.');
        tmp_session.dbg_log(fn:fn, message:'user: ' + username);
        set_kb_item(name:SSH_LIB_KB_PREFIX + "junos_prompt", value:new_channel.data_buf);
        login_check = sh.run_command(channel:new_channel, command:"uname -a", raw:TRUE, cmd_timeout_min:40);
        # JUNOS cli prompt
        if("unknown command" >< tolower(login_check) ||
           "syntax error, expecting <command>" >< tolower(login_check))
        {
          tmp_session.dbg_log(fn:fn, message:"Junos shell mode not detected. Using cli mode.");
        }
        # JUNOS shell prompt (%) so set KB item to tell ssh_lib to use shell commands
        else if("junos" >< tolower(login_check) || "juniper" >< tolower(login_check) ||
                "freebsd" >< tolower(login_check))
        {
          tmp_session.dbg_log(fn:fn, message:"Junos shell mode detected.");
          set_kb_item(name:"Host/Juniper/JUNOS/shell", value:TRUE);
          replace_kb_item(name:"Host/uname", value:login_check);
        }
        set_kb_item(name:SSH_LIB_KB_PREFIX + "junos/auth", value:TRUE);
      }
      else
      {
        tmp_session.dbg_log(fn:fn, message:'Host is not identified as SonicWall or Junos device.');
        new_channel.close();
        if(!isnull(tmp_session.channel_manager))
          tmp_session.channel_manager.remove_channel(channel:new_channel);
      }
    }
    else
    {
      tmp_session.dbg_log(fn:fn, message:'Failed to open channel for rate limit check.');
    }
    # reconnect session if needed
    if(tmp_session.cur_state.val == "SOC_CLOSED")
    {
      ret_recon_wrapper = reconnect_wrapper(session:tmp_session, fn:fn, host:host, port:port);
      if(!ret_recon_wrapper) login_res = FALSE;
    }

    if(login_res) return TRUE;
    else return FALSE;
  }

  ##
  # Iterates through "Secret/SSH/[0-9]+/*" kb items (set by ssh settings plugin)
  # and tries to find a valid login method.  If we do, return TRUE
  # session variable is reference, it will be a valid sshlib session object
  # if this function returns TRUE
  #
  # @param <session> param description
  # @param <accept_none_auth> Boolean.  If not true and 'none' auth succeeds, will
  #                                     cause the function to continuing trying other
  #                                     credentials and methods.
  # @param <rate_limit> Boolean. Only set to true if this is running with the SSH rate limiting plugin.
  #                              Login and check for sonicwall and junos ssh rate limited devices.
  #                              This will identify the device via post login banner and open a
  #                              shell to the device for ssh_rate_limiting.nasl to use. (optional)
  # @param <&new_channel> Channel object passed by reference to be used further in
  #                       ssh_rate_limiting.nasl. Only needed when rate_limit is TRUE. (optional)
  # @param <force_none_auth> Boolean. Passed to login function which then passes it to
  #                                   get_supported_auth_methods. Forces function to recheck supported
  #                                   auth methods regardless of what is cached in KB.
  #
  # @return Returns TRUE if a login succeeds using stored credentials, FALSE if none
  #         login was not possible using stored credential sets and NULL if an error
  #         happens.
  # @category SSH
  ##
  function try_ssh_kb_settings_login(&session, accept_none_auth, rate_limit, &new_channel, force_none_auth)
  {
    local_var ret, sleep_value, login_res;
    local_var tmp_session;
    local_var port, pref_port, ssh_ports, found_ports;
    local_var supported_auth_method, supported_methods_str;
    local_var j, jindex, set;
    local_var auth_method, auth_method_check;
    local_var extra, ret_recon_wrapper;
    local_var username, password;
    local_var cert, privatekey, passphrase;
    local_var kdc_hostname, kdc_port, kdc_realm, kdc_transport;
    local_var escl_type, escl_extra, root, sulogin, supass, supath;
    local_var rsa1_priv_key_cred_set = make_array();
    local_var fn = "try_ssh_kb_settings_login";
    local_var tmp_channel;
    local_var open_connection_failed = FALSE;
    local_var kex_failed = FALSE;
    local_var port_closed = FALSE;
    local_var msg, sh, login_check;
    local_var ok_to_send_password, ret_sonicwall, sonicwall_junos_ret;
    local_var custom_prompt;

    # Inherit 'host' value for open_connection() calls
    local_var host;
    if(!empty_or_null(session.remote_host))
      host = session.remote_host;
    # If we don't have a hostname, we want to only pass the port to open_connection()
    else host = NULL;

    # If we ran this function before and failed, return FALSE
    if(get_kb_item(SSH_LIB_KB_PREFIX + fn + "_failed"))
    {
      session.dbg_log(level:DEBUG3, fn:fn, message:'This function has previously failed.');
      return FALSE;
    }

    # If we ran this function before and were successful, just log in and return
    if(get_kb_item(SSH_LIB_KB_PREFIX + fn + "_success"))
    {
      session.dbg_log(level:DEBUG3, fn:fn, message:'This function has previously succeeded.');
      session = new("sshlib::session");

      ret = session.open_connection(host:host, port:get_kb_item(SSH_LIB_KB_PREFIX + "verified_login_port"));
      if(!ret)
      {
        extra = get_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX +
          session.get_kb_connection_id() + "/login_extra");
        msg = "open_connection() failed on previously successful " +
          "connection: " + last_error;
        set_kb_item(
          name  : sshlib::SSH_LIB_KB_PREFIX + fn + "/error",
          value : msg
        );
        session.set_auth_failure_error(user:extra["username"],
          port:port, msg:msg);
        return FALSE;
      }
      ret = session.login();
      if(!ret)
      {
        extra = get_kb_args(kb_prefix:"Secret/" + SSH_LIB_KB_PREFIX +
          session.get_kb_connection_id() + "/login_extra");
        msg = "Authentication failed on previously successful " +
          "connection: " + last_error;
        set_kb_item(
          name  : sshlib::SSH_LIB_KB_PREFIX + fn + "/error",
          value : msg
        );
        session.set_auth_failure_error(user:extra["username"],
          port:port, msg:msg);
      }
      return ret;
    }

    # If no user-supplied SSH credentials are available, return FALSE
    if (
      empty_or_null(get_kb_item("Secret/SSH/password")) &&
      empty_or_null(get_kb_item("Secret/SSH/kdc_hostname")) &&
      empty_or_null(get_kb_item("Secret/SSH/privatekey"))
    )
    {
      session.set_error("No user-supplied SSH credential sets were found.");
      return FALSE;
    }

    # Build list of ssh_ports to try, preferred port should be first in list
    ssh_ports = make_list(22);
    pref_port = get_kb_item('Secret/SSH/PreferredPort');
    if (pref_port) ssh_ports = make_list(pref_port, ssh_ports);
    found_ports = get_kb_list("Services/ssh");
    if (found_ports) ssh_ports = make_list(ssh_ports, found_ports);

    foreach port (list_uniq(ssh_ports))
    {
      session.dbg_log(level:DEBUG3, fn:fn, message:'Attempting to log in on port '+port+'.');
      # Skip known closed ports and respect unscanned ports settings
      if (!get_port_state(port))
      {
        session.dbg_log(level:DEBUG2, fn:fn, message:'Port '+port+' is closed.');
        set_kb_item(
          name  : sshlib::SSH_LIB_KB_PREFIX + fn + "/error",
          value : 'Port '+port+' is closed.'
        );
        port_closed = TRUE;
        continue;
      }
      else
      {
        port_closed = FALSE;
      }

      # Iterate through credentials in the KB
      # will terminate when no more usernames can be found in the kb
      for (j = -1; TRUE; j++)
      {
        jindex = kb_index(j);
        set = j+2; # Only used for logging purposes, and counts from 1.

        # Retrieve the username from the credential set
        username = get_kb_item("Secret/SSH"+jindex+"login");
        # The UI will not allow an SSH credential to be saved without a username
        # If there are no more credentials to try, exit loop
        if(!username)
        {
          if (j >= 0) session.dbg_log(level:DEBUG3, fn:fn, message:'All available credential sets have been tried.');
          else session.dbg_log(level:DEBUG3, fn:fn, message:'No SSH credential sets were found.');
          break;
        }

        # Try 'none' auth
        session.dbg_log(level:DEBUG3, fn:fn, message:'Creating new temporary session to test \'none\' authentication.');
        tmp_session = new("sshlib::session");
        # Open connection
        ret = open_connection_wrapper(session:tmp_session, fn:fn, host:host, port:port);
        # if we are in "rate limit" mode and the connection failed retry the connection.
        # reconnect on first credential set in case previous scan or manual connection
        # triggered rate limit failure.
        if(!ret && rate_limit)
        {
          if(j == -1) sleep_value = 30; # first credential set sleep value
          else sleep_value = 65; # second+ credential set sleep value higher
          tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Failed to open the initial SSH connection.' +
                                                           ' sleeping ' + sleep_value + ' seconds.');
          sleep(sleep_value);
          ret_recon_wrapper = reconnect_wrapper(session:tmp_session, fn:fn, host:host, port:port);
          # reconnect failed so break out of credentials loop
          if(!ret_recon_wrapper)
          {
            tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Error attempting session reconnect. '+tmp_session.error);
            set_kb_item(name:sshlib::SSH_LIB_KB_PREFIX +
                            "try_ssh_kb_settings_login/error",
                        value:"open_connection failed: " + last_error);
            open_connection_failed = TRUE;
            if(tmp_session.legacy_data[USE_LEGACY])
            session.use_legacy();
            break;
          }
          # reconnect worked - continue with function
          else
          {
            tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Successfully opened a connection on port '+port+'.');
            open_connection_failed = FALSE;
          }
        }
        # connection failed and we are NOT in "rate limit" mode
        else if(!ret)
        {
          tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Error calling open_connection: '+tmp_session.error);
          set_kb_item(name:sshlib::SSH_LIB_KB_PREFIX +
                          "try_ssh_kb_settings_login/error",
                     value:"open_connection failed: " + last_error);
          open_connection_failed = TRUE;
          if(tmp_session.legacy_data[USE_LEGACY])
            session.use_legacy();
          break;
        }
        else
        {
          tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Successfully opened a connection on port '+port+'.');
          open_connection_failed = FALSE;
        }

        # Check for KEX errors
        if (!tmp_session.complete_kex())
        {
          tmp_session.dbg_log(level:DEBUG3, fn:fn, message:
            'Error calling complete_kex().');
          set_kb_item(
            name  : sshlib::SSH_LIB_KB_PREFIX + fn + "/error",
            value : last_error);
          kex_failed = TRUE;
          if(tmp_session.legacy_data[USE_LEGACY])
            session.use_legacy();
          break;
        }
        else
        {
          kex_failed = FALSE;
        }

        # Determine authentication method and set ok_to_send_password to FALSE if we are using
        # non username/password authentication. This will prevent the rate_limit check from sending
        # the wrong password.
        password      = get_kb_item("Secret/SSH"+jindex+"password");
        kdc_hostname  = get_kb_item("Secret/SSH"+jindex+"kdc_hostname");
        custom_prompt = get_kb_item("SSH"+jindex+"custom_password_prompt");
        privatekey    = hex2raw(s:get_kb_item("Secret/SSH"+jindex+"privatekey"));
        ok_to_send_password = TRUE;
        # The order is important because gssapi also includes a password
        if (kdc_hostname)
          auth_method_check = "gssapi";
        else if(password)
          auth_method_check = "keyboard-interactive";
        else if(privatekey)
          auth_method_check = "publickey";
        else
          auth_method_check = "na";

        # Do not send password in rate_limit check for sonicwall devices if the cred set is non username/password
        if(auth_method_check != "keyboard-interactive") ok_to_send_password = FALSE;

        # Attempt 'none' authentication
        tmp_session.dbg_log(level:DEBUG3, fn:fn, message:"Trying 'none' authentication.");
        login_res = tmp_session.login(method:"none", extra:make_array("username",username), save_login:TRUE,
                                      force_none_auth:force_none_auth);
        if (max_index(tmp_session.supported_auth_methods) > 0)
        {
          supported_methods_str = join(tmp_session.supported_auth_methods, sep:",");
          replace_kb_item(name:SSH_LIB_KB_PREFIX + tmp_session.get_kb_connection_id() + "/" + username + "/supported_login_methods", value:supported_methods_str);
        }
        # If the host accepted 'none' auth
        if(login_res)
        {
          tmp_session.dbg_log(level:DEBUG3, fn:fn,
                              message:'The \'none\' authentication method was accepted for user \''+username+'\'');
          # if accept_none_auth is true, break for success
          if(accept_none_auth)
          {
            tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Using \'none\' authentication method.');
            # rate limit mode enabled and username/password auth is used so attempt to connect to sonicwall "none" auth
            if(rate_limit && ok_to_send_password)
            {
              sh = new("sshlib::sh_shell_handler_misc");
              ret_sonicwall = sonicwall_none_auth(tmp_session:tmp_session, new_channel:new_channel, fn:fn, jindex:jindex,
                                                  username:username, host:host, port:port, sh:sh);
              if(ret_sonicwall == "break") break;
              else if(ret_sonicwall == "continue") continue;
            }
            # rate_limit option not selected but "none" auth succeeded
            else
            {
              tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Using \'none\' authentication method.');
              break;
            }
          }
          # if accept_none_auth is false, call tmp_session.clear_saved_login_info() and proceed to trying credentials
          else
          {
            tmp_session.dbg_log(level:DEBUG3, fn:fn,
                                message:'Not using \'none\' authentication method because \'accept_none_auth\' is FALSE.');
            tmp_session.clear_saved_login_info();
            # This tells session::login() that we've already been granted
            # the "ssh-userauth" service
            tmp_session.cur_state.set("USERAUTH_FAILURE");
          }
        }
        else
        {
          tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'The \'none\' authentication method was not accepted');
        }

        # Check socket state
        if(tmp_session.cur_state.val == "SOC_CLOSED")
        {
          tmp_session.dbg_log(message:'The socket has been closed. Trying next credential set.');
          continue;
        }

        # Determine authentication method
        # using KB items set before "none" auth section above
        # The order is important because gssapi also includes a password
        if (kdc_hostname)
          auth_method = "gssapi";
        else if(password)
          auth_method = "keyboard-interactive";
        else if (privatekey)
        {
          # If the private key is in RSA1 format, skip this credential set
          # RSA1 is only supported by SSHv1, this library only supports SSHv2
          if ('SSH PRIVATE KEY FILE FORMAT 1.1\n\0' >< privatekey)
          {
            session.dbg_log(fn:fn, message:'The private key type for credential set '+set+
                ' is RSA1, which is only supported by SSHv1. This library only supports SSHv2. Trying next credential set.');
            rsa1_priv_key_cred_set[j] = TRUE;
            tmp_session.close_connection();
            continue;
          }
          auth_method = "publickey";
        }
        else
        {
          session.dbg_log(level:DEBUG3, fn:fn,
              message:'The authentication method was unable to be determined for credential set '+set+
              '. Trying next credential set.');
          tmp_session.close_connection();
          continue;
        }

        # Verify login method is supported
        if(auth_method == "keyboard-interactive")
        {
          if(!tmp_session.auth_method_supported(method:auth_method, username:username))
          {
            auth_method = "password";
            if(!tmp_session.auth_method_supported(method:auth_method, username:username))
            {
              tmp_session.dbg_log(level:DEBUG1, fn:fn, message:'Neither "keyboard-interactive" nor "password" authentication methods for credential set '+set+' is supported. Trying next credential set.');
              tmp_session.close_connection();
              continue;
            }
          }
        }
        else if(!tmp_session.auth_method_supported(method:auth_method, username:username))
        {
          tmp_session.dbg_log(level:DEBUG1, fn:fn,
              message:'The authentication method "'+auth_method+'" for credential set '
              +set+' is not supported. Trying next credential set.');
          tmp_session.close_connection();
          continue;
        }

        # Check socket state
        if(tmp_session.cur_state.val == "SOC_CLOSED")
        {
          tmp_session.dbg_log(message:'The socket has been closed. Trying next credential set.');
          continue;
        }

        # Retrieve extra args from KB depending on auth method
        extra = make_array();
        extra["username"] = username;
        if(auth_method == "keyboard-interactive" || auth_method == "password")
        {
          extra["password"] = password;
          if(!isnull(custom_prompt))
            extra["custom_prompt"] = custom_prompt;
        }
        else if (auth_method == "gssapi")
        {
          kdc_realm = get_kb_item("Kerberos/SSH"+jindex+"realm");

          extra["password"] = password;
          extra["realm"]    = kdc_realm;

          # Settings used by engine function nasl_open_sock_ex()
          # These should be removed if login fails
          replace_kb_item(name:"Secret/SSH/kdc_hostname", value:kdc_hostname);

          kdc_port = get_kb_item("Secret/SSH"+jindex+"kdc_port");
          replace_kb_item(name:"Secret/SSH/kdc_port", value:kdc_port);

          if(get_kb_item("Kerberos/SSH"+jindex+"kdc_use_tcp"))
            replace_kb_item(name:"Kerberos/SSH/kdc_use_tcp", value:TRUE);
        }
        else if (auth_method == "publickey")
        {
          cert = get_kb_item("Secret/SSH"+jindex+"certificate");
          passphrase = get_kb_item("Secret/SSH"+jindex+"passphrase");

          extra["privatekey"]   = privatekey;
          if(!isnull(passphrase))
            extra["passphrase"] = passphrase;
          if(!isnull(cert))
            extra["cert"]       = cert;
        }

        # Attempt login
        login_res = tmp_session.login(method:auth_method, extra:extra, save_login:TRUE);

        # If auth failed with keyboard-interactive but password auth is also
        # supported, try password auth
        if(!login_res && auth_method == "keyboard-interactive" &&
           tmp_session.cur_state.val != "SOC_CLOSED" &&
           tmp_session.auth_method_supported(method:"password", username:username))
        {
          tmp_session.dbg_log(fn:fn, level:DEBUG3, message:'try_ssh_kb_settings_login: Login failed for keyboard-interactive authentication with credential set '+set+' on port '+port+' with error: '+tmp_session.error+'Trying password authentication.');
          auth_method = "password";
          login_res = tmp_session.login(method:auth_method, extra:extra, save_login:TRUE);
        }

        # if login is successful and "rate limit" mode is enabled attempt to identify and
        # authenticate to junos or sonicwall device. Using non-none authentication methods.
        if(login_res && rate_limit)
        {
          sh = new("sshlib::sh_shell_handler_misc");
          sonicwall_junos_ret = sonicwall_junos_auth(tmp_session:tmp_session, new_channel:new_channel, username:username,
                                                     host:host, port:port, sh:sh);
          if(!sonicwall_junos_ret) login_res = FALSE;
        }

        # When pubkey authentication is used with AWS instances, an
        # authentication attempt appears successful, but really isn't.
        # This also catches other post-login errors such as password
        # expiration.
        if(login_res && !IS_SONICWALL)
        {
          tmp_session.dbg_log(level:DEBUG3, fn:fn, message:
            'Opening a channel to check for post-login errors.');
          tmp_channel = tmp_session.get_channel();
          if (tmp_channel)
          {
            tmp_channel.make_request(type:"shell", want_reply:FALSE);
            var cb = @client_cb_post_login_error;
            tmp_session.sshrecv_until(channel:tmp_channel, check_callback:cb, cmd_timeout:10);
            if(tmp_session.cur_state.val == "SOC_CLOSED")
            {
              # If the response to the error shell request is a closed connection, reopen it.
              tmp_session.dbg_log(level:DEBUG3, fn:fn, message:
                  'client_cb_post_login_error caused a connection close.' +
                  ' Reopening connection.');
              if(reconnect_wrapper(session:tmp_session, fn:fn, host:host, port:port))
              {
                # reconnect successful
                login_res = tmp_session.login(method:auth_method, extra:extra, save_login:TRUE);
              }
              else
              {
                # reconnect failed
                tmp_session.dbg_log(level:DEBUG3, fn:fn, message:
                  'Unable to re-establish connection after post-login error check.' +
                  'Trying next credential set.');
                tmp_session.clear_saved_login_info();
                tmp_session.close_connection();
                login_res = FALSE;
              }
            }
            if(tmp_session.post_login_error)
            {
              var login_error = tmp_channel.stderr;
              if (!login_error) login_error = tmp_channel.data_buf;
              set_kb_item(name:SSH_LIB_KB_PREFIX + "disallowed_login_id", value:TRUE);
              if(login_error)
                set_kb_item(name:SSH_LIB_KB_PREFIX + "disallowed_login_id" + "/error",
                  value:login_error);
              msg = "Login failed after authentication: " + login_error;
              set_kb_item(
                name  : sshlib::SSH_LIB_KB_PREFIX + fn + "/error",
                value : msg
              );
              tmp_session.set_auth_failure_error(user:extra["username"],
                port:port, msg:msg);
              if(tmp_session.cur_state.val == "SOC_CLOSED")
                tmp_session.dbg_log(level:DEBUG3, fn:fn, message:
                  'The socket has been closed. Trying next credential set.');
              else tmp_session.dbg_log(level:DEBUG3, fn:fn, message:
                  'Login failed for credential set '+set+' on port '+port+
                  ' with error: ' + login_error +
                  'Trying next credential set.');
              tmp_session.clear_saved_login_info();
              tmp_session.close_connection();
              if(!tmp_session.legacy_data[USE_LEGACY])
              {
                set_support_level(level: SSH_LIB_LOGIN_ERROR);
              }
              login_res = FALSE;
            }
            tmp_channel.close();

            if(!isnull(tmp_session.channel_manager))
              tmp_session.channel_manager.remove_channel(channel:tmp_channel);
          }
        }
        # If login failed, close the session and continue looping through credentials
        if(!login_res)
        {
          if(tmp_session.cur_state.val == "SOC_CLOSED")
            tmp_session.dbg_log(message:'The socket has been closed. Trying next credential set.');

          else tmp_session.dbg_log(level:DEBUG3, fn:fn, message:'Login failed for credential set '
              +set+' on port '+port+' with error: '+tmp_session.error+'Trying next credential set.');

          if (auth_method == "gssapi")
          {
            rm_kb_item(name:"Secret/SSH/kdc_hostname");
            rm_kb_item(name:"Secret/SSH/kdc_port");
            rm_kb_item(name:"Kerberos/SSH/kdc_use_tcp");
          }

          tmp_session.close_connection();
          # sleep a few seconds if rate limited option is passed.
          # sonicwall needs time after the connection closes to register that the connection is closed
          if(rate_limit)
            sleep(3);
          continue;
        }

        # Login succeeded
        session.dbg_log(level:DEBUG3, fn:fn, message:'Login succeeded for credential set '+set+' on port '+port+'.');
        # Store escalation settings
        if(get_kb_item("Secret/SSH"+jindex+"sudo"))
        {
          escl_type = get_kb_item("Secret/SSH"+jindex+"sudo_method");
          sulogin   = get_kb_item("Secret/SSH"+jindex+"su-login");
          supass    = get_kb_item("Secret/SSH"+jindex+"sudo-password");
          supath    = get_kb_item("Secret/SSH"+jindex+"sudo_path");
          root      = get_kb_item("Secret/SSH"+jindex+"root");
          if (isnull(supath)) supath = "";

          escl_extra = make_array();

          if(escl_type == "su")
          {
            escl_extra["su_user"] = root;
            escl_extra["su_pass"] = supass;
            escl_extra["su_dir"]  = supath;
          }
          else if(escl_type == "sudo")
          {
            escl_extra["sudo_user"] = root;
            escl_extra["sudo_pass"] = supass;
            escl_extra["sudo_dir"]  = supath;
          }
          else if (escl_type == "su+sudo")
          {
            escl_type = "su_sudo";
            escl_extra["su_user"]   = sulogin;
            escl_extra["su_pass"]   = supass;
            escl_extra["su_dir"]    = supath;
            escl_extra["sudo_user"] = root;
            escl_extra["sudo_dir"]  = supath;
            escl_extra["sudo_pass"] = supass;
          }
          else if(escl_type == "pbrun")
          {
            escl_extra["pbrun_user"] = root;
            escl_extra["pbrun_pass"] = supass;
            escl_extra["pbrun_dir"]  = supath;
          }
          else if(escl_type == "dzdo")
          {
            escl_extra["dzdo_user"] = root;
            escl_extra["dzdo_pass"] = supass;
            escl_extra["dzdo_dir"]  = supath;
          }
          else if(escl_type == "Cisco 'enable'")
          {
            escl_type = "cisco_enable";
            escl_extra["enable_pass"] = get_kb_item("Secret/SSH"+jindex+"enable-password");
          }
          else
          {
            escl_type = NULL;
            session.dbg_log(fn:fn, message:'Unknown escalation type '+escl_type+'.');
          }
        } # End escalation settings

        # looking at enable-admin escalataions that don't support sudo
        else if(get_kb_item("Secret/SSH"+jindex+"sudo_method") == "Cisco 'enable'")
        {
          escl_type = "cisco_enable";
          # does the extra array already exist?
          if ( isnull( escl_extra ) )
          {
            # extra array does not exist, create it
            escl_extra = make_array();
          }
          # add enable-pass to the extra array, it will be sent
          # to shell handler using set_priv_escalation later
          escl_extra["enable_pass"] = get_kb_item("Secret/SSH"+jindex+"enable-password");
        }

        # Break out of credentials loop
        break;

      } # End credentials loop

      # If we were able to log in successfully, break out of ports loop
      if(login_res) break;

    } # End ports loop
    # If we were able to log in, save settings
    if(login_res && !tmp_session.post_login_error)
    {
      session = tmp_session;

      replace_kb_item(name:SSH_LIB_KB_PREFIX + fn + "_success", value:TRUE);
      replace_kb_item(name:SSH_LIB_KB_PREFIX + "verified_login_port", value:port);

      if(escl_type)
        session.save_escalation_info(type:escl_type, args:escl_extra);

      replace_kb_item(name:"Host/Auth/SSH/" + port + "/Success", value:username);
      lcx::log_auth_success(proto:lcx::PROTO_SSH, port:port,
        user:username, clear_failures:TRUE);

      return TRUE;
    }

    # Otherwise, note the failure in the KB and return FALSE
    else
    {
      replace_kb_item(name:SSH_LIB_KB_PREFIX + fn + "_failed", value:TRUE);
      if (!open_connection_failed && !kex_failed && !port_closed)
      {
        set_kb_item(
          name  : sshlib::SSH_LIB_KB_PREFIX + fn + "/error",
          value : "No supplied credential sets succeeded on any of " +
            "the ssh ports");
      }
      if (max_index(keys(rsa1_priv_key_cred_set)) > 0)
      {
        session.use_legacy();
        session.set_legacy_cred_sets(rsa1_priv_key_cred_set);
      }
      return FALSE;
    }
  }

  ##
  # Retrieves all keys and values in the KB stored under the supplied
  # prefix as a dictionary
  #
  # @param <kb_prefix> String prefix of KB keys to read
  # @return Dictionary of KB keys and values
  # @category SSH
  ##
  function get_kb_args(kb_prefix)
  {
    var extra, tmp_list, key, val;
    extra = make_array();

    tmp_list = get_kb_list(kb_prefix + "/*");

    foreach key (keys(tmp_list))
    {
      val = tmp_list[key];
      key -= (kb_prefix + "/");
      extra[key] = val;
    }
    return extra;
  }


  ##
  # Iterates through a dictionary of keys and values saving them in
  # the KB.
  #
  # @param <kb_prefix> String prefix - first part of key to save under
  # @param <args> Dictionary of keys/values to save in the KB.
  # @category SSH
  ##
  function save_kb_args(kb_prefix, args)
  {
    var key;
    foreach key (keys(args))
    {
      if(isnull(get_kb_item(kb_prefix + "/" + key)))
        if(!isnull(args[key])) set_kb_item(name:kb_prefix + "/" + key, value:args[key]);
    }

    return NULL;
  }

  ##
  # Return the shell handler object class stored in the KB
  #
  # @return String class name
  # @category SSH
  ##
  function get_kb_shell_handler()
  {
    var handler;
    var fn = 'get_kb_shell_handler';
    var handler_string = get_kb_item(SSH_LIB_KB_PREFIX + 'shell_handler');
    if (isnull(handler_string)) handler_string = 'sshlib::sh_shell_handler';
    handler = new(handler_string);
    return handler;
  }

  ##
  # Sets the current SSH library support level to indicate that local checks are supported;
  # SSH_LIB_SUPPORTS_LOCAL_CHECKS.
  #
  # @category SSH
  ##
  function enable_local_checks()
  {
    replace_kb_item(name:'Host/local_checks_enabled', value: TRUE);
    if (defined_func('report_xml_tag'))
      report_xml_tag(tag:"Credentialed_Scan", value:"true");

    if(!info_t || info_t == INFO_SSH)
    {
      replace_kb_item(name:SSH_LIB_KB_PREFIX + "sshlib_local_checks", value:TRUE);
      set_support_level(level:SSH_LIB_SUPPORTS_LOCAL_CHECKS);
    }

    return NULL;
  }

  ##
  # Sets the current SSH library support level to the 'level' parameter
  # both in the KB and as a global variable.  Valid levels are defined
  # in ssh_lib_util.inc
  #
  # @param <level> SSH library support level.
  # @category SSH
  ##
  function set_support_level(level)
  {
    HOST_SUPPORT_LEVEL = level;
    if(!info_t || info_t == INFO_SSH)
      replace_kb_item(name:SSH_LIB_KB_PREFIX + "support_level", value:level);

    return NULL;
  }

  ##
  # Returns the current SSH library support level as defined by enumerated values in
  # ssh_lib_util.inc.
  #
  # @return Integer value of current SSH support level.
  # @category SSH
  ##
  function get_support_level()
  {
    return get_kb_item(SSH_LIB_KB_PREFIX + "support_level");
  }

  ##
  # Returns TRUE if local checks are enabled for this library on remote host, FALSE otherwise
  #
  # @return boolean
  # @category SSH
  ##
  function local_checks_enabled()
  {
    return get_kb_item(SSH_LIB_KB_PREFIX + "sshlib_local_checks");
  }

  ##
  # Returns the SSH client version of the target host.
  #
  # @return SSH client version string
  # @category SSH
  ##
  function get_ssh_client_ver()
  {
    local_var ver = get_kb_item("SSH/client_ver");
    if(!isnull(ver))
      ver = "SSH-2.0-" + ver;
    else
      ver = "SSH-2.0-" + default_local_version;

    return ver;
  }

  ##
  # Returns the SSH listening port of the target host.
  #
  # @return SSH port
  # @category SSH
  ##
  function kb_ssh_transport()
  {
    local_var port, pref, ssh_ports;

    port = get_kb_item(SSH_LIB_KB_PREFIX + "verified_login_port");
    if(port) return port;

    pref = get_kb_item("Secret/SSH/PreferredPort");
    ssh_ports = get_kb_list("Services/ssh");
    if(!isnull(ssh_ports))
    {
      ssh_ports = make_list(ssh_ports);

      # Try to use the PreferredPort (if specified)
      if (pref > 0)
        foreach port (ssh_ports) { if (port == pref) return port; }

      # Try to use port 22
      foreach port (ssh_ports) { if (port == 22) return port; }

      # Otherwise, use the first port available
      port = ssh_ports[0];
      if (port) return port;
    }

    if ( pref && get_port_state(pref) ) return pref;
    return 22; #Default
  }

  ##
  # Wrapper for debugging when session may be null
  #
  # @param <session:obj> An sshlib session object to use to log the message
  #                      if possible
  # @param <fn:string>   The function name to prepend the log with
  # @param <message:string>  The message to log
  # @param <level:int>   The debug level to pass to session if applicable
  # @param <error:bool>  Send to session.set_error if possible
  # @param <cmd_error:bool> Send to session.set_cmd_error if possible
  # @return NULL
  # @remark This is a basic wrapper and does not support all of the
  # parameters that session.dbg_log() supports. Use that directly if needed.
  # @category SSH
  ##
  function dbg_log(session, fn, message, level, error, cmd_error)
  {
    if (session)
    {
      if (cmd_error) return session.set_cmd_error(message);
      if (error) return session.set_error(message);
      return session.dbg_log(fn:fn, level:level, message:message);
    }
    return spad_log(message: fn + '(): ' + message);
  }

  ##
  # Wrapper for Channel::usable_for_shell_command() that handles input
  # validation and error generation, for use by other objects and
  # functions outside Channel
  #
  # @param <channel:object> A channel object
  # @param <nosetup_ok:bool> True if NOSETUP shell is ok
  # @return TRUE if channel is usable, else FALSE
  # @category SSH
  # @GizaNE 6.0
  ##
  function channel_usable_for_shell_command(&channel, nosetup_ok)
  {
    if (nosetup_ok && channel == NOSETUP) return TRUE;
    if (!isnull(channel) && channel.usable_for_shell_command())
      return TRUE;
    return FALSE;
  }

  ##
  # Wrapper for session::replace_shell() that handles input validation
  # and error generation, for use by other objects and functions
  # outside session
  #
  # @param <session> An sshlib session object, used for reconnection
  #                  if necessary
  # @param <channel> A channel object for the passed session
  # @return TRUE if channel is ok or replaced successfully, else FALSE
  # @category SSH
  ##
  function session_replace_shell(&session, &channel)
  {
    # Call session.replace_shell() using session passed as a reference,
    # not channel.session
    if (!session)
    {
      dbg_log(session:channel.session, fn:FUNCTION_NAME, error:TRUE, message:
        'The passed channel is NULL or unusable, but a session object' +
        ' was not passed. Unable to replace shell.');
      return FALSE;
    }
    if (session.replace_shell(channel:channel)) return TRUE;
    return FALSE;
  }
}
