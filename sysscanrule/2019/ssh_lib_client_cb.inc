#TRUSTED 1736f75f429f3b7cb07e7b2a4aa8e1c36bd37d8715799e354e5e0811495b1fb8ec3cc24638d5a6738791fe7fe5a283fc1a611507ad6ca4b407d1682b1b0c9d22c62c4b8b71a0e722e91227ed5b1a5f85738a531bcc144d98ddfd6a9f72bd6bc6ce583d400b04572d17d22c9e3880e88420fc6c5f6257cad053156ba3c5f6cb40c5a5a44ee723f9ed6c98b66560403bc75c183adb057e6c8f31da4e4a21a32c4505246d890c53aadabf21cb2f0047de832e45df3a8942533133d4a2b4960ae08b5296985980f4eb88def2631da48c2f49a434f37bb66b26bfa557afb74c29a461efcb5b197f0d9474bb77699bc903188a5caa24aa6d4cf6872595e4bf099c3a00ac822d6b92ba33d083480a0220eac8644d8530ae8fea9ed7106ed16c1432ede26576219f6fd9fdb0736623535e8375b45b8eaba4eb32521b51c36e26b9d81e57b6e65ed8050962cc83271ca0dbb914ef01662bb33267ad534dd28232e4fa453f79d8afefe714f01c9d97d89560dbb3f780fb8a0f29507bc693f59e1c6845deb7ce368b908eeea3039f5e6dd2ae23354d3f8e0321665b0f348b65d102a27e0f55ee98f9671dc881bac47d56f23fb9ae49f5e730140237df4edeede162593ed0803bc862172611c532b4f95e2ea2c34e939687418d53079a51224ec89bb36b85a067522cb033848dcec8a74f8a8ebec1cb62b8b3d3952ccedb33acb5c9559480b9
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.3
#
###

##
#
#  Namespace sshlib
#    Provides an encapsulated naming scope for sshlib functions and objects
#
##
namespace sshlib {

  ##
  # default set of handlers for ssh client
  ##
  global_var SSH_CLIENT_HANDLERS = make_array(
    PROTO_SSH_MSG_KEXINIT,          @client_cb_begin_kex,
    PROTO_SSH_MSG_KEXDH_REPLY,      @client_cb_finalize_kex,
    PROTO_SSH_MSG_KEXDH_GEX_REPLY,  @client_cb_finalize_kex,
    PROTO_SSH_MSG_NEWKEYS,          @client_cb_new_keys,

    PROTO_SSH_MSG_SERVICE_ACCEPT,   @client_cb_msg_service_accept,

    PROTO_SSH_MSG_USERAUTH_BANNER,        @client_cb_msg_userauth_banner,
    PROTO_SSH_MSG_USERAUTH_SUCCESS,       @client_cb_msg_userauth_success,
    PROTO_SSH_MSG_USERAUTH_INFO_REQUEST,  @client_cb_msg_userauth_info_request,
    PROTO_SSH_MSG_USERAUTH_FAILURE,       @client_cb_msg_userauth_failure,

    PROTO_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, @client_cb_channel_open_confirm,
    PROTO_SSH2_MSG_CHANNEL_OPEN_FAILURE,      @client_cb_channel_open_fail,
    PROTO_SSH2_MSG_CHANNEL_WINDOW_ADJUST,     @client_cb_channel_window_adjust,
    PROTO_SSH2_MSG_CHANNEL_DATA,              @client_cb_channel_data,
    PROTO_SSH2_MSG_CHANNEL_EXTENDED_DATA,     @client_cb_channel_extended_data,
    PROTO_SSH2_MSG_CHANNEL_EOF,               @client_cb_channel_eof,
    PROTO_SSH2_MSG_CHANNEL_CLOSE,             @client_cb_channel_close,
    PROTO_SSH2_MSG_CHANNEL_SUCCESS,           @client_cb_channel_success,
    PROTO_SSH2_MSG_CHANNEL_FAILURE,           @client_cb_channel_failure,
    PROTO_SSH2_MSG_CHANNEL_REQUEST,           @client_cb_channel_request,

    PROTO_SSH_MSG_GLOBAL_REQUEST, @client_cb_global_request,

    PROTO_SSH_MSG_DISCONNECT,      @client_cb_msg_disconnect,
    PROTO_SSH_MSG_IGNORE,          @client_cb_msg_ignore,
    PROTO_SSH_MSG_DEBUG,           @client_cb_msg_debug,

    PROTO_SSH_MSG_USERAUTH_GSSAPI_TOKEN,      @client_cb_userauth_gssapi_token,

    PROTO_SSH_MSG_USERAUTH_GSSAPI_ERROR,      @client_cb_userauth_gssapi_error,
    PROTO_SSH_MSG_USERAUTH_GSSAPI_ERRTOK,     @client_cb_userauth_gssapi_errtok,

    PROTO_SSH_MSG_UNIMPLEMENTED,   @client_cb_msg_unimplemented,

    -1, @client_cb_response_timeout
  );

  ##
  # sshrecv_until callbacks
  ##

  ##
  # Checks if the remote host has signaled that no more data will be sent
  # via a SSH_MSG_CHANNEL_EOF message
  #
  # @param <session>  An sshlib::session object
  # @param <channel>  A channel object for the current SSH connection
  # @return Returns TRUE if the remote has indicated that no more data will be sent over this channel
  # @category SSH
  ##
  function client_cb_check_channel_eof(session, channel)
  {
    return channel.remote_eof;
  }

  ##
  # Checks the current session to see if it is in a closed state.
  #
  # @param <session>  An sshlib::session object
  # @param <channel>  A channel object for the current SSH connection
  # @return Returns TRUE if the indicated session is closed, FALSE otherwise
  # @category SSH
  ##
  function client_cb_check_channel_closed(session, channel)
  {
    if(channel.state == CHANNEL_STATE_CLOSED)
      return TRUE;
    return FALSE;
  }

  ##
  # Checks if the remote host has accepted a channel request.
  #
  # @param <session>  An sshlib::session object
  # @param <channel>  A channel object for the current SSH connection
  # @return Returns TRUE if the remote host has sent a SSH_MSG_CHANNEL_OPEN_CONFIRMATION message indicating that it has opened a channel, otherwise returns FALSE.
  # @category SSH
  ##
  function client_cb_check_channel_not_pending(session, channel)
  {
    if(channel.state != CHANNEL_STATE_PENDING)
      return TRUE;
    return FALSE;
  }

  ##
  # Checks if a post-login error has occurred on the connection for AWS instances using public key authentication.
  # @param <session>  An sshlib::session object
  # @param <channel>  A channel object for the current SSH connection
  # @return Returns TRUE if a request to login as a different user or a post login error has occurred, otherwise returns FALSE.
  # @category SSH
  ##
  function client_cb_post_login_error(session, channel)
  {
    var fn = "client_cb_login_error";
    var text = session.error + channel.data_buf;
    if (
      ("Please login as the user" >< text && "rather than the user" >< text) ||
      "This account is currently not available" >< text ||
      "password has expired" >< text ||
      "could not get login name" >< text
    )
    {
      session.dbg_log(fn:fn, message:"Post-login error detected.");
      if("rather than the user" >< text || "not available" >< text)
        session.set_error("The host requested that login be performed" +
          " as a different user.");
      if("password has expired" >< text)
        session.set_error("The account password has expired.");
      session.found_post_login_error();
      return TRUE;
    }
    else return FALSE;
  }

  ##
  # packet handler callbacks
  ##

  ##
  # Handles timeouts during the receipt of SSH packets.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @category SSH
  ##
  function client_cb_response_timeout(session)
  {
    session.dbg_log(fn:'client_cb_response_timeout', level:DEBUG1,
                    message:'Entering handler.\n');
  }

  ##
  # Handles SSH_MSG_USERAUTH_BANNER messages that may contain a pre-login legal warning or informational message.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4252.txt to
  # @category SSH
  ##
  function client_cb_msg_userauth_banner(session)
  {
    session.dbg_log(fn:'client_cb_msg_userauth_banner', level:DEBUG1,
                    message:'Entering handler.\n');
    var userauth_banner = get_ssh_string(buffer:session.last_packet.payload, pos:0);
    if(strlen(userauth_banner) > 0)
      session.set_userauth_banner(userauth_banner);
  }

  ##
  # Handles SSH_MSG_CHANNEL_EXTENDED_DATA messages used to transmit alternate types of data such as
  # STDERR output.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_extended_data(session)
  {
    session.dbg_log(fn:'client_cb_channel_extended_data', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.handle_extended_data_recieved(sshpkt:session.last_packet);
  }

  ##
  # Handles SSH_MSG_DISCONNECT messages indicating the termination of the SSH connection.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_msg_disconnect(session)
  {
    session.dbg_log(fn:'client_cb_msg_disconnect', level:DEBUG1,
                    message:'Entering handler.\n');
    session.close_connection();
  }

  ##
  # Handles SSH_MSG_GLOBAL_REQUEST messages used to communicate requests that are not tied to a specific
  # channel.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_global_request(session)
  {
    var fn = 'client_cb_global_request';
    var req = get_ssh_string(buffer:session.last_packet.payload, pos:0);
    session.dbg_log(fn:fn, level:DEBUG1, message:'Entering handler.\n');

    if(req != '') session.dbg_log(fn:fn, level:DEBUG1,
        message:'Global request req = ' + req + '\n');

    session.sshsend(data:NULL, code:PROTO_SSH_MSG_REQUEST_FAILURE);
  }

  ##
  # Handles SSH_MSG_IGNORE messages.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_msg_ignore(session)
  {
    var fn = 'client_cb_msg_ignore';
    session.dbg_log(fn:fn, level:DEBUG1, message:'Entering handler.\n');
    session.dbg_log(fn:fn, level:DEBUG2, message:'Received SSH_MSG_IGNORE\n');
  }

  ##
  # Handles SSH_MSG_DEBUG messages that may contain information useful for debugging.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_msg_debug(session)
  {
    var fn = 'client_cb_msg_debug';
    session.dbg_log(fn:fn, level:DEBUG1, message:'Entering handler.\n');
    session.dbg_log(fn:fn, level:DEBUG2, message:'Received SSH_MSG_DEBUG\n');
  }

  ##
  # Handles SSH_MSG_UNIMPLEMENTED messages that indicate the receipt of an unrecognized message.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_msg_unimplemented(session)
  {
    var fn = 'client_cb_msg_unimplemented';
    session.dbg_log(fn:fn, level:DEBUG1, message:'Entering handler.\n');
    session.dbg_log(fn:fn, level:DEBUG2, message:'Received SSH_MSG_UNIMPLEMENTED\n');
    session.close_connection();

    exit(1, "Received SSH_MSG_UNIMPLEMENTED from remote SSH server.");
  }

  ##
  # Handles SSH_MSG_CHANNEL_DATA messages which are the primary SSH data transfer mechanism.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_data(session)
  {
    session.dbg_log(fn:'client_cb_channel_data', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);

    if (!isnull(channel)) channel.handle_data_recieved(sshpkt:session.last_packet);
  }

  ##
  # Handles SSH_MSG_CHANNEL_EOF messages that announce that the remote host will send no more data.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_eof(session)
  {
    session.dbg_log(fn:'client_cb_channel_eof', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.remote_eof();
  }

  ##
  # Handles SSH_MSG_CHANNEL_REQUEST messages which contain channel specific requests.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_request(session)
  {
    session.dbg_log(fn:'client_cb_channel_request', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.handle_request(sshpkt:session.last_packet);
  }

  ##
  # Handles SSH_MSG_CHANNEL_SUCCESS messages which accept a channel request.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_success(session)
  {
    session.dbg_log(fn:'client_cb_channel_success', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.set_response(TRUE);
  }

  ##
  # Handles SSH_MSG_CHANNEL_FAILURE messages which reject a channel request.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_failure(session)
  {
    session.dbg_log(fn:'client_cb_channel_failure', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.set_response(FALSE);
  }

  ##
  # Handles SSH_MSG_CHANNEL_WINDOW_ADJUST messages which contain how many bytes
  # we can send before we have to wait for another window size adjustment.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_window_adjust(session)
  {
    session.dbg_log(fn:'client_cb_channel_window_adjust', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.handle_window_adjust(sshpkt:session.last_packet);
  }

  ##
  # Handles SSH_MSG_CHANNEL_OPEN_CONFIRMATION messages, which accept a SSH_CHANNEL_OPEN request.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_open_confirm(session)
  {
    session.dbg_log(fn:'client_cb_channel_open_confirm', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.handle_channel_confirmation(sshpkt:session.last_packet);
  }

  ##
  # Handles SSH_MSG_CHANNEL_OPEN_FAILURE messages which reject a SSH_CHANNEL_OPEN request.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_open_fail(session)
  {
    session.dbg_log(fn:'client_cb_channel_open_fail', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);
    if (!isnull(channel)) channel.handle_channel_open_failure(sshpkt:session.last_packet);
    session.channel_manager.remove_channel(channel:channel);
  }

  ##
  # Handles SSH_MSG_CHANNEL_CLOSE messages sent by the remote host to close the channel.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function client_cb_channel_close(session)
  {
    session.dbg_log(fn:'client_cb_channel_close', level:DEBUG1,
                    message:'Entering handler.\n');
    var channel =
      session.channel_manager.packets_channel(sshpkt:session.last_packet);

    # Remove the channel from channel_manager before calling channel.close()
    # in case close_socket() gets called by sshsend() to clean up objects
    session.channel_manager.remove_channel(channel:channel);

    if (!isnull(channel) && channel.state != CHANNEL_STATE_CLOSED)
      channel.close();
  }

  ##
  # Handles SSH_MSG_SERVICE_ACCEPT messages which indicate support for a service requested with SSH_MSG_SERVICE_REQUEST
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_msg_service_accept(session)
  {
    session.dbg_log(fn:'client_cb_msg_service_accept', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("SERVICE_REQUEST_SUCCESS");
  }

  ##
  # Handles SSH_MSG_USERAUTH_SUCCESS messages, which indicates authentication success.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4252.txt
  # @category SSH
  ##
  function client_cb_msg_userauth_success(session)
  {
    session.dbg_log(fn:'client_cb_msg_success', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_SUCCESS");

    if(session.compression_alg_c_to_s == "zlib@openssh.com")
      session.enable_compression(mode:MODE_OUT);
    if(session.compression_alg_s_to_c == "zlib@openssh.com")
      session.enable_compression(mode:MODE_IN);
  }

  ##
  # Handles SSH_MSG_USERAUTH_FAILURE messages, which reject an authentication request.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4252.txt
  # @category SSH
  ##
  function client_cb_msg_userauth_failure(session)
  {
    session.dbg_log(fn:'client_cb_msg_userauth_failure', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_FAILURE");
  }

  ##
  # Handles SSH_MSG_USERAUTH_INFO_REQUEST and SSH_MSG_USERAUTH_PK_OK
  # messages which share the same SSH message id.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4256.txt and https://www.ietf.org/rfc/rfc4252.txt
  # @category SSH
  ##
  function client_cb_msg_userauth_info_request(session)
  {
    session.dbg_log(fn:'client_cb_msg_userauth_info_request', level:DEBUG1,
                    message:'Entering handler.\n');
    if(session.cur_state.val == "USERAUTH_GSSAPI_REQUEST")
      client_cb_userauth_gssapi_response(session:session);
    else if(session.cur_state.val == "USERAUTH_PK_REQUEST")
      client_cb_msg_userauth_pk_ok(session:session);
    else
      session.cur_state.set("USERAUTH_INFO_REQ");
  }

  ##
  # Handles SSH_MSG_USERAUTH_PK_OK messages accepting a public key presented for authentication.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4252.txt
  # @category SSH
  ##
  function client_cb_msg_userauth_pk_ok(session)
  {
    session.dbg_log(fn:'client_cb_msg_userauth_pk_ok', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_PK_OK");
  }

  ##
  # Handles SSH_MSG_USERAUTH_INFO_REQUEST messages sent to request information for authentication.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4256.txt
  # @category SSH
  ##
  function client_cb_userauth_gssapi_response(session)
  {
    session.dbg_log(fn:'client_cb_userauth_gssapi_response', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_GSSAPI_RESPONSE");
  }

  ##
  # Handles SSH_MSG_USERAUTH_GSSAPI_TOKEN messages, which request a MIC
  # to complete the gssapi-with-mic exchange.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4462.txt
  # @category SSH
  ##
  function client_cb_userauth_gssapi_token(session)
  {
    session.dbg_log(fn:'client_cb_userauth_gssapi_token', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_GSSAPI_TOKEN");
  }

  ##
  # Handles SSH_MSG_USERAUTH_GSSAPI_ERROR messages, which indicate a GSSAPI authentication failure.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4462.txt
  # @category SSH
  ##
  function client_cb_userauth_gssapi_error(session)
  {
    session.dbg_log(fn:'client_cb_userauth_gssapi_error', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_GSSAPI_ERROR");
  }

  ##
  # Handles SSH_MSG_USERAUTH_GSSAPI_ERRTOK messages, which indicate a GSSAPI authentication failure.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4462.txt
  # @category SSH
  ##
  function client_cb_userauth_gssapi_errtok(session)
  {
    session.dbg_log(fn:'client_cb_userauth_gssapi_errtok', level:DEBUG1,
                    message:'Entering handler.\n');
    session.cur_state.set("USERAUTH_GSSAPI_ERRTOK");
  }

  ##
  # Handles SSH_MSG_NEWKEYS messages, which provide parameters used to encrypt further communication.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_new_keys(session)
  {
    session.dbg_log(fn:'client_cb_new_keys', level:DEBUG1,
                    message:'Entering handler.\n');

    if(!session.new_cipherset)
      return session.close_socket(error:"Packet type 'SSH_MSG_NEWKEYS' was received before cipherset was established.");

    session.dbg_log(fn:'client_cb_new_keys', level:DEBUG1,
        message:'SSH_MSG_NEW_KEYS Received! Updating ciphers.\n');

    session.sshsend(data:NULL, code:PROTO_SSH_MSG_NEWKEYS);
    if(session.cur_state.val == "SOC_CLOSED")
      return session.set_error("Socket already closed when attempting to send SSH_MSG_NEW_KEYS packet.");

    # "zlib" compression method is enabled directly after NEWKEYS
    if(session.compression_alg_c_to_s == "zlib")
      session.enable_compression(mode:MODE_OUT);
    if(session.compression_alg_s_to_c == "zlib")
      session.enable_compression(mode:MODE_IN);

    # re-initialize streams if compression was enabled previously using zlib@openssh.com
    if(session.compression_enabled_c_to_s && "zlib@openssh.com" == session.compression_alg_c_to_s)
      session.enable_compression(mode:MODE_OUT);
    if(session.compression_enabled_s_to_c && "zlib@openssh.com" == session.compression_alg_s_to_c)
      session.enable_compression(mode:MODE_IN);

    # these are not likely to happen, but handle it here just in case
    if(session.compression_alg_c_to_s == "none" && session.compression_enabled_c_to_s)
      session.disable_compression(mode:MODE_OUT);
    if(session.compression_alg_s_to_c == "none" && session.compression_enabled_s_to_c)
      session.disable_compression(mode:MODE_IN);

    session.new_keys();
    session.cur_state.set("KEX_DONE");
  }

  ##
  # Handles SSH_MSG_KEXINIT messages, which acknowledge receipt of a SSH_MSG_KEXINIT and provide parameters for key exchange.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_begin_kex(session)
  {
    session.cur_state.set("KEX_BEGIN");

    session.dbg_log(fn:'client_cb_begin_kex', level:DEBUG1,
                    message:'Entering handler.\n');

    local_var pkt = session.last_packet;
    local_var remote_init = pkt.payload;
    local_var namelists = session.kex_handler.kex_pkt_parse_namelists(pkt);
    session.kex_handler.set_remote_cookie(substr(pkt.payload, 0, 15));

    session.kex_handler.set_remote_init_pkt(remote_init);
    _server_algo = pkt.raw;

    # Error parsing namelists
    if(isnull(namelists))
      return session.close_socket(error:"Error parsing key exchange name lists.");

    session.kex_handler.set_kex_recv_namelists(namelists);

    local_var namelist;
    local_var algo;
    foreach namelist (keys(session.kex_handler.kex_supported_namelists))
    {
      # we don't care about language, we'll connect to anything :)
      if("language" >< namelist) continue;
      algo = session.kex_handler.select_algorithm(namelist:namelist);

      if(!algo)
        return session.close_socket(error:"Server does not support algorithms in "+namelist);
      session.kex_handler.set_algorithm(namelist,algo);
    }

    session.kex_handler.generate_ssh_cookie();

    # send back our cookie + supported algorithms
    local_var init_pkt = session.kex_handler.our_cookie;
    foreach namelist (KEX_NAME_LISTS)
    {
      local_var nlist = session.kex_handler.kex_supported_namelists[namelist];

      if(isnull(nlist))
        nlist = "";
      init_pkt += mk_ssh_string(nlist);
    }

    init_pkt += crap(data:'\0', length:5); # boolean + uint32 (remaining fields)
    session.sshsend(data:init_pkt, code:PROTO_SSH_MSG_KEXINIT);
    if(session.cur_state.val == "SOC_CLOSED")
      return session.set_error("Socket already closed when attempting to send KEXINIT packet.");
    session.kex_handler.set_our_init_pkt(init_pkt);

    local_var cipherset;

    if(session.kex_handler.kex_alg =~ "^ecdh-sha2-")
    {
      local_var nid;
      if(session.kex_handler.kex_alg == "ecdh-sha2-nistp256") nid = curve_nid.nist.P256;
      if(session.kex_handler.kex_alg == "ecdh-sha2-nistp384") nid = curve_nid.nist.P384;
      if(session.kex_handler.kex_alg == "ecdh-sha2-nistp521") nid = curve_nid.nist.P521;
      if(!session.kex_handler.ecdh_gen_secret_key(nid:nid))
        return session.close_socket(error:'ecdh_gen_secret_key() failed.');

      cipherset = new("sshlib::cipherset");
      session.set_new_cipherset(cipherset);
      session.init_new_crypto();

      # transmit key in uncompressed format - see http://www.secg.org/sec1-v2.pdf sec. 2.3.3
      pkt = mk_ssh_string('\x04' + session.kex_handler.ecdh_local_pub.x + session.kex_handler.ecdh_local_pub.y);
      session.sshsend(data:pkt, code:PROTO_SSH_MSG_KEXDH_INIT);
    }
    else if(session.kex_handler.kex_alg != "diffie-hellman-group-exchange-sha1" && session.kex_handler.kex_alg != "diffie-hellman-group-exchange-sha256")
    {
      var dh_group = ereg_replace(pattern:"-[^-]+$", string:session.kex_handler.kex_alg, replace:"");
      local_var p = DH_CONSTANT_GROUP_P_AND_G[dh_group]["p"];
      local_var g = DH_CONSTANT_GROUP_P_AND_G[dh_group]["g"];

      cipherset = new("sshlib::cipherset");
      session.kex_handler.set_dh_groups(p:p, g:g);

      session.set_new_cipherset(cipherset);

      session.init_new_crypto();

      if(!session.kex_handler.dh_gen_key())
        return session.close_socket(error:'dh_gen_key() failed.');

      pkt = mk_ssh_mpint(session.kex_handler.dh_local_pub);
      session.sshsend(data:pkt,code:PROTO_SSH_MSG_KEXDH_INIT);
    }
    else
    {
      # Send group request
      pkt =
        # minimal size in bits of group
        mkdword(MIN_DH_GROUP_SIZE, order:BYTE_ORDER_BIG_ENDIAN) +
        # preferred size in bits of group
        mkdword(PRF_DH_GROUP_SIZE, order:BYTE_ORDER_BIG_ENDIAN) +
        # maximal size in bits of group
        mkdword(MAX_DH_GROUP_SIZE, order:BYTE_ORDER_BIG_ENDIAN);
      session.sshsend(data:pkt, code:PROTO_SSH_MSG_KEXDH_GEX_REQUEST);
    }
  }

  ##
  # Handles PROTO_SSH_MSG_KEXDH_REPLY and PROTO_SSH_MSG_KEXDH_GEX_REPLY messages, which provide parameters to compute a shared encryption key.
  #
  # @param <session>  An sshlib::session object
  # @return Returns NULL
  # @remark https://www.ietf.org/rfc/rfc4253.txt
  # @category SSH
  ##
  function client_cb_finalize_kex(session)
  {
    var fn = 'client_cb_finalize_kex';
    session.dbg_log(fn:fn, level:DEBUG1, message:'Entering handler.\n');

    if(isnull(session.new_cipherset) && (session.kex_handler.kex_alg == "diffie-hellman-group-exchange-sha1" || # still need p and g
                                         session.kex_handler.kex_alg == "diffie-hellman-group-exchange-sha256"))
    {
      session.dbg_log(fn:fn, level:DEBUG1,
          message:'obtaining p & g from group exchange [' + session.kex_handler.kex_alg + ']\n');

      var pkt = session.last_packet;

      local_var p, g, tmp, pos;
      tmp = get_ssh_mpint(buffer:pkt.payload, pos:0);

      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return session.close_socket(error:"Unable to parse DH base or modulus.");

      p = tmp['value'];
      pos = tmp['length'];

      tmp = get_ssh_mpint(buffer:pkt.payload, pos:pos);
      if(isnull(tmp) || empty_or_null(tmp['value']) || isnull(tmp['length']))
        return session.close_socket(error:"Unable to parse DH base or modulus.");

      g = tmp['value'];

      if(strlen(p) > (MAX_DH_GROUP_SIZE/8))
        return session.close_socket(error:"DH Modulus length (" +
          (strlen(p)*8) + " bits) is greater than maximum modulus length (" +
          MAX_DH_GROUP_SIZE + " bits).");

      if(strlen(p) < (MIN_DH_GROUP_SIZE/8))
        return session.close_socket(error:"DH Modulus length (" +
          (strlen(p)*8) + " bits) is less than minimum modulus length (" +
          MIN_DH_GROUP_SIZE + " bits).");

      if(isnull(g) || !strlen(g))
        return session.close_socket(error:"Invalid DH value for g.");

      session.dbg_log(fn:fn, level:DEBUG3,
          message:"p = " + hexstr(p) + '\n' + "g = " + hexstr(g) + '\n');

      session.kex_handler.set_dh_groups(p:p, g:g);
      local_var cipherset = new("sshlib::cipherset");

      session.set_new_cipherset(cipherset);

      session.init_new_crypto();

     if(!session.kex_handler.dh_gen_key())
        return session.close_socket(error:'dh_gen_key() failed.');

      pkt = mk_ssh_mpint(session.kex_handler.dh_local_pub);
      session.sshsend(data:pkt,code:PROTO_SSH_MSG_KEXDH_GEX_INIT);

      return NULL;
    }
    # this function will set session error message and return NULL if
    # there is a problem.  you might want to refactor this
    if(isnull(session.kex_handler.parse_host_cert()))
      return session.close_socket(error:"error parsing host certificate.");

    # If a certificate was provided by the server rather than a public key,
    # verify that the signature is valid
    if(!isnull(session.kex_handler.host_cert))
    {
      if(!session.kex_handler.verify_ssh_cert_signature(session.kex_handler.host_cert))
        return session.close_socket(error:"Invalid signature on " + session.kex_handler.server_host_key_alg + " host certificate.");
      else session.dbg_log(fn:fn, message:"Verified host certificate signature.");
    }

    if(!session.ignore_known_hosts)
    {
      if(!isnull(session.kex_handler.host_cert))
      {
        if(!session.kex_handler.verify_known_hosts(cert:session.kex_handler.host_cert))
          session.close_socket(error:"Verification of SSH server certificate against known_hosts failed.");
      }
      else
      {
        if(!session.kex_handler.verify_known_hosts(key:session.remote_host_key, key_type:session.kex_handler.auth_alg))
          session.close_socket(error:"Verification of SSH server public key against known_hosts failed.");
      }
    }
  }

  ##
  # Handles responses by the remote host to "exec" commands sent via an SSH_MSG_CHANNEL_REQUEST message
  #
  # @param <session>  An sshlib::session object
  # @return Returns TRUE if the remote host has closed the channel or the remote host does not support the command.  Otherwise it will return FALSE.
  # @remark https://www.ietf.org/rfc/rfc4254.txt
  # @category SSH
  ##
  function run_exec_command_cb(session, channel)
  {
    var fn = 'run_exec_command_cb';
    session.dbg_log(fn:fn, level:DEBUG3, message:'Entering handler.\n');

    # Check for pk-command-not-found prompt and close channel if found
    if ("install package" >< tolower(channel.data_buf) &&
        "to provide command" >< tolower(channel.data_buf))
    {
      session.set_cmd_error(chomp(channel.data_buf));
      session.set_cmd_error("Prompt to install missing command detected. "+
        "Closing channel.");
      channel.clear_data_buf();
      channel.close();
      return TRUE;
    }

    return client_cb_check_channel_closed(session:session, channel:channel);
  }


  ##
  # Callback function for rate limiting check. Determine if we are at a Juniper Junos prompt
  # or failed login attempt with Junos. Also checks if we are at another prompt to force quick
  # exit. Used in sshlib::try_ssh_kb_settings_login()
  #
  # @param session  An sshlib::session object
  # @param channel  An sshlib::channel object
  # @return Returns TRUE
  # @category SSH
  ##
  function rate_limiting_check_cb(session, channel)
  {
    var last6;
    if(strlen(channel.data_buf) == 0) last6 = " ";
    else if(strlen(channel.data_buf) < 6) last6 = channel.data_buf;
    else last6 = substr(channel.data_buf, strlen(channel.data_buf) - 6);

    if ("access denied" >< tolower(channel.data_buf))
      return TRUE;
    if ("junos" >< tolower(channel.data_buf))
      return TRUE;
    if ("juniper" >< tolower(channel.data_buf))
      return TRUE;
    if ("#" >< last6 || ">" >< last6 || "$" >< last6 || "%" >< last6)
      return TRUE;
  }


  ##
  # Callback function for rate limiting check. Determine if we are at a SonicWall password prompt
  # Used in sshlib::try_ssh_kb_settings_login()
  #
  # @param session  An sshlib::session object
  # @param channel  An sshlib::channel object
  # @return Returns TRUE
  # @category SSH
  ##
  function rate_limiting_check_password_prompt_cb(session, channel)
  {
    if ("password:" >< tolower(channel.data_buf))
    {
      return TRUE;
    }
  }

  ##
  # Callback function for rate limiting check. Determine if we are at a SonicWall prompt
  # Used in sshlib::try_ssh_kb_settings_login(). By the time this runs we already know
  # device is SonicWall.
  #
  # @param session  An sshlib::session object
  # @param channel  An sshlib::channel object
  # @return Returns TRUE
  # @category SSH
  ##
  function sonicwall_is_password_success_cb(session, channel)
  {
    var last6;
    if(strlen(channel.data_buf) == 0) last6 = " ";
    else if(strlen(channel.data_buf) < 6) last6 = channel.data_buf;
    else last6 = substr(channel.data_buf, strlen(channel.data_buf) - 6);

    if("must be changed" >< channel.data_buf)
    {
      return TRUE;
    }
    if(">" >< last6 && "access denied" >!< tolower(channel.data_buf))
    {
      return TRUE;
    }
  }
}
