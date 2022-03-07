#TRUSTED ab4d8fea3c4c1c7ff3c7fd9a3892c5dfb1c8cb0140257023debe929481b92ffbb53441468d762cbd01b3aa6ec9ca7d877f72f39098180a192a6f63110cb9b0352b8f524b4089bd3769ffe435fb47716227a4668352ef7d0ea4fb092a1c7bea8e3c6bb5076fdb34a4babda6428e97bce7e30e3f3c293d9de4a07fcf01cdce47ebb4434c7d06f868313f1daac977b6ceb1a80129575d27525ca71ffb7a5ce7b1429e038129941b9a406dcdb141b852a836cd24cb8d616c1bf41dcea34ad4c92ad497282d44df2fa1d75dc449a22a22f8dbf27dae57b3b3d965b6b9df01976a3af4b6537af9e0e8601592c9f58feade1bb330ac9001fccefff72fd774c6d696ff62150f0ede1e8b886c0e8cb6903b76ff9dbf3012cb41ab88897a7d07d385213ca90062cd6ef256c858c9051a3b7fff6e4f6d108a1abe3f1037ac08d8dadd96861028ed03d11106bec890a9d79b56b5198e8877507a1d94f658f61fd24223abe3381b52d806b810b3b0871903f934f7697f1c733db57093f4af136cb2439432d77be44e88bbd6b92645b113b06a07d4ca3b39600e4f8f78d40ceee24dd2c666f02655fa3c5a379078cee81009b5464713c267b981f12282ac8c7c62e590e27c9113d4ede7f09fe21cf74ff1853702055df62f3e0d065487f04d752e0bc397a0b343c7a20de8175cc5f4a5c38703df700e585371ef02dbc4051622c1e99ac54a50d3
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# Revision 1.10
#

include("audit_nlib.inc");

###
# Some applications implement custom protocols that support StartTLS.
# This library contains functions that will initiate StartTLS
# connections for such non-standard protocols. This will prevent
# having code occur in both a *_starttls.nasl plugin, and the
# open_sock_ssl() function in ssl_funcs.inc.
###

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection in StartTLS mode.
##
function amqp_starttls(encaps, socket)
{
  local_var line, port, req, res, ver;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # We need to get the version from the KB, which is stored by port.
  if (!defined_func("get_peer_name"))
    return NULL;
  port = get_peer_name(socket);
  if (isnull(port) || isnull(port[1]))
    return NULL;
  port = port[1];

  ver = get_kb_item("amqp/" + port + "/protocol/version");
  if (isnull(ver))
    return NULL;
  ver = split(ver, sep:".", keep:FALSE);

  # Send command to request StartTLS negotiation.
  req = raw_string(
    "AMQP",      # Magic cookie
    2,           # Protocol ID
    int(ver[0]), # Major version number
    int(ver[1]), # Minor version number
    int(ver[2])  # Revision number
  );
  send(socket:socket, data:req);

  # Receive response, which should be identical to our request.
  res = recv(socket:socket, min:8, length:128);
  if (res != req)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @remark A full library exists for this protocol, but only for NBINs.
#
# @remark This function spawns a child that MITMs the connection to
#         wrap/unwrap SSL messages during the handshake.
#
# @return A connection in StartTLS mode.
##
function mssql_starttls(encaps, socket)
{
  local_var enc, hdr, id, inner, len, middle, outer, pair, pos, ppid;
  local_var req, rec, recs, res, socket_error, state, type;
  var middle_pending, outer_pending;
  var fn = "mssql_starttls";

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Track the packet's ID, a sequence number.
  id = 0;

  # Create pre-login request.
  req = raw_string(
    18,                # Type (Pre-login message)
    0x01,              # Status (End of message)
    0x00, 0x2F,        # Length
    0x00, 0x00,        # SPID
    id++,              # PacketID
    0x00,              # Window

    0,                 # PL_OPTION_TOKEN (VERSION)
    0x00, 0x1A,        # Offset of field
    0x00, 0x06,        # Length of field

    1,                 # PL_OPTION_TOKEN (ENCRYPTION)
    0x00, 0x20,        # Offset of field
    0x00, 0x01,        # Length of field

    2,                 # PL_OPTION_TOKEN (INSTOPT)
    0x00, 0x21,        # Offset of field
    0x00, 0x01,        # Length of field

    3,                 # PL_OPTION_TOKEN (THREADID)
    0x00, 0x22,        # Offset of field
    0x00, 0x04,        # Length of field

    4,                 # PL_OPTION_TOKEN (MARS)
    0x00, 0x26,        # Offset of field
    0x00, 0x01,        # Length of field

    0xFF,              # PL_OPTION_TOKEN (TERMINATOR)

    16, 0, 0, 0, 0, 0, # VERSION
    0,                 # ENCRYPTION
    0,                 # INSTOPT
    "TNBL",            # THREADID
    0                  # MARS
  );

  # Send the pre-login request.
  send(socket:socket, data:req);

  # Receive response, ensuring it is large enough to hold the header
  # (8 bytes) and the terminator (1 byte).
  res = recv(socket:socket, min:9, length:1024);
  if (isnull(res) || strlen(res) < 9)
    return NULL;

  # Perform simple validation on the response.
  # Note: A fragmented packet will fail here.
  len = strlen(res);
  if (
    getbyte(blob:res, pos:0) != 4 ||
    getbyte(blob:res, pos:1) != 1 ||
    getword(blob:res, pos:2) != len
  ) return NULL;

  # Parse out the encryption field.
  pos = 8;
  enc = NULL;
  while (pos < len)
  {
    type = getbyte(blob:res, pos:pos);

    # Stop parsing if we hit the terminator.
    if (type == 0xFF)
      break;

    # Parse the ENCRYPTION field.
    if (type == 1)
    {
      if (pos + 1 >= len)
        break;
      pos = getword(blob:res, pos:pos + 1);

      if (pos >= len)
        break;
      enc = getbyte(blob:res, pos:pos);

      break;
    }

    pos += 5;
  }

  # Check if encryption is unsupported by the server.
  if (isnull(enc) || enc == 2)
    return NULL;

  # Remember who the parent is, so that the child can exit when the
  # parent does.
  ppid = getpid();

  # Set things up as follows:
  #   parent <-> inner|middle <-> child <-> outer
  pair = socketpair();
  if (isnull(pair))
  {
    ssl_dbg(src:fn,ppid:ppid,msg:'socketpair() returned NULL. ' +
      'Performance may be degraded.');
    return NULL;
  }
  inner = pair[0];
  middle = pair[1];
  outer = socket;

  # Fork, transferring ownership of the middle and outer sockets to
  # the child. If we're on the parent side of the fork, continue as
  # normal with the inner socket.
  ssl_dbg(src:fn, msg:'Forking child process to handle SSL over TDS.');
  if (fork(middle, outer) != 0)
  {
    # Check if the caller just wants the command sent, or if they want
    # the entire negotiation done.
    if (!encaps)
    {
      ssl_dbg(src:fn, msg:'Encapsulation not specified, returning '+
        'socket '+inner+' to parent for negotiation.');
      return inner;
    }

    if (!defined_func("socket_negotiate_ssl"))
      return NULL;

    ssl_dbg(src:fn, msg:'Returning socket_negotiate_ssl(socket:'+
      inner+', transport:'+encaps+') ('+ENCAPS_NAMES[encaps]+') '+
      'to parent.');
    return socket_negotiate_ssl(socket:inner, transport:encaps);
  }

  # According to the MS-TDS document, v20130118, section 3.3.5.3:
  #
  #   A TLS/SSL negotiation packet is a PRELOGIN (0x12) packet header
  #   encapsulated with TLS/SSL payload. The TDS server MUST exchange
  #   TLS/SSL negotiation packet with the client and reenter this
  #   state until the TLS/SSL negotiation is successfully completed.
  #
  # So what we're going to do is read in each SSL packet during the
  # handshake, mangling each, and then stop interfering once the
  # handshake is finished.
  #
  # Since both the parent and the child are waiting the same timeout
  # length, the child needs to know the sequence of a handshake,
  # otherwise it will wait one timeout period too long and the parent
  # will fail a recv() call. The indicators of switching state are:
  #
  #   middle:
  #     ClientHello      = send to outer immediately
  #     ChangeCipherSpec = send to outer after next record
  #
  #   outer:
  #     ChangeCipherSpec = send to middle after next record
  #
  # We can avoid more complex state logic on the outer socket because
  # the records are wrapped and we know the exact length, avoiding
  # needless waiting.

  state = make_array("middle", "start", "outer", "start");

  ssl_dbg(src:fn,ppid:ppid,msg:'Child process starting main loop.');
  while (TRUE)
  {
    socket_error = socket_get_error(middle);
    if (isnull(socket_error))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'socket_get_error() ' +
        'returned NULL for socket '+middle+'. Breaking main loop.');
      break;
    }
    if (socket_error != NOERR && socket_error != ETIMEDOUT)
    {
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:
        'Error on socket '+middle+': '+dbg::soc_strerr(socket_error)+
        '. Breaking main loop.');
      break;
    }
    middle_pending = socket_pending(middle);
    if (isnull(middle_pending))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'socket_pending() ' +
        'returned NULL for socket '+middle+'. Breaking main loop.');
      break;
    }
    if (middle_pending)
    {
      # Collect all the SSL records available from the parent.
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Socket '+middle+' is pending.'+
        ' Collecting SSL records from parent.');
      if (state["middle"] != "application-data")
      {
        recs = "";
        ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Entering loop for SSL ' +
          'negotiation.');
        while (TRUE)
        {
          rec = recv_ssl(socket:middle);
          if (isnull(rec))
          {
            ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Done receiving ' +
              'from parent, breaking SSL negotiation loop.');
            break;
          }
          ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Received SSL record'+
            ' from parent:',ddata:rec);
          recs += rec;

          if (state["middle"] == "start")
          {
            rec = ssl_find(
              blob:recs,
              "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
              "handshake_type", SSL3_HANDSHAKE_TYPE_CLIENT_HELLO
            );
            if (!isnull(rec))
            {
              ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Received handshake ' +
                'message from parent, updating state to "after-hello"'+
                ' and breaking SSL negotiation loop.');
              state["middle"] = "after-hello";
              break;
            }
          }
          else if (state["middle"] == "after-hello")
          {
            rec = ssl_find(
              blob:rec, encrypted:FALSE,
              "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
            );
            if (!isnull(rec))
            {
              ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Received change-' +
                'cipher-spec message from parent, updating state to '+
                '"change-cipher-spec" and breaking SSL negotiation ' +
                'loop.');
              state["middle"] = "change-cipher-spec";
              break;
            }
          }
          else if (state["middle"] == "change-cipher-spec")
          {
            ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'SSL negotiation ' +
              'complete, updating state to "application-data" and ' +
              'breaking SSL negotiation loop.');
            state["middle"] = "application-data";
            break;
          }
        } # End of inner loop

        if (recs)
        {
          # Wrap data from middle -> outer.
          # Note: If OpenSSL ever sends 4088+ bytes, this will fail.
          len = 8 + strlen(recs);

          hdr = raw_string(
            18,          # Type (Pre-login message)
            0x01,        # Status (End of message)
            mkword(len), # Length
            0x00, 0x00,  # SPID
            id++,        # PacketID
            0x00         # Window
          );

          ssl_dbg(src:fn,ppid:ppid,msg:'Adding TDS header:',ddata:hdr);
          ssl_dbg(src:fn,ppid:ppid,msg:'Forwarding wrapped SSL ' +
            'records from parent to target.');
          send(socket:outer, data:hdr + recs);
        }
      }
      else
      {
        ssl_dbg(src:fn,ppid:ppid,msg:'Receiving and forwarding SSL ' +
          'record from parent to target.');
        # Pass an SSL record through unmolested.
        rec = recv_ssl(socket:middle);
        if (isnull(rec))
        {
          ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Did not receive an SSL '+
            'record from parent, breaking main loop.');
          break;
        }

        send(socket:outer, data:rec);
      }
    }

    socket_error = socket_get_error(outer);
    if (isnull(socket_error))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'socket_get_error() returned '+
        'NULL for socket '+outer+'. Breaking main loop.');
      break;
    }
    if (socket_error != NOERR && socket_error != ETIMEDOUT)
    {
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:
        'Error on socket '+outer+': '+dbg::soc_strerr(socket_error)+
        '. Breaking main loop.');
      break;
    }
    outer_pending = socket_pending(outer);
    if (isnull(outer_pending))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'socket_pending() ' +
        'returned NULL for socket '+outer+'. Breaking main loop.');
      break;
    }
    if (outer_pending)
    {
      # Collect SSL records from the target
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Socket '+outer+' is pending.'+
        ' Collecting SSL records from target.');
      if (state["outer"] != "application-data")
      {
        ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Entering loop for SSL ' +
          'negotiation.');
        recs = "";
        while (TRUE)
        {
          # Read the TDS pre-login packet header.
          hdr = recv(socket:outer, length:8, min:8);
          if (hdr) ssl_dbg(src:fn,ppid:ppid,face:"t",msg:
            'Received TDS header from target:',ddata:hdr);
          if (isnull(hdr) || strlen(hdr) != 8 || getbyte(blob:hdr, pos:0) != 18)
          {
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'TDS header is NULL or '+
              'invalid, breaking SSL negotiation loop.');
            break;
          }

          # Parse out the length of the packet body.
          len = getword(blob:hdr, pos:2) - 8;

          # Read the body of the TDS packet.
          res = recv(socket:outer, length:len, min:len);
          if (res) ssl_dbg(src:fn,ppid:ppid,face:"t",msg:
            'Received packet body from target:',ddata:res);
          if (isnull(res) || strlen(res) != len)
          {
            recs = "";
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Did not receive TDS '+
              'packet body, breaking SSL negotiation loop.');
            break;
          }
          recs += res;

          # Check if we've received all the fragments of the TDS message.
          if ((getbyte(blob:res, pos:1) & 0x1) == 1)
          {
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Finished receiving TDS'+
              ' packet fragments, breaking SSL negotiation loop.');
            break;
          }
        } # End of inner loop

        if (!recs)
        {
          ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'No SSL records received '+
            'for SSL negotiation, breaking main loop.');
          break;
        }

        # Send all the unwrapped records to the parent.
        ssl_dbg(src:fn,ppid:ppid,msg:'Forwarding unwrapped SSL records '+
            'from target to parent.');
        send(socket:middle, data:recs);

        # Transition our state.
        if (state["outer"] == "start")
        {
          recs = ssl_find(
            blob:rec, encrypted:FALSE,
            "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
          );
          if (!isnull(recs))
          {
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Received "change-'+
              'cipher-spec", updating state to "change-cipher-spec".');
            state["outer"] = "change-cipher-spec";
          }
        }
        else if (state["outer"] == "change-cipher-spec")
        {
          ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'SSL negotiation ' +
            'complete, updating state to "application-data".');
          state["outer"] = "application-data";
        }
      }
      else
      {
        # Pass an SSL record through unmolested.
        ssl_dbg(src:fn,ppid:ppid,msg:'Receiving and forwarding SSL ' +
          'record from target to parent.');
        rec = recv_ssl(socket:outer);
        if (isnull(rec))
        {
          ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Did not receive an SSL '+
            'record from target, breaking main loop.');
          break;
        }

        send(socket:middle, data:rec);
      }
    }

    # Check if the parent has exited.
    if (wait(pid:ppid, nonblock:TRUE) == -1)
    {
      ssl_dbg(src:fn,ppid:ppid,msg:'Parent process is no longer running, '+
        'breaking main loop.');
      break;
    }
  }

  # Clean up our sockets.
  ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Closing parent socket '+
    middle+'.');
  close(middle);
  ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Closing target socket '+
    outer+'.');
  close(outer);

  # Exit silently.
  ssl_dbg(src:fn,ppid:ppid,msg:'Child process exiting.');
  exit(0);
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection in StartTLS mode.
##
function nut_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Send command to request StartTLS negotiation.
  send(socket:socket, data:'STARTTLS\r\n');

  # Receive response.
  line = recv_line(socket:socket, length:1024);
  if (line !~ "^OK STARTTLS")
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Prepares RDP server to accept a TLS connection
#
# @param socket Existing TCP connection to the RDP server.
# @param encaps SSL version to use when making an SSL/TLS connection
# @return a socket or NULL
# @remark
#   - If encaps is null and the function returns a socket, an SSL/TLS connection is not made, but
#     the server is the state to accept an SSL/TLS handshake.
#   - If encaps is not null and the function returns a socket, an SSL/TLS connection is made with the specified encapsulation.
#   - Negotiation-based SSL is supported in Windows Server 2003 and later.
#   - Direct (no negotiation) SSL is supported in later Windows OSes (ie Windows Server 2008)
#   - Caller should use encaps TLSv1 or later, as Windows RDP server doesn't support SSLv3
#
##
function rdp_starttls(encaps, socket)
{
  local_var data, len, req, res, type;

  req =
    # TPKT Header [T.123]
    '\x03' + # version number (always 0000 0011)
    '\x00' + # reserved (always 0)
    '\x00\x13' + # Length (including header) - big endian

    # Connection request TPDU
    '\x0e' +        # LI (length indicator)
    '\xe0' +        # CR (1110) + CDT (0000 = class 0 or 1)
    '\x00\x00' +    # DST REF (always 0)
    '\x00\x00' +    # SRC REF
    '\x00' +        # Class option (class 0)

    # RDP negotiation request
    '\x01' +            # RDP_NEG_REQ
    '\x00' +            # Flags (must be 0)
    '\x08\x00' +        # Length (must be 8) - little endian
    '\x03\x00\x00\x00'; # PROTOCOL_SSL | PROTOCOL_HYBRID

  send(socket:socket, data: req);

  res = recv(socket:socket, length:19, timeout:60);
  if(isnull(res)) return NULL;

  # Check length:
  # - Server supportting security protocol negotiation should return 19-byte response per  http://msdn.microsoft.com/en-us/library/cc240501.aspx, section 2.2.1.2
  # - Server (ie. on XP) not supportting negotiation returns a shorter response; these RDP servers are known to not support SSL
  if(strlen(res) != 19)
    return NULL;

  # Parse RDP_NEG_RSP or RDP_NEG_FAILURE
  type  = ord(res[11]);
  len   = ord(res[13]) | (ord(res[14]) << 8);
  data  = ord(res[15]) | (ord(res[16]) << 8) | (ord(res[17]) << 16) | (ord(res[18]) << 24); # selected proto for RDP_NEG_RSP or error code for RDP_NEG_FAILURE

  # RDP_NEG_RSP and RDP_NEG_FAILURE must be 8 bytes per protocol spec
  if(len != 8)
    return NULL;

  # Successful response (RDP_NEG_RSP)
  if(type == 2)
  {
    # We requested PROTOCOL_SSL|PROTOCOL_HYBRID, and should get either one of them
    if (data != 1 && data != 2)
      return NULL;

    # Establish a TLS connection if caller requests it
    if(! isnull(encaps) && encaps != ENCAPS_IP)
      return socket_negotiate_ssl(socket: socket, transport: encaps);
    else
      return socket;

  }
  # Error response (RDP_NEG_FAILURE)
  # possible causes:
  #   - RDP server configured to use only RDP legacy security
  #   - RDP server not configured/assigned a certificate for SSL
  else if(type == 3)
    return NULL;
  # Unknown response; unlikely to reach here
  else
    return NULL;
}

#----------------------------------------------------------------#
# Function    : ircd_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
#               'exit_on_fail' => if specified, exit on a        #
#                 failure rather than returning NULL.            #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (ircd_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function ircd_starttls(socket, encaps, exit_on_fail)
{
  local_var req, resp, s, ssl_socket;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  req = 'STARTTLS\r\n';
  send(socket:socket, data:req);

  resp = "";
  while(s = recv_line(socket:socket, length:2048))
  {
    s = chomp(s);
    # 670 is STARTTLS success
    # 691 is explicit STARTTLS failure/not supported
    # no response is STARTTLS not supported
    if(s =~ "^[^ ]+ (670|691) ")
    {
      resp = s;
      break;
    }
  }

  if (resp && resp =~ "^[^ ]+ 670 ")
  {
    if (encaps)
    {
      if (!defined_func("socket_negotiate_ssl"))
      {
        if (exit_on_fail) audit(AUDIT_FN_UNDEF, "socket_negotiate_ssl");
        else return NULL;
      }
      ssl_socket = socket_negotiate_ssl(socket:socket, transport:encaps);
      if (isnull(ssl_socket) && exit_on_fail) exit(1, "Failed to negotiate an SSL / TLS connection after sending a STARTTLS command.");
      else return ssl_socket;
    }
    return socket;
  }

  if (exit_on_fail) exit(1, "The IRC server did not send back a valid response to a STARTTLS command.");
  else return NULL;
}


##
# Initiate a PostgreSQL StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection to a PostgreSQL server in StartTLS mode.
##
function postgresql_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # The PostgreSQL startls command - '1234' msw + '5679' lsw -
  # https://www.postgresql.org/docs/9.2/static/protocol-message-formats.html
  var starttls = '\x00\x00\x00\x08\x04\xD2\x16\x2F';

  # Send command to request StartTLS negotiation.
  send(socket:socket, data:starttls);

  # Receive response - 'S' means success, 'N' means SSL not available.
  res = recv(socket:socket, length:1, timeout:60);
  if (res !~ "S")
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Vmware port 902 Start TLS call
# This will initialize the connection to vmaware's port 902
# which takes in an initial starttls like connection before
# accepting ssl connections
#
# 
#
##
function vmware_902_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Receive response.
  line = recv_line(socket:socket, length:1024);
  if (line !~ "^220 VMware Authentication Daemon Version" && "SSL Required" >!< line)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;
  
  return socket_negotiate_ssl(socket:socket, transport:encaps);
}
