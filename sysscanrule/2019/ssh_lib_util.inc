#TRUSTED a598d331ac2fe8567e771c464531632a5d7bd8c3a985913086fe3d43a78e766be8a6a333b2cd3653284d1cea9cd21811f68172767499a1a76e4723fad26b6b41bf1528988007933eea7d70dcae23dc4850189af9f2b280c067d2856907b346ce811196fd51326d3401b0f14ed25ccf7cd928a84243d648278bc73e92ea503ec18a66458f2e6e4fbb907aa806599adcc49acab80b8e98e9e2d451ecf9a943ecf5d1e9fc4b512ad14ea4df4e30783a24e3e866d5cb183a141ff5d8f21b59cc2161c5e2b0cb7bcefb2b4dda1890c4cd42c6118e5ca6141367c6a380881c6964290a45e82e4bd0113e8135cca134019d7a95ac1f2170fd9edb9c4e10954c0dd85cd9fe8d211ef3da76be827eab928e31dd81cf8e63c69161a5f4baf4f07fee1fd7814a0a28331a9024b32b04d4713db108cf5a47883a6d42db534ac2c6bce9dc4197d1c36312e5c933c47a9be99ada3fd0f39899c8d3a4e20220e8a7dc0095b65ebe9690fc780b549d0eb555370ab0017f76255f32babcbde2cf406f6626078aa7a7d3661bc6e2b4fe062d40a3b4d38cf48a55221edac508e4c0a396fa6f04baf17ba01723456004d4fc1e81a722e76e97438a7dcc5ac9ca78ebb4b9f078574e466aa3cb41fbe777d889cf478a76e6b50b028e113a479a522787f0fb46cadb54044e336da5113c9226ac29c95cac1ed4fc8f0698370323e80c650fd41695a6df9411

###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.3
#
# <at:var at:name="NOGPL" />
#
###

# Engine variable not available in GizaNE < 6.6
if(nasl_level() < 6600)
  global_var EACCES = 8;

# Global vars also used by ssh_func.inc
global_var KEY_LEN;
global_var _server_algo;

namespace sshlib {

  #######################################################################
  # Global constants                                                    #
  #######################################################################
  global_var SSH_LIB_LOGIN_ERROR              = 1;
  global_var SSH_LIB_SUPPORTS_LOGIN           = 2;
  global_var SSH_LIB_SUPPORTS_COMMANDS        = 3;
  global_var SSH_LIB_LOCAL_CHECKS_ERROR       = 4;
  global_var SSH_LIB_LOCAL_CHECKS_UNAVAILABLE = 5;
  global_var SSH_LIB_SUPPORTS_LOCAL_CHECKS    = 6;

  global_var HOST_SUPPORT_LEVEL            = NULL;
  global_var HOST_SUPPORTS_LOGIN           = 2;
  global_var HOST_SUPPORTS_COMMANDS        = 3;
  global_var HOST_LOCAL_CHECKS_ERROR       = 4;
  global_var HOST_LOCAL_CHECKS_UNAVAILABLE = 5;
  global_var HOST_SUPPORTS_LOCAL_CHECKS    = 6;

  global_var MODE_IN  = 0;
  global_var MODE_OUT = 1;

  global_var DEBUG1 = 1;
  global_var DEBUG2 = 2;
  global_var DEBUG3 = 3;
  global_var DEBUG_DISABLED = 0;

  global_var SSH_LIB_ONLY_ESCL_PRIVS_IF_NEEDED = FALSE;
  global_var TAP_MODE = FALSE;

  global_var Z_PARTIAL_FLUSH;

  global_var SSH_LIB_KB_PREFIX = "SSH/";
  global_var NOSETUP = "nosetup";

  ssh2_packet_type_labels = make_array (
    -1,  "NO_MSG_RECV_TIMEOUT",

    1,   "PROTO_SSH_MSG_DISCONNECT",
    2,   "PROTO_SSH_MSG_IGNORE",
    3,   "PROTO_SSH_MSG_UNIMPLEMENTED",
    4,   "PROTO_SSH_MSG_DEBUG",

    5,   "PROTO_SSH_MSG_SERVICE_REQUEST",
    6,   "PROTO_SSH_MSG_SERVICE_ACCEPT",

    20,  "PROTO_SSH_MSG_KEXINIT",
    21,  "PROTO_SSH_MSG_NEWKEYS",

    # KEX/GEX Codes
    30,  "PROTO_SSH_MSG_KEXDH_INIT",
    31,  "PROTO_SSH_MSG_KEXDH_REPLY",
    32,  "PROTO_SSH_MSG_KEXDH_GEX_INIT",
    33,  "PROTO_SSH_MSG_KEXDH_GEX_REPLY",
    34,  "PROTO_SSH_MSG_KEXDH_GEX_REQUEST",

    # GSSAPI codes
    60,  "PROTO_SSH_MSG_USERAUTH_GSSAPI_RESPONSE",
    61,  "PROTO_SSH_MSG_USERAUTH_GSSAPI_TOKEN",
    63,  "PROTO_SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE",
    64,  "PROTO_SSH_MSG_USERAUTH_GSSAPI_ERROR",
    65,  "PROTO_SSH_MSG_USERAUTH_GSSAPI_ERRTOK",
    66,  "PROTO_SSH_MSG_USERAUTH_GSSAPI_MIC",

    # Auth Codes
    50,  "PROTO_SSH_MSG_USERAUTH_REQUEST",
    51,  "PROTO_SSH_MSG_USERAUTH_FAILURE",
    52,  "PROTO_SSH_MSG_USERAUTH_SUCCESS",
    53,  "PROTO_SSH_MSG_USERAUTH_BANNER",
    60,  "PROTO_SSH_MSG_USERAUTH_INFO_REQUEST",
    61,  "PROTO_SSH_MSG_USERAUTH_INFO_RESPONSE",

    80,  "PROTO_SSH_MSG_GLOBAL_REQUEST",

    # RFC 4254, section 9.
    81,  "PROTO_SSH_MSG_GLOBAL_REQUEST",
    81,  "PROTO_SSH_MSG_REQUEST_SUCCESS",

    82,  "PROTO_SSH_MSG_REQUEST_FAILURE",

    # Channel codes
    90,  "PROTO_SSH2_MSG_CHANNEL_OPEN",
    91,  "PROTO_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION",
    92,  "PROTO_SSH2_MSG_CHANNEL_OPEN_FAILURE",
    93,  "PROTO_SSH2_MSG_CHANNEL_WINDOW_ADJUST",
    94,  "PROTO_SSH2_MSG_CHANNEL_DATA",
    95,  "PROTO_SSH2_MSG_CHANNEL_EXTENDED_DATA",
    96,  "PROTO_SSH2_MSG_CHANNEL_EOF",
    97,  "PROTO_SSH2_MSG_CHANNEL_CLOSE",
    98,  "PROTO_SSH2_MSG_CHANNEL_REQUEST",
    99,  "PROTO_SSH2_MSG_CHANNEL_SUCCESS",
    100, "PROTO_SSH2_MSG_CHANNEL_FAILURE"
);

  global_var PROTO_SSH_MSG_DISCONNECT                        = 1;
  global_var PROTO_SSH_MSG_IGNORE                            = 2;
  global_var PROTO_SSH_MSG_UNIMPLEMENTED                     = 3;
  global_var PROTO_SSH_MSG_DEBUG                             = 4;

  global_var PROTO_SSH_MSG_SERVICE_REQUEST                   = 5;
  global_var PROTO_SSH_MSG_SERVICE_ACCEPT                    = 6;

  global_var PROTO_SSH_MSG_KEXINIT                           = 20;
  global_var PROTO_SSH_MSG_NEWKEYS                           = 21;

  # KEX/GEX Codes
  global_var PROTO_SSH_MSG_KEXDH_INIT                        = 30;
  global_var PROTO_SSH_MSG_KEXDH_REPLY                       = 31;
  global_var PROTO_SSH_MSG_KEX_DH_GEX_GROUP                  = 31;
  global_var PROTO_SSH_MSG_KEXDH_GEX_INIT                    = 32;
  global_var PROTO_SSH_MSG_KEXDH_GEX_REPLY                   = 33;
  global_var PROTO_SSH_MSG_KEXDH_GEX_REQUEST                 = 34;

  # GSSAPI codes
  global_var PROTO_SSH_MSG_USERAUTH_GSSAPI_RESPONSE          = 60;
  global_var PROTO_SSH_MSG_USERAUTH_GSSAPI_TOKEN             = 61;
  global_var PROTO_SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
  global_var PROTO_SSH_MSG_USERAUTH_GSSAPI_ERROR             = 64;
  global_var PROTO_SSH_MSG_USERAUTH_GSSAPI_ERRTOK            = 65;
  global_var PROTO_SSH_MSG_USERAUTH_GSSAPI_MIC               = 66;

  # Auth Codes
  global_var PROTO_SSH_MSG_USERAUTH_REQUEST                  = 50;
  global_var PROTO_SSH_MSG_USERAUTH_FAILURE                  = 51;
  global_var PROTO_SSH_MSG_USERAUTH_SUCCESS                  = 52;
  global_var PROTO_SSH_MSG_USERAUTH_BANNER                   = 53;
  global_var PROTO_SSH_MSG_USERAUTH_INFO_REQUEST             = 60;
  global_var PROTO_SSH_MSG_USERAUTH_INFO_RESPONSE            = 61;
  global_var PROTO_SSH_MSG_USERAUTH_PASSWD_CHANGEREQ         = 60;
  global_var PROTO_SSH_MSG_USERAUTH_PK_OK                    = 60;

  # RFC 4254, section 9.
  global_var PROTO_SSH_MSG_GLOBAL_REQUEST                    = 80;
  global_var PROTO_SSH_MSG_REQUEST_SUCCESS                   = 81;

  global_var PROTO_SSH_MSG_REQUEST_FAILURE                   = 82;
  # Channel codes
  global_var PROTO_SSH2_MSG_CHANNEL_OPEN                     = 90;
  global_var PROTO_SSH2_MSG_CHANNEL_OPEN_CONFIRMATION        = 91;
  global_var PROTO_SSH2_MSG_CHANNEL_OPEN_FAILURE             = 92;
  global_var PROTO_SSH2_MSG_CHANNEL_WINDOW_ADJUST            = 93;
  global_var PROTO_SSH2_MSG_CHANNEL_DATA                     = 94;
  global_var PROTO_SSH2_MSG_CHANNEL_EXTENDED_DATA            = 95;
  global_var PROTO_SSH2_MSG_CHANNEL_EOF                      = 96;
  global_var PROTO_SSH2_MSG_CHANNEL_CLOSE                    = 97;
  global_var PROTO_SSH2_MSG_CHANNEL_REQUEST                  = 98;
  global_var PROTO_SSH2_MSG_CHANNEL_SUCCESS                  = 99;
  global_var PROTO_SSH2_MSG_CHANNEL_FAILURE                  = 100;

  # RFC 4253 Section 6.1
  global_var MAX_PACKET_SIZE = 35000;

# from RFC 4254
  global_var PTY_OPT_TTY_OP_END = 0; # Indicates end of options.
  global_var PTY_OPT_VINTR = 1; # Interrupt character; 255 if none.  Similarly for the other characters.  Not all of these characters are supported on all systems.
  global_var PTY_OPT_VQUIT = 2; # The quit character (sends SIGQUIT signal on POSIX systems).
  global_var PTY_OPT_VERASE = 3; # Erase the character to left of the cursor.
  global_var PTY_OPT_VKILL = 4; # Kill the current input line.
  global_var PTY_OPT_VEOF = 5; # End-of-file character (sends EOF from the terminal).
  global_var PTY_OPT_VEOL = 6; # End-of-line character in addition to carriage return and/or linefeed.
  global_var PTY_OPT_VEOL2 = 7; # Additional end-of-line character.
  global_var PTY_OPT_VSTART = 8; #Continues paused output (normally control-Q).
  global_var PTY_OPT_VSTOP = 9; # Pauses output (normally control-S).
  global_var PTY_OPT_VSUSP = 10; # Suspends the current program.
  global_var PTY_OPT_VDSUSP = 11; # Another suspend character.
  global_var PTY_OPT_VREPRINT = 12; # Reprints the current input line.
  global_var PTY_OPT_VWERASE = 13; # Erases a word left of cursor.
  global_var PTY_OPT_VLNEXT = 14; # Enter the next character typed literally, even if it is a special character
  global_var PTY_OPT_VFLUSH = 15; # Character to flush output.
  global_var PTY_OPT_VSWTCH = 16; # Switch to a different shell layer.
  global_var PTY_OPT_VSTATUS = 17; # Prints system status line (load, command, pid, etc).
  global_var PTY_OPT_VDISCARD = 18; # Toggles the flushing of terminal output.

  global_var PTY_OPT_IGNPAR = 30; # The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
  global_var PTY_OPT_PARMRK = 31; # Mark parity and framing errors.
  global_var PTY_OPT_INPCK = 32; # Enable checking of parity errors.
  global_var PTY_OPT_ISTRIP = 33; # Strip 8th bit off characters.
  global_var PTY_INLCR = 34; # Map NL into CR on input.
  global_var PTY_IGNCR = 35; # Ignore CR on input.
  global_var PTY_ICRNL = 36; # Map CR to NL on input.
  global_var PTY_IUCLC = 37; # Translate uppercase characters to lowercase.
  global_var PTY_IXON  = 38; # Enable output flow control.
  global_var PTY_IXANY = 39; # Any char will restart after stop.
  global_var PTY_IXOFF = 40; # Enable input flow control.
  global_var PTY_IMAXBEL = 41; # Ring bell on input queue full.

  global_var PTY_OPT_ISIG = 50; # Enable signals INTR, QUIT, [D]SUSP.
  global_var PTY_OPT_ICANON = 51; # Canonicalize input lines.
  global_var PTY_OPT_XCASE = 52; # Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".
  global_var PTY_OPT_ECHO = 53; # Enable echoing.
  global_var PTY_OPT_ECHOE = 54; # Visually erase chars.
  global_var PTY_OPT_ECHOK = 55; # Kill character discards current line.
  global_var PTY_OPT_ECHONL = 56; # Echo NL even if ECHO is off.
  global_var PTY_OPT_NOFLSH = 57; # Don't flush after interrupt.
  global_var PTY_OPT_TOSTOP = 58; # Stop background jobs from output.
  global_var PTY_OPT_IEXTEN = 59; # Enable extensions.
  global_var PTY_OPT_ECHOCTL = 60; # Echo control characters as ^(Char).
  global_var PTY_OPT_ECHOKE = 61; # Visual erase for line kill.
  global_var PTY_OPT_PENDIN = 62; # Retype pending input.

  global_var PTY_OPT_OPOST = 70; # Enable output processing.
  global_var PTY_OPT_OLCUC = 71; # Convert lowercase to uppercase.
  global_var PTY_OPT_ONLCR = 71; # Map NL to CR-NL.
  global_var PTY_OPT_OCRNL = 72; # Translate carriage return to newline (output).
  global_var PTY_OPT_ONOCR = 73; # Translate newline to carriage return-newline (output).
  global_var PTY_OPT_ONLRET = 74; # Newline performs a carriage return (output).

  global_var PTY_OPT_PTY_OPT_CS7 = 90; # 7 bit mode.
  global_var PTY_OPT_CS8 = 91; # 8 bit mode.
  global_var PTY_OPT_PARENB = 92; # Parity enable.
  global_var PTY_OPT_PARODD = 93; # Odd parity, else even.

  global_var PTY_OPT_TTY_OP_ISPEED = 128; # Specifies the input baud rate in bits per second.
  global_var PTY_OPT_TTY_OP_OSPEED = 129; # Specifies the output baud rate in bits per second.

  global_var DEFAULT_PTY_SIZE_PIXELS = make_list(640, 480);
  global_var DEFAULT_PTY_SIZE_CHARS = make_list(80, 24);
  global_var DEFAULT_PTY_OPTS = make_array(
    PTY_OPT_ECHO, mkdword(1, order:BYTE_ORDER_BIG_ENDIAN),
    PTY_OPT_OCRNL, mkdword(0, order:BYTE_ORDER_BIG_ENDIAN)
  );
  global_var DEFAULT_PTY_TERM = "vt100";

  #######################################################################
  # General utility functions                                           #
  #######################################################################

  ##
  # Extracts length prefixed string from ssh packet buffer
  #
  # @param <buffer> Buffer to extract string from
  # @param <pos> Position in buffer where length prefixed string is located
  # @return Returns extracted string
  # @category SSH
  ##
  function get_ssh_string(buffer, pos)
  {
    local_var len, ret, fn;
    fn = 'get_ssh_string';

    if(pos + 4 > strlen(buffer))
      return NULL;
    len = getdword(blob:buffer, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
    if(isnull(len))
      return NULL;
    if(len == 0)
      return "";
    pos += 4;
    if(pos + len > strlen(buffer))
      return NULL;
    
    return substr(buffer, pos, pos + len - 1);;
  }

  ##
  # Extracts length-prefixed multiple precision integer (mpint) in ssh packet.
  # buffer. See rfc4251 section 5 for details. 
  #
  # @param <buffer> Buffer to extract mpint from
  # @param <pos> Position in buffer where mpint is located
  # @returns array with length and value of mpint
  # @category SSH
  ##
  function get_ssh_mpint(buffer, pos)
  {
    local_var len, ret, fn, first;
    fn = 'get_ssh_mpint';
    ret = make_array();

    if(pos + 4 > strlen(buffer))
      return NULL;
    len = getdword(blob:buffer, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
    if(isnull(len))
      return NULL;
    if(len == 0)
      return "";
    pos += 4;
    if(pos + len > strlen(buffer))
      return NULL;

    ret['value'] = substr(buffer, pos, pos + len - 1);
    ret['length'] = strlen(ret['value']) + 4;
    
    first = getbyte(blob:ret['value'], pos:0);

    if(first == 0)
    {
      ret['value'] = substr(ret['value'], 1);
    }

    return ret;
  }

  ##
  # Builds length prefixed ssh string
  # See rfc4251 section 5 for details 
  #
  # @anonparam <First> String
  # @return encoded SSH length-prefixed string
  # @category SSH
  ##
  function mk_ssh_string()
  {
    local_var buffer;
    buffer = _FCT_ANON_ARGS[0];
    return mkdword(strlen(buffer), order:BYTE_ORDER_BIG_ENDIAN) + buffer;
  }

  ##
  # Normalizes mpint by removing leading 0x00  
  # @anonparam <First> mpint string to normalize
  # @return normalized mpint
  # @category SSH
  ##
  function normalize_mpint()
  {
    local_var mpint;
    mpint = _FCT_ANON_ARGS[0];
    if(getbyte(blob:mpint, pos:0) == 0)
      return substr(mpint, 1);
    return mpint;
  }

  ##
  # Builds length-prefixed multiple precision integer (mpint) string.
  # See rfc4251 section 5 for details. 
  #
  # @param <buffer> raw string containing mpint
  # @return string with prefix-length encoded mpint
  # @category SSH
  ##
  function mk_ssh_mpint(buffer)
  {
    local_var len;

    if (isnull(buffer))
      buffer = _FCT_ANON_ARGS[0];

    if (ord(buffer[0]) & 0x80)
      len = mkdword(strlen(buffer) + 1, order:BYTE_ORDER_BIG_ENDIAN) +
        mkbyte(0);
    else
      len = mkdword(strlen(buffer), order:BYTE_ORDER_BIG_ENDIAN);

    return len + buffer;
  }

  ##
  # A utility function for converting integers into the (/[0-9+/|/)
  # notation used to specify alternative kb items.
  #
  # @anonparam integer index
  # @return kb index string
  # @category SSH
  ##
  function kb_index()
  {
    local_var j;
    j = _FCT_ANON_ARGS[0];
    if (j < 0) return '/';
    else return '/'+j+'/';
  }

  ##
  # A utility function for removing escape sequences to clean up
  # data before it is returned to the plugin.
  #
  # @anonparam string s
  # @return string sanitized data
  # @category SSH
  ##
  function remove_escape_sequences()
  {
    local_var s;

    s = _FCT_ANON_ARGS[0];

    if ('\x1b' >!< s || '\x00' >< s)
      return s;

    s = ereg_replace(pattern:'\x1b\\[[0-9]+(;[0-9]+)?[A-Za-z]', replace:'', string:s);
    s = ereg_replace(pattern:'\x1b\\[\\?[0-9]+[A-Za-z]', replace:'', string:s);
    s = ereg_replace(pattern:'\x1b\\[[mK]', replace:'', string:s);
    s = ereg_replace(pattern:'\x1b=\x0d', replace:'', string:s);
    s = ereg_replace(pattern:'\x1b\x3e', replace:'', string:s);
    s = ereg_replace(pattern:'\x1b[0-9]*E', replace:'\n', string:s);

    return s;
  }
}
