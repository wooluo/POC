#TRUSTED 54d83cd4420aea33a14b1407c4ed7badee11ea45c9efb5b111f2b75a55b142bde8220b5d825877db33245db3279b0e1ad116c1107b9f1b5b9d37bb13fd7e97179a490c3fb933a3ee5f7fee5c72c26858329ebf5f7b7a4dbc120071f951c7414d96654b392416548ad7d86e6774c9d112c957baeb17660494cfc4d40c20bcf85d15816aa50312177d8bdcbc6837ef7ef9635a4976dd30e5022c7547b56077717b0755dd5cf4f3c0d5a48f87256e09b51ab4e05c2ffae14520e0b96f432e08911092807431b2161899ba33f76e8d76271e853da1eb4e18d780b0748a097e7378f05a757ef96faf9d2fc28c4b475688d4853fd6c0593140bb9a193a1806ca61d1094ddf0936347b141dbd8d073b25f32ddd0be9e0a7869668b400de06f649c5550815f8bc1d4050577ab2345fe08cec6db56c5543c464b080906256f0b4064af0f7e76db7a59d2f095fd5c9d2d0873c292fa582ec5f0de894357353dcbf2f32e861280d2c5f2ef2aecda16f9d5afe509ffad320a0da9672f1a2644b382647665f8d35868f58c42062db0388c71dbc3e4a7bcc8b3ee928f6d7f826c3c7ec57080cfc84c2d2fd82f7a184e7a11b7b7fae0a1fc6d56e9df15a480ac21e9bc055510f2571524d1f210a41bc44103f18ec9f7396b9055916523d420d926b9656100ea434e4a9778126a613ed4aa2cf2026e12456ffc671465b17ea93f4413e58ea5a4e76

###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.0
#
###

include("datetime.inc");
include("dump.inc");
include("spad_log_func.inc");

namespace dbg {

  ##
  # General debugging template. Formats debugging message and forwards
  # to spad_log().
  #
  # @param [src:string] The message source, e.g. "mssql_starttls" or
  #                     "ssl_supported_ciphers.nasl"
  # @param [msg:string] The message to log
  # @param [ddata:data] The data to dump to hex/ascii and append
  #
  # @return NULL
  ##
  function log(src, msg, ddata)
  {
    if (!get_kb_item("global_settings/enable_plugin_debugging"))
      return NULL;

    var out = "";

    # If we're running in CLI mode add timestamp
    if(isnull(get_preference("plugins_folder")))
      out += strftime("[%F %T] ",unixtime());

    # Add source, assume function if not nasl or nbin
    if (src)
    {
      out += src;
      var l = strlen(src);
      if (src !~ '\\.(nasl|nbin)$' && substr(src, l-2, l-1) != "()")
        out += "()";
      out += ": ";
    }

    # Add message
    out += msg;

    # Add ddata
    if (ddata)
    {
      out += '\n' + hexdump(ddata:ddata);
    }

    spad_log(message:out);
    return NULL;
  }

  ##
  # Translates socket error code into description string
  #
  # @anonparam [int] Error code returned from socket_get_error()
  #
  # @return [string] Description of the error
  ##
  function soc_strerr()
  {
    var err = _FCT_ANON_ARGS[0];
    if (isnull(err)) return "error code missing";

    var e = int(err);
    if (e == NOERR) return "no error";
    if (e == ETIMEDOUT) return "operation timed out";
    if (e == ECONNRESET) return "connection reset by peer";
    if (e == EUNREACH) return "host unreachable";
    if (e == EUNKNOWN) return "unknown error";
    if (e == ESSL) return "SSL error";
    if (e == EINPROGRESS) return "operation in progress";
    if (e == ECONNREFUSED) return "connection refused";
    if (e == ENOBUFS) return "no buffer space available";
    return "unknown error code: "+err;
  }

}
