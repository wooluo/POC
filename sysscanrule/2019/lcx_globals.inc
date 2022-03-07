#TRUSTED 82095bd1b74cf3d867237ba1305d68c4939ad3769586839d5fc5ea58dfbc16ad2b8c94598ef5b390f3e5ff56541d514544582ca4bca161707ca8ae879ad29958d9096c8880dbe0f4a42c3fa37eff9511bfd297cc7377bd0379732959652fc95c1f541b77f5ccaefc6bbe52356edadaf41f3d0dd7a262180e938700657fb08f7c4b66c92984bef94d0abe9794bbf201e611cd7cb3e48c1860340a12d0dd954f3d1c0090eb39a541775e65a60ddd09bbf255fed326a7f5e1b62647b52233f5ace268c96bd90d71b7c0b5ae416cb8754f1434f63ec2dafecb8e4cfda808828fec4fae5ad5dd4b13b85117c82f434f64371ad97e2caba0c9d1effe6fda4bce970c6ece9d97b8d5cd200a94cbfc0b0689261adfdfe3e6a8750ac0ac698aa74aaead0460ea7ad2b2c62b1f062a3df63deb3cfc3c068526bc56e227fda27e695e66b61a552d7aa8da5b4d6041869e5cffb4722626c7c41e4ae50aae959b12ce71f0817fdd3cbfde0b43e142afe92ff5ae40dbb632de08ea99932cc9a2adda617fc636debccdf6b8d1da7f5bf132e63dfcd2af6c1bec85f149ff32c73b92d1573612abec1b6e24c0b656c7b6c50f9769c4c9140b38c09cc664491e531bb639ec087ff27da5e5dbb27e69d9cbdfbbedd496c36c893bec3ae3f5c6c3d32c336df6512b22b7119cd0ad2b064df8114cfdc44865954477f43bd5b658a0889456d9dec00e3960
##
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.3
#
##

include("hostlevel_funcs.inc");

namespace lcx {

  # General globals

  ##
  # KB prefix for most local checks KB items
  ##
  global_var KB_PREFIX = "HostLevelChecks/";

  ##
  # KB prefix for third-party patch management checks
  ##
  global_var KB_PM_PREFIX = "ThirdPartyChecks/";

  ##
  # KB key for testing mode
  ##
  global_var KB_TESTING = KB_PREFIX + "testing_mode";

  ##
  # Global var (bool) for testing mode
  ##
  global_var TESTING = FALSE;
  if (get_kb_item(KB_TESTING)) TESTING = TRUE;

  ##
  # Name of plugin metadata cache table
  ##
  global_var _PLUGIN_TBL = "plugin_metadata";
  ##
  # Status of plugin metadata cache table initialization
  # Set by _plugin_tbl_has_inited()
  ##
  global_var _PLUGIN_TBL_INIT;

  ##
  # Name of thirdparty auth results table
  ##
  global_var _AUTH_RESULTS_TBL = "patch_management_auth_results";
  ##
  # Status of third-party patch management auth results table initialization
  # Set by _auth_results_tbl_has_inited()
  ##
  global_var _AUTH_RESULTS_TBL_INIT;

  ##
  # KB key for local checks protocol
  ##
  global_var KB_PROTO = KB_PREFIX + "proto";
  ##
  # KB key for account used for local checks
  ##
  global_var KB_LOGIN = KB_PREFIX + "login";
  ##
  # KB prefix for reports
  ##
  global_var KB_REPORT = KB_PREFIX + "reports/";

  # Protocols

  ##
  # Global var for SMB protocol
  ##
  global_var PROTO_SMB = 1;
  ##
  # Global var for SSH protocol
  ##
  global_var PROTO_SSH = 2;
  ##
  # Global var for SNMP protocol
  ##
  global_var PROTO_SNMP = 3;
  ##
  # Global var for NTP protocol
  ##
  global_var PROTO_NTP = 4;
  ##
  # Global var for RSH protocol
  ##
  global_var PROTO_RSH = 5;
  ##
  # Global var for REXEC protocol
  ##
  global_var PROTO_REXEC = 6;
  ##
  # Global var for RLOGIN protocol
  ##
  global_var PROTO_RLOGIN = 7;
  ##
  # Global var for Telnet protocol
  ##
  global_var PROTO_TELNET = 8;
  ##
  # Global var for localhost/pread()
  ##
  global_var PROTO_LOCAL = 9;
  ##
  # Global var for HTTP protocol
  ##
  global_var PROTO_HTTP = 10;
  ##
  # Global var for HTTPS protocol
  ##
  global_var PROTO_HTTPS = 11;
  ##
  # Global var for HTTP/HTTPS protocol (could be either)
  ##
  global_var PROTO_HTTP_S = 12;
  ##
  # Global var for SOAP protocol
  ##
  global_var PROTO_SOAP = 13;
  ##
  # Global var for IBM iSeries IBMI protocol
  ##
  global_var PROTO_IBMI = 14;
  ##
  # Array of protocol names
  ##
  global_var PROTO_NAMES = make_list();
  PROTO_NAMES[PROTO_SMB]    = "SMB";
  PROTO_NAMES[PROTO_SSH]    = "SSH";
  PROTO_NAMES[PROTO_SNMP]   = "SNMP";
  PROTO_NAMES[PROTO_NTP]    = "NTP";
  PROTO_NAMES[PROTO_RSH]    = "RSH";
  PROTO_NAMES[PROTO_REXEC]  = "REXEC";
  PROTO_NAMES[PROTO_RLOGIN] = "RLOGIN";
  PROTO_NAMES[PROTO_TELNET] = "TELNET";
  PROTO_NAMES[PROTO_LOCAL]  = "LOCALHOST";
  PROTO_NAMES[PROTO_HTTP]   = "HTTP";
  PROTO_NAMES[PROTO_HTTPS]  = "HTTPS";
  PROTO_NAMES[PROTO_HTTP_S] = "HTTP/HTTPS";
  PROTO_NAMES[PROTO_SOAP]   = "SOAP";
  PROTO_NAMES[PROTO_IBMI]   = "iSeries";
  ##
  # Array of protocol globals
  ##
  global_var PROTO_GLOBALS = make_array(
    "SMB",        PROTO_SMB,
    "SSH",        PROTO_SSH,
    "SNMP",       PROTO_SNMP,
    "NTP",        PROTO_NTP,
    "RSH",        PROTO_RSH,
    "REXEC",      PROTO_REXEC,
    "RLOGIN",     PROTO_RLOGIN,
    "TELNET",     PROTO_TELNET,
    "LOCALHOST",  PROTO_LOCAL,
    "HTTP",       PROTO_HTTP,
    "HTTPS",      PROTO_HTTPS,
    "HTTP/HTTPS", PROTO_HTTP_S,
    "SOAP",       PROTO_SOAP,
    "iSeries",    PROTO_IBMI
  );
  ##
  # Array of info_t globals to lcx globals
  # (Initialized below namespace)
  ##
  global_var INFO_T_TO_LCX = make_list();

  # Third-party patch management products
  global_var PM_PROD_VCENTER = 1;

  global_var PM_PROD_NAMES = make_list();
  PM_PROD_NAMES[PM_PROD_VCENTER] = "VMware vCenter";

  global_var PM_PROD_GLOBALS = make_array(
    PM_PROD_NAMES[PM_PROD_VCENTER], PM_PROD_VCENTER
  );

  # Issue types

  ##
  # Issue type for local checks / patch mgmt error issues
  # - Always reported by hostlevel_check_failed.nasl
  # - May be cleared by certain plugins on success
  #
  # Example: Required command failed with an error, access error
  # preventing local checks from being enabled
  ##
  global_var ISSUES_ERROR    = 1;
  global_var PM_ISSUES_ERROR = 6;
  ##
  # Issue type for local checks / patch mgmt informational issues
  # - Always reported by hostlevel_checks_skipped.nasl
  #
  # Examples: Local checks unavailable, auth OK but unidentified OS
  ##
  global_var ISSUES_INFO    = 2;
  global_var PM_ISSUES_INFO = 7;
  ##
  # Issue type for general service issues - complete failure to
  # connect to the service and authenticate
  # - Generally logged by primary authentication plugins:
  #   ssh_get_info2.nasl, ssh_get_info.nasl, smb_login.nasl, etc
  # - Only reported by hostlevel_check_failed.nasl if ISSUES_ERROR
  #   type issues are also reported or the KB item
  #   Host/local_checks_enabled is NOT set
  #
  # Examples: A protocol error prevented authentication, none of the
  # provided credentials were successful
  ##
  global_var ISSUES_SVC     = 3;
  global_var PM_ISSUES_SVC  = 8;
  ##
  # Issue type for individual errors encountered during authentication
  # attempts by any plugin throughout the scan
  # - Only reported by host_credentials_failed.nasl if there is not
  #   successful auth on the same proto/port
  # - Only reported by authentication_success_intermittent_failure.nasl
  #   if there is successful auth on the same proto/port by the same
  #   user
  # - May be cleared for a proto/port/user on successful auth
  #
  # Examples: Auth failure, KEX failure, protocol failure, failure
  # to open a socket AFTER successful auth has been established on
  # the port
  ##
  global_var ISSUES_AUTH    = 4;
  global_var PM_ISSUES_AUTH = 9;
  ##
  # Issue type for logging auth success - not really an "issue", but
  # uses the same logging framework
  # - Generally logged by primary authentication plugins:
  #   ssh_get_info2.nasl, ssh_get_info.nasl, smb_login.nasl, etc
  # - Reported by authentication_success*.nasl plugins
  ##
  global_var AUTH_SUCCESS    = 5;
  global_var PM_AUTH_SUCCESS = 10;
  ##
  # List of issue types
  # Leaving out AUTH_SUCCESS since it isn't really an issue, it just
  # borrows the framework
  ##
  global_var ISSUES = [
    ISSUES_ERROR,
    ISSUES_INFO,
    ISSUES_SVC,
    ISSUES_AUTH
  ];
  global_var PM_ISSUES = [
    PM_ISSUES_ERROR,
    PM_ISSUES_INFO,
    PM_ISSUES_SVC,
    PM_ISSUES_AUTH
  ];

  # KB Prefixes for issues

  ##
  # KB prefix for local checks / patch mgmt error issues
  ##
  global_var KB_ISSUES_ERROR    = KB_PREFIX + "issues/error/";
  global_var KB_PM_ISSUES_ERROR = KB_PM_PREFIX + "issues/error/";
  ##
  # KB prefix for local checks / patch mgmt informational issues
  ##
  global_var KB_ISSUES_INFO     = KB_PREFIX + "issues/info/";
  global_var KB_PM_ISSUES_INFO  = KB_PM_PREFIX + "issues/info/";
  ##
  # KB prefix for service issues
  ##
  global_var KB_ISSUES_SVC      = KB_PREFIX + "issues/svc/";
  global_var KB_PM_ISSUES_SVC   = KB_PM_PREFIX + "issues/svc/";
  ##
  # KB prefix for auth issues
  ##
  global_var KB_ISSUES_AUTH     = KB_PREFIX + "issues/auth/";
  global_var KB_PM_ISSUES_AUTH  = KB_PM_PREFIX + "issues/auth/";
  ##
  # KB prefix for auth successes
  ##
  global_var KB_AUTH_SUCCESS    = KB_PREFIX + "auth_success/";
  global_var KB_PM_AUTH_SUCCESS = KB_PM_PREFIX + "auth_success/";
  ##
  # Array of issue types to KB prefixes
  ##
  global_var KB_ISSUES = make_list();
  KB_ISSUES[ISSUES_ERROR]  = KB_ISSUES_ERROR;
  KB_ISSUES[ISSUES_INFO]   = KB_ISSUES_INFO;
  KB_ISSUES[ISSUES_SVC]    = KB_ISSUES_SVC;
  KB_ISSUES[ISSUES_AUTH]   = KB_ISSUES_AUTH;
  KB_ISSUES[AUTH_SUCCESS]  = KB_AUTH_SUCCESS;

  global_var KB_PM_ISSUES = make_list();
  KB_PM_ISSUES[PM_ISSUES_ERROR]  = KB_PM_ISSUES_ERROR;
  KB_PM_ISSUES[PM_ISSUES_INFO]   = KB_PM_ISSUES_INFO;
  KB_PM_ISSUES[PM_ISSUES_SVC]    = KB_PM_ISSUES_SVC;
  KB_PM_ISSUES[PM_ISSUES_AUTH]   = KB_PM_ISSUES_AUTH;
  KB_PM_ISSUES[PM_AUTH_SUCCESS]  = KB_PM_AUTH_SUCCESS;

  # Other globals

  ##
  # Store debugging logs to facilitate unit testing
  ##
  global_var DBG_LOG = make_list();
  ##
  # The built-in global SCRIPT_NAME is sometimes unreliable
  # in namespace functions
  ##
  global_var THIS_SCRIPT = SCRIPT_NAME;
  ##
  # Standardized var for unknown items
  ##
  global_var UNKNOWN = "unknown";
}

# Initializing outside namespace as a workaround for issue with
# unreliable globals inside namespaces
lcx::INFO_T_TO_LCX[INFO_LOCAL]  = lcx::PROTO_LOCAL;
lcx::INFO_T_TO_LCX[INFO_SSH]    = lcx::PROTO_SSH;
lcx::INFO_T_TO_LCX[INFO_RSH]    = lcx::PROTO_RSH;
lcx::INFO_T_TO_LCX[INFO_REXEC]  = lcx::PROTO_REXEC;
lcx::INFO_T_TO_LCX[INFO_RLOGIN] = lcx::PROTO_RLOGIN;
lcx::INFO_T_TO_LCX[INFO_TELNET] = lcx::PROTO_TELNET;
