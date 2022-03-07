#TRUSTED 27f8e710d29243cee9d7a77dbffc3f854331e28d4df5812ac8707b1aaa09f5f1dc398c0767ef7cfbdafc55210947d5e9189cc81b67f95c1e0ea4dc2e91f39f08bea99478e02368d1b68a96b275105d04cb678f34b4cfa63e0e06e98eaa1b40ee16d6e0e87da7a3eeda84fb177a423b2dd4a5f0e704b1139cd7d0dc402268152d9f610cfd5d10c873e0cef8c44fcb59a064e68bf56b83e385cdcb9a8726994929585d43992edc476f30616047fd6286a6a47457ec19e712c0ed16324450220004e13983e1af893e5e27b011788889dc59dd38b8b0bf4709160987d1f5d1f57ed02f3195bbc53cb41b4d6e32e44e9b0d6d998d29f9bff572f95d90266d7d4b729c735aca9f162ccfc1324379acb3d7e91e9a265ad138cf0721f4b66fde80ffb52ec75aacaa3290e28c0dc0e9deebc570a41b8fbb0f3c3167fa456a1cacb711c8b5215e41f0085ad988722fe1ccb40e02de0b3a1ebec9314df95784466f34c3b59f5c29f198f7d0a97eafb86a00a9fb117c91925902fd4fec00e38c2faf2634655c5e5ff28a7ccd839a067e8d5b294594a78d48f59a2eb7e3d46fa43bd9cc61f23e916f78926f4e208bea6311275ffa9fa6db7138cb2a785a365c2dec85b15d3b5353de4d1f8bcf7a3ca59e7a777c457e29548e00e0bfa4e47bf80123601212a0745ce05728f2c3119fab71ba590385253abc742918598b01ccc1491c0ec1ebf46c
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.4
#
###

##
# Track if the table (ssh_cmd_log_json) is created for logging SSH commands in JSON format.
##
global_var ssh_command_log_table_built = FALSE;

_SCRIPT_NAME = SCRIPT_NAME;

namespace sshlib
{
  object cmd_logger
  {
    ##
    # Constructor function for cmd_logger object
    #
    # @return implicit NULL return
    # @category SSH
    # @GizaNE 6.0
    ##
    function cmd_logger()
    {
      query_scratchpad(
        "CREATE TABLE IF NOT EXISTS ssh_cmd_log(
         plugin text,
         cmd text,
         md5 text,
         response text,
         error text,
         ran_with_priv_escl integer,
         forced_escl integer,
         failed_needs_escl integer,
         priv_escl_failed integer,
         user text,
         escl_user text,
         escl_method text,
         emulated integer
       );");

      query_scratchpad(
        "CREATE TABLE IF NOT EXISTS ssh_always_escl(
          cmd_md5 text
         );");
    }

    ##
    # Add log for SSH command including response, user, and escalation information.
    #
    # @param cmd Executed command
    # @param response Command response
    # @param error Associated error message
    # @param ran_with_priv_escl Boolean ran with privilege escalation
    # @param forced_escl Boolean privilege escalation forced
    # @param failed_needs_escl Boolean command failed needs privilege escalation
    # @param priv_escl_failed Boolean privilege escalation failed
    # @param user Login username
    # @param escl_user Escalation username
    # @param escl_method Escalation method
    #
    # @return NULL
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function add(cmd, escl_cmd, response, error, ran_with_priv_escl,
      forced_escl, failed_needs_escl, priv_escl_failed, user,
      escl_user, escl_method, emulated)
    {
      if(!cmd) return NULL;

      var resp = response;
      if (!isnull(resp)) resp = chomp(substr(response, 0, 512));
      else resp = "";

      if(!error) error = "";
      else error = chomp(string_reverse(chomp(string_reverse(error))));

      if(!ran_with_priv_escl) ran_with_priv_escl = 0;
      else ran_with_priv_escl = 1;

      if(!forced_escl) forced_escl = 0;
      else forced_escl = 1;

      if(!failed_needs_escl) failed_needs_escl = 0;
      else failed_needs_escl = 1;

      if(!priv_escl_failed) priv_escl_failed = 0;
      else priv_escl_failed = 1;

      if(!user) user = "";
      if(!escl_user) escl_user = "";
      if(!escl_method) escl_method = "";
      if(!escl_cmd) escl_cmd = "";
      if(!emulated) emulated = 0;

      var md5 = hexstr(MD5(cmd));

      query_scratchpad(
        "INSERT INTO ssh_cmd_log VALUES(
         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", _SCRIPT_NAME, cmd,
        md5, resp, error, ran_with_priv_escl, forced_escl, failed_needs_escl,
        priv_escl_failed, user, escl_user, escl_method, emulated);

      if(ran_with_priv_escl)
        query_scratchpad("INSERT INTO ssh_always_escl VALUES (?);", md5);

      log_command_and_response(
        cmd                : cmd,
        escl_cmd           : escl_cmd,
        response           : response,
        error              : error,
        ran_with_priv_escl : ran_with_priv_escl,
        forced_escl        : forced_escl,
        failed_needs_escl  : failed_needs_escl,
        priv_escl_failed   : priv_escl_failed,
        user               : user,
        escl_user          : escl_user,
        escl_method        : escl_method,
        emulated           : emulated
      );
    }

    ##
    #  Log error for SSH command including response, user, and escalation information.
    #
    # @param cmd Executed command
    # @param response Command response
    # @param error Associated error message
    # @param ran_with_priv_escl Boolean ran with privilege escalation
    # @param forced_escl Boolean privilege escalation forced
    # @param failed_needs_escl Boolean command failed needs privilege escalation
    # @param priv_escl_failed Boolean privilege escalation failed
    # @param user Login username
    # @param escl_user Escalation username
    # @param escl_method Escalation method
    #
    # @return NULL
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function log_error(cmd, response, error, ran_with_priv_escl,
      escl_cmd, forced_escl, failed_needs_escl, priv_escl_failed, user,
      escl_user, escl_method)
    {
      if(!cmd) return NULL;

      if(!ran_with_priv_escl) ran_with_priv_escl = 0;
      else ran_with_priv_escl = 1;

      if(!forced_escl) forced_escl = 0;
      else forced_escl = 1;

      if(!failed_needs_escl) failed_needs_escl = 0;
      else failed_needs_escl = 1;

      if(!priv_escl_failed) priv_escl_failed = 0;
      else priv_escl_failed = 1;

      if(!user) user = "";
      if(!escl_user) escl_user = "";
      if(!escl_method) escl_method = "";
      if(!escl_cmd) escl_cmd = "";

      log_command_and_response(
        cmd                : cmd,
        escl_cmd           : escl_cmd,
        response           : response,
        error              : error,
        ran_with_priv_escl : ran_with_priv_escl,
        forced_escl        : forced_escl,
        failed_needs_escl  : failed_needs_escl,
        priv_escl_failed   : priv_escl_failed,
        user               : user,
        escl_user          : escl_user,
        escl_method        : escl_method
      );
      return NULL;
    }

    ##
    # Log SSH command including response, user, and escalation information to debug log and JSON log.
    #
    # @param cmd Executed command
    # @param response Command response
    # @param error Associated error message
    # @param ran_with_priv_escl Boolean ran with privilege escalation
    # @param forced_escl Boolean privilege escalation forced
    # @param failed_needs_escl Boolean command failed needs privilege escalation
    # @param priv_escl_failed Boolean privilege escalation failed
    # @param user Login username
    # @param escl_user Escalation username
    # @param escl_method Escalation method
    #
    # @return NULL
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    private function log_command_and_response(cmd, escl_cmd, response,
      error, ran_with_priv_escl, forced_escl, failed_needs_escl,
      priv_escl_failed, user, escl_user, escl_method, emulated)
    {
      if(!cmd) return NULL;

      var resp = response;
      if (!isnull(response) && strlen(response) >= 512) resp = chomp(substr(resp, 0, 512));

      if(!user) user = "";
      if(!escl_user) escl_user = "";
      if(!escl_method) escl_method = "";

      var hostname = get_host_name();
      if(!hostname) hostname = get_host_ip();

      var message = {
        'plugin'              : _SCRIPT_NAME,
        'command'             : cmd,
        'constructed_command' : escl_cmd,
        'response'            : resp,
        'error'               : error,
        'hostname'            : hostname,
        'user'                : user,
        'escl_user'           : escl_user,
        'escl_method'         : escl_method,
        'ran_with_priv_escl'  : ran_with_priv_escl,
        'forced_escl'         : forced_escl,
        'failed_needs_escl'   : failed_needs_escl,
        'priv_escl_failed'    : priv_escl_failed,
        'emulated'            : emulated
      };


      add_ssh_cmd_log_entry(message:serialize(message));
      spad_log(message: serialize(message), name: 'ssh_commands.log');
    }

    ##
    # Add JSON command log entry.
    #
    # @param message JSON entry to log
    #
    # @return implicit NULL
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    private function add_ssh_cmd_log_entry(message)
    {
      if(!ssh_command_log_table_built)
      {
        query_scratchpad("CREATE TABLE IF NOT EXISTS ssh_cmd_log_json ( json_text text );");
        ssh_command_log_table_built = TRUE;
      }
      query_scratchpad("INSERT INTO ssh_cmd_log_json VALUES (?);", message);
    }

    ##
    # Get command log entries.
    #
    # @param using_priv_escal Boolean with privilege escalation
    #
    # @return List of arrays containing logged command data
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function get_commands(using_priv_escl)
    {
      var res;
      if(!using_priv_escl)
        res = query_scratchpad("SELECT plugin, cmd, md5, response, error, ran_with_priv_escl, forced_escl FROM ssh_cmd_log ORDER BY ran_with_priv_escl ASC");
      else
        res = query_scratchpad("SELECT plugin, cmd, md5, response, error, forced_escl FROM ssh_cmd_log WHERE ran_with_priv_escl=1");

      return res;
    }

    ##
    # Should privilege escalation be used for the command.
    #
    # @param command Command to check
    #
    # @return TRUE if should be escalated otherwise FALSE
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function should_escl_privs(cmd)
    {
      var md5 = hexstr(MD5(cmd));
      var res = query_scratchpad("SELECT cmd_md5 FROM ssh_always_escl WHERE cmd_md5=?", md5);
      if(empty_or_null(res))
        return FALSE;
      return TRUE;
    }

    ##
    # Add MD5(s) of command(s) that should be escalated.
    #
    # @param list_txt MD5(s) of command(s) to be escalated one per line
    #
    # @return implicit NULL
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function add_escl_md5s(list_txt)
    {
      var list_entries = split(list_txt, sep:'\n', keep:FALSE);
      var item, entry;
      foreach entry (list_entries)
      {
        item = pregmatch(pattern: "^([a-fA-F0-9]{32})\s*(\n|$)", string: entry);
        if(!isnull(item) && !isnull(item[1]))
          query_scratchpad("INSERT INTO ssh_always_escl VALUES (?);", tolower(item[1]));
      }
    }
  }
}
