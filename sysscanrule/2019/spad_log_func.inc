#TRUSTED 99d332c848e535661b56f8e549589e6fa5193c468918202462c0d45482368746709982ec1117aeae99f268cb4d1a52bd80d233e9866f2062a5a68276473a171adb64d50d9f7a8e4d7a940db038615a4f7abd1fab9fa7465352814c93d0023e54269ca19dddb5c2f1af0b1f7379aa09236a6ff7aa3aea4978fa9d022b81baf5876940229476e1f63450358f995d6a18600f554646f33f387c3b062f2b25dbe267facb177ff8ba1c9344e56edf390658017ea4a196da5dae4d8056757b3a02f579a80259ecd5869eec70380a76d2ce9912f34d7b48f379e149eb637a41962313e18d675d25ba348bf2f42a00926691530321b33b71f2bcd6cec1135157244b53c38797f0e3ddb4b147aad01c0796d45a320e54c708f940d9165888437a0b7024909bc2750e4a14090324607fc296df783c4c07e86d3bd4c83289f6dd321fb2a9a08ac64af16546252c58538a8f6b2bf33cff8dee6a7011be1e1fe9243bac85b20c32ef30e0a4d4e21909614299deff9b0b45f8f4ddf759cc709ea87a8d3351fcb8914aa715e9f24caec07ed3434daba14c5c7a219c7649e66d1195426cbe2ed74bc774d9069abde78ee6e8bf51edd745d9b21de7fb5b387c156fdb2c80aff4e721bbe1422e5fe26f9bcb4a8fe7d5c12523df83df62cd1b85744ca615388225fd869729179abbcd7028c9013a539199e9f7ebaaeee4a71859d7a492178cc6941514

###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# @include misc_func.inc
# @include global_settings.inc
#
###

##
# Name of the table where logs are stored.
##
global_var __SPAD_LOG_TABLE_NAME;
__SPAD_LOG_TABLE_NAME  = "logstore";

##
# For thread safety (some plugins call branch/fork)
##
global_var __SPAD_LOG_SQLDB_MUTEX;
__SPAD_LOG_SQLDB_MUTEX = __SPAD_LOG_TABLE_NAME + "_" + get_host_ip();

##
# Table definition for spad log table
#
# id      : log message id (integer auto increments)
# name    : log file name (128 CHAR) used when attached as a file, should be unique
#           for a logging session e.g. "ssh_get_info.log" or "virus_scanner_debug.log"
#           defaults to SCRIPT_NAME.log. This column is indexed.
# time    : time stamp for message, will be pre-appended to message when log created
# message : log message (unrestricted TEXT)
##
global_var __SPAD_LOG_TBL_SQL;

##
# SQL to insert a new log message
##
global_var __SPAD_LOG_INS_SQL;

##
# SQL to get unique log names
##
global_var __SPAD_LOG_NAM_SQL;

##
# SQL to check if table is created
##
global_var __SPAD_LOG_CHK_SQL;

##
# SQL to get text / time data for single log
##
global_var __SPAD_LOG_TXT_SQL;

__SPAD_LOG_INS_SQL = "INSERT INTO "+__SPAD_LOG_TABLE_NAME+" (name,message) VALUES(?,?)";
__SPAD_LOG_NAM_SQL = "SELECT DISTINCT name FROM "+__SPAD_LOG_TABLE_NAME;
__SPAD_LOG_CHK_SQL = "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name='" +__SPAD_LOG_TABLE_NAME+"'";
__SPAD_LOG_TXT_SQL = "SELECT time,message FROM "+__SPAD_LOG_TABLE_NAME+" WHERE name=? ORDER BY time";
__SPAD_LOG_TBL_SQL =
  "CREATE TABLE IF NOT EXISTS "+__SPAD_LOG_TABLE_NAME+" (" +
    "id      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
    "name    CHAR(128) NOT NULL ," +
    "time    DATETIME DEFAULT current_timestamp, " +
    "message TEXT" +
  "); " +
  "CREATE INDEX IF NOT EXISTS logstore_name_idx ON "+__SPAD_LOG_TABLE_NAME+"(name)";

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'.
#
# @param message string required - message to log
# @param name    string optional - name of the log handle to log message
#                                  defaults to <SCRIPT_NAME>.log
#
# @remark Returns immediately if kb item 'global_settings/enable_plugin_debugging'
#         is not set.
#
# @remark If you are running in "CLI Mode" messages will be displayed directly
#         to the STDOUT and name will be ignored entirely.
#
# @remark It's highly recommended if you're logging in a plugin that branches / 
#         forks to not use the default name or to pre-append a thread specific
#         identifier to message, e.g.:
#
#            port = branch(list_of_ports)
#            spad_log(message:"("+port+") Opening connection ...");
#
#         Remember that functions like get_kb_item and get_single_install can
#         branch depending on the structure of the KB, its up to you to decide
#         if thread specific logging is appropriate for your logging needs in
#         these situations.
##
function spad_log(message,name)
{
  # Skip if plugin logging not enabled
  if(!get_kb_item("global_settings/enable_plugin_debugging"))
    return;

  # Set default values
  if(isnull(name))
    name = ((SCRIPT_NAME - ".nasl") - ".nbin") + ".log";
  # Catch dev mistakes
  if(typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return;
  }
  if(isnull(message) || typeof(message) !~ '(data|string)')
  {
    err_print("Parameter 'message' is null or an invalid type.");
    return;
  }

  # If we're not running in CLI mode log to spad db
  if(!isnull(get_preference("plugins_folder")))
  {
    _spad_log_to_db(message:message,name:name);
  }
  # If we are in CLI mode show message directly
  else
  {
    display(message);
    if(message !~ '\n$')
      display('\n');
  }
}

##
# combine spad_log with a call to exit 
# to report exit messages to spad log when needed
# 
# @param message, see spad_log message parameter, optional see remark
# @param name, see spad_log name parameter
# @param exit_level, see exit call for details, default to 0
# @param exit_msg, see exit call for details REQUIRED
#
# @remark if message is not supplied spad_log will use exit_msg
##
function spad_log_and_exit(message, name, exit_level, exit_msg)
{
  if (isnull(exit_msg))
    exit(0, "NO AUDIT TRAIL MESSAGE SUPPLIED!");

  if (isnull(exit_level))
    exit_level = 0;

  if (isnull(message))
  {
    spad_log(message:exit_msg, name:name);
    exit(exit_level, exit_msg);
  }
  else
  {
    spad_log(message:message, name:name);
    exit(exit_level, exit_msg);
  }
}

##
# Returns a structure that can be attached with security_report_with_attachments
##
function spad_log_get_report_attachments()
{
  local_var names,row,msgs,logs,txt,lidx;

  if(!_spad_log_has_inited())
    return NULL;

  names = query_scratchpad(__SPAD_LOG_NAM_SQL);

  if(empty_or_null(names))
    return NULL;

  logs = make_list();
  lidx = 0;
  foreach row (names)
  {
    if(isnull(row['name']))
      continue;

    txt = _spad_log_get_txt(name:row['name']);

    if(isnull(txt))
      continue;

    logs[lidx] = make_array();
    logs[lidx]["type" ] = "text";
    logs[lidx]["name" ] = row['name'];
    logs[lidx]["value"] = txt;
    lidx += 1;
  }
  return logs;
}

##
# Adds log message specified by param 'message' to the
# log handle / file specified by param 'name'. Does
# the scratch pad database interaction only.
#
# @param message string required - message that to log
# @param name    string required - name of the log handle to log message
#
##
function _spad_log_to_db(message,name)
{
  if(typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return;
  }
  if(isnull(message) || typeof(message) !~ '(data|string)')
  {
    err_print("Parameter 'message' is null or an invalid type.");
    return;
  }

  if(!_spad_log_has_inited())
    _spad_log_init();

  query_scratchpad(__SPAD_LOG_INS_SQL,name,message);
}

##
# Get the log text for particular log
#
# @param name string required - name of the log to get the text of
#
# @remark a new line if always added to the end of messages if one
#         is not already present
##
function _spad_log_get_txt(name)
{
  local_var ret,row,txt;

  if(isnull(name) || typeof(name) !~ '(data|string)')
  {
    err_print("Parameter 'name' is null or an invalid type.");
    return NULL;
  }
  
  ret = query_scratchpad(__SPAD_LOG_TXT_SQL, name);

  if(empty_or_null(ret))
    return NULL;
  txt = NULL;
  foreach row (ret)
  {
    txt += "["+row['time']+"] "+row["message"];
    if(row["message"] !~ '\n$') txt += '\n';
  }
  return txt;
}

##
# Creates the necessary SQLite tables for logging
##
function _spad_log_init()
{
  query_scratchpad(__SPAD_LOG_TBL_SQL);
}

##
# Checks to see the log structures have been initialized
##
function _spad_log_has_inited()
{
  local_var ret;

  ret = query_scratchpad(__SPAD_LOG_CHK_SQL);

  if(isnull(ret) || ret[0]["cnt"] == 0)
    return FALSE;
  return TRUE;
}
