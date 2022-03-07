#TRUSTED 56859fc6239dcc90fbecfa9e827c086497fd2ca8a97ef13dbdc60531571327b1d38c392776cb9e1cd281aa24d5b0a7d12531b02e9b7244f71ea81e5deb24d6bad1478c1a3c0538ba9c886b3a6656f970fb63009c44f2e558eaa125689945584760da64f9384af735e61f4256f295f147c7f7c04c683cc00b667e1f6943f18d73b1e5d41d40bd4da573763a5d970802ced4bb45a847446500fb9214c6cd4bb93639db30e1601626caa671cd477297e502b4b80a46a6d273bdcd5e003e7c565438fc72ac59c9094b230f63934d0af00785cf8a41f4a2682217bbfdfe021feab11938072c7a9ac4baa2f5efc466d81a9517c276d46ee6bb7ff9994e044a321bc9392547872734e865841acd0b25897c022fc228a34213b1969168e35f04e2bb5550c1a4347833bc97b9c1e14f801bef54cdc677eff82b49994cfdce1235a7c51ef079c75a3b8b1ea7a399f884a397b89cffd0861bbd9dea27ca3690f513bf623b017f3da2f2351f2a10ff84971873823caa8279810fcea1fe6e6018c425b5666332ddf48e86ba04519150ab55b1e0ce1ad2b43ef76b96b3e81f05de4a6cf75f227fb4984a588561ee4ad1cf4048a2736feff3695eb7760a092bc3608ea6da2048c184426abca5ac432afef75042e25f8f6ff4599459a07773c19b3c2bf919d3e64de30ea18d8ee7da28324fb3c6b60e055f1c59a84dada77943f94625986fd7529b
#------------------------------------------------------------------------------
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# install_func.inc
#
# Revision: 1.18
#
# @include audit.inc
# @include global_settings.inc
# @include misc_func.inc
# @include string.inc
# @include data_protection.inc
###
#

include("string.inc");

### Constants ###
CPE_KEY             = '/cpe';
DISPLAY_VERSION_KEY = '/display_version';
LIST_BULLET         = '- ';
PATH_REPORT_KEY     = 'Path';
PRIORITY_KEY        = '/priority';
ROOT_KB_KEY         = 'installed_sw/';
SEPARATOR           = ';';     # Default separator for lists in KB.
SERVICE_REPORT_KEY  = 'Service';
SOURCE_KEY          = 'Source';
UNKNOWN_VER         = "unknown";
VERSION_KEY         = '/version';
VERSION_REPORT_KEY  = 'Version';

### Debug Flag ###
IF_VERBOSE_ERRORS = FALSE;

### get_single_install Flag ###
IF_GSI_CALLED = make_array();

# Return Codes
# Negative values are conditions that should not occur at run-time
# Positive values can occur at run-time and should be handled
# gracefully.
IF_LOWER_PRIORITY  = 2;   # Install is lower priority than existing.
IF_NOT_FOUND       = 1;   # No installs found.
IF_OK              = 0;   # Successful return.
IF_ERROR           = -1;  # General/Unknown/Upstream error.
IF_MISSING_ARG     = -2;  # Missing argument to function.
IF_ARG_BAD_TYPE    = -3;  # Function argument is the wrong type.
IF_UNEXPECTED_NULL = -4;  # Unexpected NULL value encountered.
IF_PARSE_ERROR     = -5;  # Failed to parse input.
IF_MISSING_FUNC    = -6;  # Missing function definition. Indicates missing include.
IF_MUTEX_ARGS      = -7;  # Mutually exclusive arguments.

# Source Priorities
IF_PRIORITY_HIGH   = 1;
IF_PRIORITY_NORMAL = 0;
IF_PRIORITY_LOW    = -1;
IF_PRIORITY_LOWER  = -2;

# Error Templates
IF_ERROR_TEMPLATE = make_list(1, "%s(): Unknown or upstream error occurred.", IF_ERROR);
IF_MISSING_ARG_TEMPLATE = make_list(2, "%s(): missing required argument '%s'.", IF_MISSING_ARG);
IF_ARG_BAD_TYPE_TEMPLATE = make_list(3, "%s(): '%s' arg must be type '%s'.", IF_ARG_BAD_TYPE);
IF_UNEXPECTED_NULL_TEMPLATE = make_list(2, "%s(): '%s' variable is unexpectedly NULL.", IF_UNEXPECTED_NULL);
IF_PARSE_ERROR_TEMPLATE = make_list(2, "%s(): Failure parsing variable '%s'.", IF_PARSE_ERROR);
IF_MISSING_FUNC_TEMPLATE = make_list(3, "%s(): The function '%s' is not defined. Try including '%s'.", IF_MISSING_FUNC);
IF_MUTEX_ARGS_TEMPLATE = make_list(2, "%s(): The arguments '%s' cannot be specified at the same time.", IF_MUTEX_ARGS);

### Globals ###
InstallReport = make_array();   # Report for all installs found.
InstallCount = make_array();    # Number of installs found.

### Functions ###

# Get both and local and remote (combined) installs
#
# @param  string app_name
# @param  int     exit_if_not_found OPTIONAL defaults to FALSE, exits
#                 if no installs of app_name are found.
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. that each
#                          install is an array containing all the data
#                          stored in the KB.
#                          (NULL if ret[0] != IF_OK)
##
function get_combined_installs(app_name, exit_if_not_found)
{
  local_var installs, local_installs, remote_installs,
            install, tmp, port, args, func_name, i;

  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Default value
  if (isnull(exit_if_not_found)) exit_if_not_found = FALSE;

  # report on both local and remote installs
  installs = make_list();

  local_installs = get_installs(app_name: app_name);

  if(local_installs[0] == IF_OK) installs = make_list(installs, local_installs[1]);
  remote_installs = get_kb_list(ROOT_KB_KEY+ "*/" + app_name + "/*" + VERSION_KEY);

  if(!isnull(remote_installs))
  {
    foreach install(keys(remote_installs))
    {
       tmp = split(install, sep:'/',  keep:FALSE);
       port = int(tmp[1]);
       remote_installs = get_installs(app_name: app_name, port:port);
       if(remote_installs[0] == IF_OK)
       {
         # add port information to array
         for (i=0; i<max_index(remote_installs[1]); i++)
           remote_installs[1][i]["port"] = port;
         installs = make_list(installs, remote_installs[1]);
       }
    }
  }

  if(max_index(installs) == 0)
  {
    if(exit_if_not_found) audit(AUDIT_NOT_INST, app_name);
    return make_list(IF_NOT_FOUND);
  }
  else
  {
    return make_list(IF_OK, make_nested_list(installs));
  }
}

##
# Registers an application install in the KB.
#
# @param  string  app_name
# @param  string  path will be base-64 encoded in KB key.
# @param  string  version OPTIONAL defaults to UNKNOWN_VER
# @param  string  version OPTIONAL used in report if supplied
# @param  int     port OPTIONAL if supplied, install KB key is
#                 'installed_sw/<port>/<app_name>/<path>/
# @param  string  cpe OPTIONAL i.e. cpe:/a:adobe:acrobat_reader
# @param  array   extra OPTIONAL Array keys must be strings, values
#                 may be strings, ints or lists. Lists will be stored
#                 in KB as SEPARATOR separated strings.
# @param  array   extra_no_report OPTIONAL like extra but not included
#                 in report
# @param  bool    webapp OPTIONAL if TRUE reports path as URL
# @param  string  service OPTIONAL the name of the service (e.g. SNMP, SIP),
#                 install KB is 'installed_sw/<port>/<app_name>/<protocol>/'
# @param  string  protocol OPTIONAL IP protocol for port (default: 'tcp')
# @param  int     priority OPTIONAL defaults to IF_PRIORITY_NORMAL
# @param  string  rep_path OPTIONAL if set appends string to webapp
#                 path created by build_url2()
#
# @remark This function has a side effect of creating KB items to
#         store the install data passed to it. Additionally, it will
#         update a 'installed_sw/<app_name>' key that counts the
#         number of installs of <app_name>.
#
# @return IF_OK if successful
#         IF_ERROR otherwise
##
function register_install(app_name, path, version, display_version, port, cpe, extra,
  extra_no_report, webapp, service, protocol, priority, rep_path)
{
  local_var func_name, args;
  local_var install_kb_key, app_kb_key;
  local_var install_added, proto;
  local_var report_version, report_path, p_extra;

  func_name = 'register_install';

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return return_error(IF_MUTEX_ARGS_TEMPLATE, args);
  }

  # Webapp and service are mutually exclusive
  if (!isnull(webapp) && !isnull(service))
  {
    args = make_list(func_name, 'webapp and service');
    return return_error(IF_MUTEX_ARGS_TEMPLATE, args);
  }

  # If app is a webapp, we need a port.
  if (webapp && isnull(port))
  {
    args = make_list(func_name, 'port');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # If 'service' is specified, we need a port.
  if (!isnull(service) && isnull(port))
  {
    args = make_list(func_name, 'port');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Default values.
  if (isnull(version)) version = UNKNOWN_VER;
  if (isnull(webapp)) webapp = FALSE;
  if (isnull(priority)) priority = IF_PRIORITY_NORMAL;
  if (isnull(protocol)) protocol = 'tcp';

  # Increment install count and save in KB.
  if (isnull(InstallCount[app_name])) InstallCount[app_name] = 1;
  else InstallCount[app_name] += 1;
  replace_kb_item(name:ROOT_KB_KEY + app_name, value:InstallCount[app_name]);

  app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return IF_ERROR;
  app_kb_key = app_kb_key[1];

  # Set webapp key and ensure we store a path for root installs
  if (webapp)
  {
    if (path == '') path = '/';
    set_kb_item(name:"www/"+port+"/webapp_installed", value:TRUE);
  }

  # Generate install KB key.
  install_kb_key = make_install_kb_key(app_kb_key:app_kb_key, path:path, service:service, protocol:protocol);
  if (install_kb_key[0] != IF_OK) return IF_ERROR;
  install_kb_key = install_kb_key[1];

  # Add data to KB.
  install_added =
    add_install_to_kb(
      install_kb_key:install_kb_key,
      version:version,
      display_version:display_version,
      extra:extra,
      extra_no_report:extra_no_report,
      cpe:cpe,
      priority:priority
    );

  if (install_added == IF_LOWER_PRIORITY) return IF_LOWER_PRIORITY;
  else if (install_added != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  # Register service if unknown
  if (!isnull(service) && service_is_unknown(port:port, ipproto:protocol))
  {
    # Replace any spaces with an underscore and lowercase service name
    proto = tolower(str_replace(string:service, find:' ', replace:'_'));
    register_service(port:port, proto:proto, ipproto:protocol);
  }

  # Add install to report.
  if (!isnull(display_version)) report_version = display_version;
  else report_version = version;

  # Build URL path if webapp
  if (webapp)
  {
    if (isnull(rep_path)) p_extra = "";
    else p_extra = rep_path;
    report_path = build_url2(port:port, qs:path + p_extra);

    PATH_REPORT_KEY = 'URL';
  }
  else report_path = path;

  if (
    add_install_to_report(
      app_name:app_name,
      path:report_path,
      service:service,
      version:report_version,
      extra:extra) != IF_OK
    ) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  return IF_OK;
}

##
# Creates a base KB key for an application.
#
# @param app_name string
# @param port     int OPTIONAL
#
# @remark This key does NOT end in a '/'.
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the app KB key
#                          (NULL if ret[0] != IF_OK)
function make_app_kb_key(app_name, port)
{
  local_var func_name, args;
  local_var app_kb_key;

  func_name = "make_app_kb_key";

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # App KB key consists of ROOT + port, if supplied + app_name
  app_kb_key = ROOT_KB_KEY;
  if (!isnull(port)) app_kb_key += port + '/';
  app_kb_key += app_name;

  return make_list(IF_OK, app_kb_key);
}

##
# Creates a base KB key for an install.
#
# @param  string  app_name
# @param  string  path     OPTIONAL local or URL path
# @param  string  service  OPTIONAL service name (e.g. SNMP, SIP)
# @param  string  protocol OPTIONAL IP protocol used by the port
#
# @remark 'path' or 'service' must be specified
# @remark If 'service' is specified, 'protocol' must also be specified
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the install KB key
#                          (NULL if ret[0] != IF_OK)
##
function make_install_kb_key(app_kb_key, path, service, protocol)
{
  local_var func_name, args;
  local_var install_kb_key, b64_path;

  func_name = 'make_install_kb_key';

  # Input validation.
  if (isnull(app_kb_key))
  {
    args = make_list(func_name, 'app_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return make_list(return_error(IF_MUTEX_ARGS_TEMPLATE, args));
  }

  if (!isnull(service) && isnull(protocol))
  {
    args = make_list(func_name, 'protocol');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Base KB key starts with app KB key.
  install_kb_key = app_kb_key + '/';

  # Encode path in base-64 and add to install_kb_key.
  if (!isnull(path))
  {
    b64_path = IF_base64(path);
    if (b64_path[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
    install_kb_key += b64_path[1];
  }

  if (!isnull(service))
  {
    install_kb_key += "service/" + protocol + '/' + service;
  }

  return make_list(IF_OK, install_kb_key);
}

##
# Adds install values to the KB.
#
# @param string  install_kb_key
# @param string  version
# @param string  display_version OPTIONAL
# @param array   extra OPTIONAL
# @param array   extra_no_report OPTIONAL
# @param string  cpe OPTIONAL
# @param int     priority
#
# @return IF_OK if successful
#         IF_MISSING_ARG if argument is missing
#         IF_ARG_BAD_TYPE if any argument is wrong type
#         IF_ERROR if unknown or upstream error occurs
##
function add_install_to_kb(install_kb_key, version, display_version, extra, extra_no_report,
  cpe, priority)
{
  local_var func_name, args;
  local_var existing_priority, cpe_with_version;

  func_name = 'add_install_to_kb';

  # Input validation.
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(priority))
  {
    args = make_list(func_name, 'priority');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(display_version) && !is_string(display_version))
  {
    args = make_list(func_name, 'display_version', 'string');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  if (!isnull(extra_no_report) && typeof(extra_no_report) != 'array')
  {
    args = make_list(func_name, 'extra_no_report', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # If this install is already registered in the KB, only replace the
  # data if this is a higher priority install.
  existing_priority = get_kb_item(install_kb_key + PRIORITY_KEY);
  if (!isnull(existing_priority) && existing_priority > priority)
    return IF_LOWER_PRIORITY;

  # If there is an existing install, we need to over-write the source.
  # If we're not already providing one in 'extra' or 'extra_no_report'
  # set it to UNKNOWN_VER.
  if (!isnull(existing_priority) && isnull(extra[SOURCE_KEY]) && isnull(extra_no_report[SOURCE_KEY]))
    extra[SOURCE_KEY] = UNKNOWN_VER;

  # Add priority to KB.
  replace_kb_item(name:install_kb_key + PRIORITY_KEY, value:priority);

  # Add version to KB.
  replace_kb_item(name:install_kb_key + VERSION_KEY, value:version);

  # If supplied, add the display version to the KB.
  if (!isnull(display_version))
    replace_kb_item(name:install_kb_key + DISPLAY_VERSION_KEY, value:display_version);

  if (!isnull(cpe))
  {
    cpe_with_version = add_version_to_cpe(cpe:cpe, version:version);
    cpe_with_version = standardize_cpe(cpe:cpe_with_version);

    replace_kb_item(name:install_kb_key + CPE_KEY, value:cpe_with_version);
  }

  if (!empty_or_null(extra))
  {
    if (add_extra_to_kb(install_kb_key:install_kb_key, extra:extra) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }
  if (!empty_or_null(extra_no_report))
  {
    if (add_extra_to_kb(install_kb_key:install_kb_key, extra:extra_no_report) != IF_OK)
      return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  }

  return IF_OK;
}

##
# Adds extra items to the KB.
#
# @param array extra
# @remark This function has the side effect of modifying the KB.
# @remark List values are joined SEPARATOR separated strings.
#
# @return IF_OK if successful
##
function add_extra_to_kb(install_kb_key, extra)
{
  local_var func_name, args;
  local_var key, value;

  func_name = "add_extra_to_kb";

  # Input validation
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Add extra items to KB
  foreach key (keys(extra))
  {
    value = extra[key];

    # Simply ignore NULL values instead of raising an error
    if (isnull(value))
    {
      continue;
    }

    if (!is_string(value) && typeof(value) != 'array' && typeof(value) != 'int')
    {
      args = make_list(func_name, "extra['" + key + "']", 'string/list/int');
      return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
    }

    if (typeof(value) == 'array') value = join(value, sep:SEPARATOR);

    replace_kb_item(name:install_kb_key + '/' + key, value:value);
  }

  return IF_OK;
}

##
# Adds the application install to the global report.
#
# @param string   app_name
# @param string   path     OPTIONAL local or URL path
# @param string   service  OPTIONAL service name (e.g. SNMP, SIP)
# @param string   version
# @param array    extra OPTIONAL
#
# @remark 'path' or 'service' must be specified
#
# @return IF_OK if successful
#         IF_MISSING_ARG if argument is missing
#         IF_ARG_BAD_TYPE if any argument is wrong type
#         IF_ERROR if unknown or upstream error occurs
##
function add_install_to_report(app_name, path, service, version, extra)
{
  local_var func_name, args;
  local_var report;
  local_var extra_string, extra_list;
  local_var fields, field_length;

  func_name = 'add_install_to_report';

  # Input validation.
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  { 
    args = make_list(func_name, 'path and service');
    return return_error(IF_MUTEX_ARGS_TEMPLATE, args);
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return return_error(IF_ARG_BAD_TYPE_TEMPLATE, args);
  }

  # Initialize report if needed.
  report = InstallReport[app_name];
  if (isnull(report)) report = '';

  # Process extra array.
  if (!isnull(extra))
  {
    extra = process_extra(extra);
    if (extra[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
    extra_string = extra[1];
    extra_list = extra[2];
  }
  else
  {
    extra_string = NULL;
    extra_list = NULL;
  }

  # Determine field length.
  if (!isnull(path))
    fields = make_list(PATH_REPORT_KEY, VERSION_REPORT_KEY);

  if (!isnull(service))
    fields = make_list(SERVICE_REPORT_KEY, VERSION_REPORT_KEY);

  if (!isnull(extra_string) && len(extra_string) > 0) fields = make_list(fields, keys(extra_string));
  field_length = maxlen(fields);
  if (field_length == -1) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  # Add string data to report.
  report =
    add_string_data_to_report(
      report:report,
      path:path,
      service:service,
      version:version,
      extra:extra_string,
      field_length:field_length
    );
  if (report[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
  report = report[1];

  # Add list data to report.
  if (!isnull(extra_list))
  {
    report =
      add_list_data_to_report(
        report:report,
        extra:extra_list
      );
    if (report[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));
    report = report[1];
  }

  # Store report in global variable.
  InstallReport[app_name] = report;

  return IF_OK;
}

##
# Splits the extra array into two arrays, one containing string values
# the other containing list values.
#
# @param  array extra
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is an array with all the string values
#                   ret[2] is an array with all the list values
##
function process_extra(extra)
{
  local_var func_name, args;
  local_var extra_string, extra_list;
  local_var key, value;
  local_var ret;

  func_name = 'process_extra';

  # Accept argument anonymously.
  if (isnull(extra)) extra = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Initialize return values.
  extra_string = make_array();
  extra_list = make_array();

  # Iterate through the array and split into two.
  foreach key (keys(extra))
  {
    value = extra[key];

    # Simply ignore NULL values instead of raising an error
    if (isnull(value))
    {
      continue;
    }
    else if (is_string(value))
    {
      extra_string[key] = value;
    }
    else if (typeof(value) == 'array')
    {
      extra_list[key] = value;
    }
    else if (typeof(value) == 'int')
    {
      extra_string[key] = string(value);
    }
    else
    {
      args = make_list(func_name, "extra['" + key + "']", 'string/list');
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }
  }

  # Build return, can't use make_list because it will flatten
  # extra_string and extra_list. When 5.0 is out of support, replace
  # with make_list2().
  ret[0] = IF_OK;
  ret[1] = extra_string;
  ret[2] = extra_list;

  return ret;
}

##
# Adds top block of string data to install report.
#
# @param string   report
# @param string   path     OPTIONAL local or URL path
# @param string   service  OPTIONAL service name (e.g. SNMP, SIP)
# @param string   version
# @param array    extra OPTIONAL
# @param int      field_length
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_string_data_to_report(report, path, service, version, extra, field_length)
{
  local_var func_name, args;
  local_var format_string;

  func_name = 'add_string_data_to_report';

  # Input validation.
  if (isnull(report))
  {
    args = make_list(func_name, 'report');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(path) && isnull(service))
  {
    args = make_list(func_name, 'path or service');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Path and service are mutually exclusive
  if (!isnull(path) && !isnull(service))
  {
    args = make_list(func_name, 'path and service');
    return make_list(return_error(IF_MUTEX_ARGS_TEMPLATE, args));
  }

  if (isnull(version))
  {
    args = make_list(func_name, 'version');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(field_length))
  {
    args = make_list(func_name, 'field_length');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(extra) && typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (typeof(field_length) != 'int')
  {
    args = make_list(func_name, 'field_length', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  format_string = '\n  %-' + field_length + "s : %s";

  # Add path or service and protocol along with version to report.
  if (!isnull(path))
  {
    report += vsprintf(args:make_list(PATH_REPORT_KEY, path), format:format_string);
  }

  if (!isnull(service))
  {
    report += vsprintf(args:make_list(SERVICE_REPORT_KEY, service), format:format_string);
  }

  report += vsprintf(args:make_list(VERSION_REPORT_KEY, version), format:format_string);

  # Add string data from extras to report.
  if (!isnull(extra))
  {
    local_var key, value;

    foreach key (sort(keys(extra)))
    {
      value = extra[key];
      if (!is_string(value))
      {
        args = make_list(func_name, "extra['" + key + "']", "string");
        return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
      }

      report += vsprintf(args:make_list(key, value), format:format_string);
    }
  }

  report += '\n';

  return make_list(IF_OK, report);
}

##
# Adds bottom block of list data to install report.
#
# @param string   report
# @param array    extra
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_list_data_to_report(report, extra)
{
  local_var func_name, args;

  func_name = 'add_list_data_to_report';

  # Input validation.
  if (isnull(report))
  {
    args = make_list(func_name, 'report');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(extra))
  {
    args = make_list(func_name, 'extra');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(extra) != 'array')
  {
    args = make_list(func_name, 'extra', 'array');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Add list data from extras to report.
  local_var key, value;

  foreach key (sort(keys(extra)))
  {
    local_var element;

    value = extra[key];
    if (typeof(value) != 'array')
    {
      args = make_list(func_name, "extra['" + key + "']", "list");
      return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
    }

    report += '\n  ' + key + ' :';
    foreach element (sort(value)) report += '\n    ' + LIST_BULLET + element;
    report += '\n';
  }

  return make_list(IF_OK, report);
}

##
# Reports detected installs.
#
# @param  string  app_name OPTIONAL if NULL all installs in
#                 InstallReport will be reported.
# @param  int     port OPTIONAL defaults to 0
# @param  string  extra OPTIONAL extra data to be appended to report
# @param  string  protocol OPTIONAL protocol for report
#
# @return IF_OK if successful
#         IF_NOT_FOUND if no install report for that app
#         IF_ERROR otherwise
##
function report_installs(app_name, port, extra, protocol)
{
  local_var func_name, args;
  local_var report;

  func_name = 'report_installs';

  # Input Validation
  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (!isnull(extra) && !is_string(extra))
  {
    args = make_list(func_name, 'extra', 'string');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Default Value
  if (isnull(port)) port = 0;

  # If app_name was not provided, report every installed app.
  # Otherwise, report only on the specified app_name.
  if (isnull(app_name))
  {
    local_var app_count, temp;

    report = '';
    app_count = len(InstallReport);

    foreach app_name (keys(InstallReport))
    {
      # If there is more than one app, add a header with the app name.
      if (app_count > 1) report += '\n--- ' + app_name + ' ---\n';

      # Add the header to the report and check the value.
      temp = add_header_to_report(app_name);
      if (temp[0] != IF_OK) return IF_ERROR;
      report += temp[1];
    }
  }
  else
  {
    report = add_header_to_report(app_name);
    if (report[0] == IF_NOT_FOUND) return IF_NOT_FOUND;
    else if (report[0] != IF_OK) return IF_ERROR;
    report = report[1];
  }

  # Add extra data if it exists.
  if (!isnull(extra)) report += '\n' + extra + '\n';

  # Finally, report.
  if (report_verbosity > 0)
  {
    report = data_protection::sanitize_user_paths(report_text: report);
    security_note(extra:report, port:port, proto:protocol);
  }
  else security_note(port:port, proto:protocol);

  return IF_OK;
}

##
# Adds header to report if install count is greater than 1.
#
# @param string app_name
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the modified report
#                          (NULL if ret[0] != IF_OK)
##
function add_header_to_report(app_name)
{
  local_var func_name, args;
  local_var report, count;

  func_name = 'add_header_to_report';

  # Allow argument to be passed anonymously.
  if (isnull(app_name)) app_name = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Retrieve report and exit if either is NULL.
  report = InstallReport[app_name];
  count = InstallCount[app_name];

  if (isnull(report) || isnull(count)) return make_list(IF_NOT_FOUND);

  # Add header to report if install count is greater than 1.
  if (count > 1) report =
    '\nGizaNE detected ' + count + ' installs of ' + app_name + ':\n' + report;

  return make_list(IF_OK, report);
}

##
# Retrieves all installs of an application/cpe.
#
# @param  string  app_name
# @param  int     port OPTIONAL limits search to remote installs found
#                 on port
# @param  bool    service OPTIONAL if true return service installs (default: true)
# @param  bool    webapp  OPTIONAL if true return webapp installs (default: true)
# @param  int     exit_if_not_found OPTIONAL defaults to FALSE, exits
#                 if no installs of app_name are found.
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. that each
#                          install is an array containing all the data
#                          stored in the KB.
#                          (NULL if ret[0] != IF_OK)
##
function get_installs(app_name, port, service, webapp, exit_if_not_found)
{
  local_var func_name, args;
  local_var app_kb_key, install_kb_keys;
  local_var installs;
  local_var i, ret;

  func_name = 'get_installs';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  # Default value
  if (isnull(exit_if_not_found)) exit_if_not_found = FALSE;

  app_kb_key = make_app_kb_key(app_name:app_name, port:port);
  if (app_kb_key[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  app_kb_key = app_kb_key[1];

  # Get a list of KB keys for each install.
  install_kb_keys = find_installs_by_key(app_kb_key:app_kb_key, service:service, webapp:webapp);
  if (install_kb_keys[0] == IF_NOT_FOUND)
  {
    if (exit_if_not_found)
    {
      if (isnull(port)) audit(AUDIT_NOT_INST, app_name);
      else audit(AUDIT_NOT_DETECT, app_name, port);
    }
    else return make_list(IF_NOT_FOUND);
  }
  else if (install_kb_keys[0] != IF_OK)
    return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));

  install_kb_keys = install_kb_keys[1];

  # Populate install data.
  installs = get_install_data_from_keys(install_kb_keys);

  if (installs[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
  installs = installs[1];

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = installs;

  return ret;
}

##
# Returns a single install of app, branches if there are multiple.
#
# @param  string  app_name
# @param  int     port OPTIONAL
# @param  bool    exit_if_unknown_ver OPTIONAL if TRUE, will exit if
#                 version == UNKNOWN_VER. Defaults to FALSE.
# @param  bool    service OPTIONAL if true return service installs (default: true)
# @param  bool    webapp  OPTIONAL if true return webapp installs (default: true)
#
# @remark This function calls get_installs() w/ exit_if_not_found set
#         to TRUE and will exit if there are no installs.
# @remark This function assumes that if looking for an app on several
#         ports, you are branching over the ports as well. That is to
#         say, it does not account for iterating over ports but then
#         branching over installs and will break. Consider it enforced
#         consistency.
#
# @return array single install
##
function get_single_install(app_name, port, exit_if_unknown_ver, combined, service, webapp)
{
  local_var func_name, args;
  local_var installs, install;

  func_name = 'get_single_install';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (!isnull(port) && typeof(port) != 'int')
  {
    args = make_list(func_name, 'port', 'int');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  if (isnull(combined)) combined = FALSE;

  if (isnull(exit_if_unknown_ver)) exit_if_unknown_ver = FALSE;

  # This function should only be called once per plugin or you'll end
  # up potentially forking a LOT.
  if (IF_GSI_CALLED[app_name])
    exit(1, "get_single_install() should only be called once per app to avoid excessive forking.");

  IF_GSI_CALLED[app_name] = TRUE;

  if(combined)
    installs = get_combined_installs(app_name:app_name, exit_if_not_found:TRUE);
  else
    installs = get_installs(
      app_name:app_name, port:port, service:service, webapp:webapp, exit_if_not_found:TRUE);

  if (installs[0] != IF_OK) return return_error(IF_ERROR_TEMPLATE, make_list(func_name));

  install = branch(installs[1]);
  if (isnull(port)) port = install['port'];

  if (exit_if_unknown_ver && install['version'] == UNKNOWN_VER)
  {
    if (!isnull(port))
    {
      # Service
      service = get_kb_list('installed_sw/' + port + '/' + app_name + '/service/*/*/version');
      if (!empty_or_null(service))
        audit(AUDIT_SERVICE_VER_FAIL, app_name, port);

      # Webapp
      if (!empty_or_null(install['path']))
        audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name,build_url2(qs:install['path'], port:port));
      else
        audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);
    }
    else audit(AUDIT_UNKNOWN_APP_VER, app_name);
  }

  return install;
}

##
# Finds all installs under the app KB key.
#
# @param  string  app_kb_key
# @param  bool    service OPTIONAL if true return service installs (default: true)
# @param  bool    webapp  OPTIONAL if true return webapp installs (default: true)
#
# @remark if service or webapp are not specified return all installs 
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of install KB keys for installs
#                          of app_name (NULL if ret[0] != IF_OK)
##
function find_installs_by_key(app_kb_key, webapp, service)
{
  local_var func_name, args;
  local_var install_kb_version_keys, install_kb_keys;
  local_var key, key_split, ret;

  func_name = 'find_installs_by_key';

  # Allow anonymous argument
  if (isnull(app_kb_key)) app_kb_key = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(app_kb_key))
  {
    args = make_list(func_name, 'app_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  # Defaults
  if (isnull(webapp)) webapp = true;
  if (isnull(service)) service = true;

  # Search by version since every install is guaranteed to have this
  # key. Then just strip out VERSION_KEY to get the install KB key.
  install_kb_version_keys = get_kb_list(app_kb_key + '/*' + VERSION_KEY);
  if (empty_or_null(install_kb_version_keys))
    return make_list(IF_NOT_FOUND);

  # Process install keys and add to 
  install_kb_keys = make_list();
  foreach key (sort(keys(install_kb_version_keys)))
  {
    key_split = split(key, sep:'/', keep:FALSE);

    if (
      webapp && service || # skip checks if all were specified / none were passed to this func
      webapp  && key_split[1] =~ "^[0-9]+$" && key_split[3] != 'service' || # webapp
      service && key_split[1] =~ "^[0-9]+$" && key_split[3] == 'service' # service
    )
      install_kb_keys = make_list(install_kb_keys, key - VERSION_KEY);
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = install_kb_keys;

  return ret;
}

##
# Retrieves data associated with install keys passed in.
#
# @param  list install_kb_keys
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a list of installs s.t. each install is
#                          an array containing install data.
#                          (NULL if ret[0] != IF_OK)
##
function get_install_data_from_keys(install_kb_keys)
{
  local_var func_name, args;
  local_var installs, install, install_kb_key, install_kb_list, install_kb_key_split;
  local_var i, kbs, key, top_key;
  local_var temp, ret;

  func_name = 'get_install_data_from_keys';

  # Allow anonymous argument
  if (isnull(install_kb_keys)) install_kb_keys = _FCT_ANON_ARGS[0];

  # Input validation
  if (isnull(install_kb_keys))
  {
    args = make_list(func_name, 'install_kb_keys');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  if (typeof(install_kb_keys) != 'array')
  {
    args = make_list(func_name, 'install_kb_keys', 'list');
    return make_list(return_error(IF_ARG_BAD_TYPE_TEMPLATE, args));
  }

  installs = make_list();
  i = 0;

  # Get all KBs associated with each install_kb_key and then store the
  # values in an array per install, indexed by the top-level key name.
  foreach install_kb_key (install_kb_keys)
  {
    # Get all KBs for the install.
    install_kb_list = install_kb_key + '/*';
    kbs = get_kb_list(install_kb_list);
    install = make_array();

    install_kb_key_split = split(install_kb_key, sep:'/', keep:FALSE);

    # Service
    #  KB Format: register_install/<port>/<app>/service/<protocol>/<service>
    if (install_kb_key_split[1] =~ '^[0-9]+$' && install_kb_key_split[3] == 'service')
    {
      install['protocol'] = install_kb_key_split[4];
      install['service']  = install_kb_key_split[5];
    }
    # Local or webapp with a path
    else
    {
      # Decode path from install_key and store it in array.
      temp = get_path_from_kb_key(install_kb_key);
      if (temp[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));
      install['path'] = temp[1];
    }

    foreach key (keys(kbs))
    {
      # We just want the top-level key as the array key.
      top_key = key - (install_kb_key + '/');

      install[top_key] = kbs[key];
    }

    installs[i] = install;
    i++;
  }

  ret = make_list();
  ret[0] = IF_OK;
  ret[1] = installs;

  return ret;
}

##
# Returns the path associated with an install KB key.
#
# @param  string install_kb_key [description]
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the base64-decoded path associated
#                          w/ the KB key
#                          (NULL if ret[0] != IF_OK)
##
function get_path_from_kb_key(install_kb_key)
{
  local_var func_name, args;
  local_var pattern, match, path, port_match;

  func_name = 'get_path_from_kb_key';

  # Accept argument anonymously.
  if (isnull(install_kb_key)) install_kb_key = _FCT_ANON_ARGS[0];

  # Input validation.
  if (isnull(install_kb_key))
  {
    args = make_list(func_name, 'install_kb_key');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  pattern = ROOT_KB_KEY + "(?:\d+/)?.+/(.*)";
  match = pregmatch(string:install_kb_key, pattern:pattern, icase:FALSE);
  if (isnull(match))
  {
    args = make_list(func_name, 'install_kb_key');
    return make_list(return_error(IF_PARSE_ERROR_TEMPLATE, args));
  }

  # A Base64-encoded path will not contain '/'
  path = IF_base64_decode(match[1]);
  if (path[0] != IF_OK) return make_list(return_error(IF_ERROR_TEMPLATE, make_list(func_name)));

  # Check for webapp by looking for a port in 'install_kb_key'
  # If we have one and the www/port/webapp_installed key is set
  # Check for root installs and return and empty value for the path
  # Otherwise return the path as is
  port_match = pregmatch(pattern:'installed_sw/([0-9]+)/', string:install_kb_key);

  if (!isnull(port_match) && !empty_or_null(port_match[1]))
  {
    port_match = port_match[1];
    if (get_kb_item('www/' + port_match + '/webapp_installed'))
    {
      if (path[1] == '/') path[1] = '';
    }
  }
  return make_list(IF_OK, path[1]);
}

##
# Returns the number of installs of 'app_name'.
#
# @param  string  app_name
# @param  bool    exit_if_zero OPTIONAL, if TRUE will exit w/ audit if
#                              install count is 0.
#
# @return int   < 0 if error occurs
#               = 0 if no installs found
#               > 0 if 1 or more installs found
##
function get_install_count(app_name, exit_if_zero)
{
  local_var func_name, args;
  local_var count;

  func_name = 'get_install_count';

  # Input Validation
  if (isnull(app_name))
  {
    args = make_list(func_name, 'app_name');
    return return_error(IF_MISSING_ARG_TEMPLATE, args);
  }

  # Default Value
  if (isnull(exit_if_zero)) exit_if_zero = FALSE;

  count = get_kb_item(ROOT_KB_KEY + app_name);
  if (isnull(count) || count == 0)
  {
    if (exit_if_zero) audit(AUDIT_NOT_INST, app_name);
    else return 0;
  }

  return count;
}

##
# Encodes a string to base-64 in a 'KB-safe' way.
#
# @param string str string to encode
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the encoded string
#                          (NULL if ret[0] != IF_OK)
##
function IF_base64(str)
{
  local_var func_name, args;
  local_var b64;

  func_name = 'IF_base64';

  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(str))
  {
    args = make_list(func_name, 'str');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  b64 = base64(str:str);

  b64 = str_replace(string:b64, find:'=', replace:'$');
  b64 = str_replace(string:b64, find:'/', replace:'&');

  return make_list(IF_OK, b64);
}

##
# Decodes a 'KB-safe' base64 string back to ASCII.
#
# @param string str string to decode
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is the decoded string
#                          (NULL if ret[0] != IF_OK)
##
function IF_base64_decode(str)
{
  local_var func_name, args;

  func_name = 'IF_base64';

  if (isnull(str)) str = _FCT_ANON_ARGS[0];
  if (isnull(str))
  {
    args = make_list(func_name, 'str');
    return make_list(return_error(IF_MISSING_ARG_TEMPLATE, args));
  }

  str = str_replace(string:str, find:'$', replace:'=');
  str = str_replace(string:str, find:'&', replace:'/');

  return make_list(IF_OK, base64_decode(str:str));
}

##
# Returns error code for given template and prints error.
#
# @param  list  error_template defined in header
# @param  list  args
#
# @return int   error corresponding to error_template or IF_ERROR if
#               error occurs within this function
##
function return_error(error_template, args)
{
  # Allow arguments to be passed anonymously.
  if (isnull(error_template)) error_template = _FCT_ANON_ARGS[0];
  if (isnull(args)) args = _FCT_ANON_ARGS[1];

  # Input validation.
  if (isnull(error_template))
  {
    err_print("return_error(): missing required argument 'error_template'.");
    return IF_ERROR;
  }

  if (isnull(args))
  {
    err_print("return_error(): missing required argument 'args'.");
    return IF_ERROR;
  }

  if (typeof(error_template) != 'array' || len(error_template) != 3)
  {
    err_print("return_error(): An invalid error template was passed.");
    return IF_ERROR;
  }

  if (typeof(args) != 'array' || len(args) != error_template[0])
  {
    err_print("return_error(): The number of args passed does not match the error template for " +
      "error code: " + error_template[2] + ". (Expected " + error_template[0] +
      ", received " + len(args) + ")");
    return IF_ERROR;
  }

  # Print error if verbose.
  if (IF_VERBOSE_ERRORS) err_print(vsprintf(args:args, format:error_template[1]));

  return error_template[2];
}

# Copy of build_url() in http_misc_func.inc to avoid dependency
# requirement.
function build_url2(port, host, qs, username, password)
{
  local_var t, url, p, n;

  t = get_port_transport(port);
  p = "";
  if (t > ENCAPS_IP)
  {
    url = "https://";
    if (port != 443) p = ':' + port;
  }
  else
  {
    url = "http://";
    if (port != 80) p = ':' + port;
  }

  if (strlen(host) > 0)
    n = host;
  else
  {
    if (get_kb_item("DNS/invalid_hostname"))
    n = get_host_ip();
    else
    {
      n = get_host_name();
      if (n =~ "^([0-9]+\.)+in-addr\.arpa$")
      n = get_host_ip();
    }
  }

  if (! isnull(username) || ! isnull(password))
  {
    url += username;
    if (! isnull(password))
    url += ":" + password;
    url += "@";
  }
  url = url + n + p;
  if (strlen(qs) > 0 && qs[0] == '/') url = url + qs;
  else url = url + '/' + qs;
  return url;
}

##
# Append version to CPE ID
#
# @param  string cpe ID to append version to
# @param  string version to append to CPE ID
#
# @remark if version is NULL or UNKNOWN_VER, then the cpe is returned
#         with just a colon appended (e.g. cpe:/a:wordpress:wordpress:)
#
# @return CPE ID string with version appended if available (e.g. cpe:/a:wordpress:wordpress:5.1.1)
##
function add_version_to_cpe(cpe, version)
{
  var func_name = "add_version_to_cpe";

  if (isnull(cpe)) return NULL;
  
  var cpe_with_version = cpe;

  # Append a colon if its not already there
  if (cpe[strlen(cpe) - 1] != ":")
    cpe_with_version += ":";
  
  if (!isnull(version) && version != UNKNOWN_VER)
    cpe_with_version += version;

  return cpe_with_version;
}

##
# Standardize CPE ID
#
# @param  string  cpe ID to standardize
#
# @remark This is just a start, more standardizations will be added at a later date.
#
# @return standardized CPE ID string 
##
function standardize_cpe(cpe)
{
  var func_name = "standardize_cpe";

  if (isnull(cpe)) return NULL;

  cpe = str_replace(string:cpe, find:' ', replace:'_');     # Replace spaces with underscores
  cpe = tolower(cpe);                                       # Lowercase

  return cpe;
}

