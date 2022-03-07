#TRUSTED 15aed792712ff96a5f3fd32178ae225bb9850533202b76fbdf00761e1ff1ad08600588d5dfd829866208c8db1deed96dae6fa08f44db378f488ba1a514969a893e7f2689a7159a493499115baab13d5cf6b4299ecd548c373600ac1df504dc9f57e8d5cd8f9edd1ae9aa8d95d7c811df0a14940b6e8c2dd357706fc1c968fde495e099d70f9943a60291d93bd7b6d4e09a2ce406a75f1082aca449a08f53879dcdc18cc8198242007101f2db5e41368c3011e4bcaf4be24dc3ba917e996c353b647b3f9c50943ec77d65cd299793a00a8bbd7837cc51bdae761f17dbcf5be986bb1add37d210cab4182f9c5161ab7aa3349e9bfd8b3f3fa6a80a9b984605992f6f8b6b244dee58a8ad60cfb7bc4b2bb84dd22959a20d9b7401e7de300848f899043ff24a2eb609c8d596fc842f08f8d63135b73f52a26b1928cbe8d5484bee71af474370bc017d55982092a506db9a9b97009f966b2b272db8c96d83ae11b0d7dec4c9e679f2cf0201bbb021f8554ff886191800d0ea4d7a54ab4b2d8ea41d4998e038b93faf38c0d064debdd8e2a8c616ac2cd58b441f65e8267e2398c1bed4fc076eb551a56ec42e555400907afb32ffca62d564c91440553b415ed91a3d3fd4b974730d62f4e8f716df355135fb3a506f8c6fba32d28b0056c64ca1e275f86ee807cd05d278f2bea7c2e88088daf2a5d46cc85b20d31effe3aa08fb88c8db
#
# (C) WebRAY Network Security, Inc.
#
# v1.36

#pragma static
global_var experimental_scripts, report_verbosity, debug_level, thorough_tests, report_paranoia, supplied_logins_only;
global_var all_addr_private, all_addr_public, __gs_opt;

experimental_scripts = 0;
report_verbosity = 1;
debug_level = 0;
thorough_tests = 0;
report_paranoia = 1;
all_addr_private = 0;
all_addr_public = 0;
supplied_logins_only = 0;

global_var SECURITY_HOLE    = 'Hole';
global_var SECURITY_WARNING = 'Warning';
global_var SECURITY_NOTE    = 'Note';

if (  get_kb_item("global_settings/supplied_logins_only") ) 
{
 supplied_logins_only = 1;
}

__gs_opt = get_kb_item("global_settings/network_type");
if (__gs_opt)
{
  if ("LAN" >< __gs_opt) all_addr_private = 1;
  else if ("Internet" >< __gs_opt) all_addr_public = 1;
}

__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}

__gs_opt = get_kb_item("global_settings/report_paranoia");
if (__gs_opt)
{
  if ("Avoid false alarms" >< __gs_opt) report_paranoia = 0;
  else if ("Normal" >< __gs_opt) report_paranoia = 1;
  else if ("Paranoid" >< __gs_opt) report_paranoia = 2;
}

__gs_opt = get_kb_item("global_settings/debug_level");
debug_level = int(__gs_opt);
if (debug_level < 0) debug_level = 0;

__gs_opt = get_kb_item("global_settings/experimental_scripts");
if ( __gs_opt )
{
   if ( "no" >< __gs_opt ) experimental_scripts = 0;
   else if ("yes" >< __gs_opt) experimental_scripts = 1;
}

__gs_opt = get_kb_item("global_settings/thorough_tests");
if ( __gs_opt )
{
 if ( "no" >< __gs_opt) thorough_tests = 0;
 else if ("yes" >< __gs_opt) thorough_tests = 1;
}

include("data_protection_nlib.inc");

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 msg = SCRIPT_NAME + '(' + get_host_ip() + '): ';
 foreach i (_FCT_ANON_ARGS) { msg = msg + i; }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

# Only use this function to print a fatal error, e.g. a violation of an API
function err_print(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 msg = SCRIPT_NAME + '(' + get_host_ip() + '): ';
 foreach i (_FCT_ANON_ARGS) { msg = msg + i; }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("ERR: ", msg);
}

##
# Taken from http_misc_func.inc
#
# @param resp       Text from our response to include in the report
# @param max_lines  Max number of lines to include of output. Default to 10
##
function beginning_of_response2(resp, max_lines)
{
  local_var     txt, i, line;

  if (isnull(resp))
    return err_print('beginning_of_response2: missing parameter resp.');

  if (max_lines <= 0) max_lines = 10;
  i = 0;
  foreach line(split(resp, keep: 0))
  {
    line = chomp(line);
    line = ereg_replace(string: line, pattern: '^[ \t]+', replace: '');
    txt += line + '\n';
    if (++ i  >= max_lines) return txt + '[...]\n';
  }
  return txt;
}

##
# security_report will appear in GizaNE 5
#
# @param port       port number of the web server
# @param proto      sets the reporting protocol, defaults to tcp
# @param severity   report severity (note, warning, hole)
# @param extra      report text to display
# @param cmd        Command executed.  Used in the report output.  If TRUE
#                   use code/command execution report
# @param file       File to use in report. If TRUE, use reporting for lfi/rfi
# @param request    array list of request(s) used in report output
# @param output     Output to use in report for file_read or cmd_exec
#                   Is an optional param when generic is TRUE
# @param line_limit Number of output lines to display in report. 10 by default
# @param rep_extra  Any extra text to include in the report output (optional)
# @param attach_type Attachment type used with security_report_with_attachments
#                    defaults to 'text/plain' in none provided.
# @param generic    Used for reporting of general SQLi / XSS vulns
#                   When generic is TRUE, output can be optional
# @param sqli       If TRUE, sets SQLInjection KB item
# @param xss        If TRUE, sets XSS KB item
# @param xsrf       If TRUE, sets XSRF KB item
##
function security_report_v4(port, proto, severity, extra, cmd, file, request, output, line_limit, rep_extra, attach_type, generic, sqli, xss, xsrf)
{
  local_var attach_level, snip, s, report, rep_footer, rep_header;
  local_var num_req, attachments, i;

  if (isnull(severity))
    return err_print('security_report_v4: missing parameter severity.');
  if (isnull(port))
    return err_print('security_report_v4: missing parameter port.');

  if ( (!isnull(cmd)) || (!isnull(file)) )
  {
    if (isnull(request))
      return err_print('security_report_v4: missing parameter request.');
    if (isnull(output))
      return err_print('security_report_v4: missing parameter output.');
  }

  # if output contains /etc/passwd values ensure PII is redacted
  if(!isnull(output)) output = data_protection::redact_etc_passwd(output:output);
  if(!isnull(extra)) extra = data_protection::redact_etc_passwd(output:extra);
  if(!isnull(rep_extra)) rep_extra = data_protection::redact_etc_passwd(output:rep_extra);

  # if output contains uid values ensure PII is redacted
  if(!isnull(output)) output = data_protection::sanitize_uid(output:output);
  if(!isnull(extra)) extra = data_protection::sanitize_uid(output:extra);
  if(!isnull(rep_extra)) rep_extra = data_protection::sanitize_uid(output:rep_extra);

  # validate the protocol
  if(isnull(proto) || !strlen(string(proto)))
    proto = 'tcp';
  else if(tolower(proto) !~ "^(tcp|udp|icmp|egp)$")
    proto = 'tcp';
  else
    proto = tolower(proto);

  # These are set unconditionally
  if (xss)
    replace_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (xsrf)
    replace_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (sqli)
    replace_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  attach_level = 2;  # Default value
  if (severity == SECURITY_NOTE) attach_level = 0;
  if (severity == SECURITY_WARNING) attach_level = 2;
  if (severity == SECURITY_HOLE) attach_level = 3;

  if (isnull(line_limit))
    line_limit = 10;

  if (isnull(attach_type))
    attach_type = 'text/plain';

  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  rep_footer = crap(data:"-", length:66);

  if (!isnull(cmd))
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nGizaNE was able to execute the command "' + cmd + '" using the' +
      '\nfollowing request' + s + ' :' +
      '\n' + 
      '\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    report +=
      '\n\n' + 'This produced the following truncated output (limited to ' +
      line_limit + ' lines) :' +
      '\n' + snip +
      '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
      '\n' + snip +
      '\n';

    report = data_protection::sanitize_user_paths(report_text: report);

    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto, extra:report);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto, extra:report);
    else
      security_note(port:port, proto:proto, extra:report);
  }

  else if (!isnull(file))
  {
    output = data_protection::sanitize_user_paths(report_text: output);
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nGizaNE was able to exploit the issue to retrieve the contents of ' +
      '\n' + "'" + file + "'" + ' using the following request' + s + ' :' +
      '\n' +
      '\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\n' + 'This produced the following truncated output (limited to ' +
        line_limit + ' lines) :' +
        '\n' + snip +
        '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
        '\n' + snip +
        '\n';

      if (severity == SECURITY_HOLE)
        security_hole(port:port, proto:proto, extra:report);
      else if (severity == SECURITY_WARNING)
        security_warning(port:port, proto:proto, extra:report);
      else
        security_note(port:port, proto:proto, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< file) file = ereg_replace(
        pattern:"^.+/([^/]+)$", replace:"\1", string:file);
      if ("\" >< file) file = ereg_replace(
        pattern:"^.+\\([^\\]+)$", replace:"\1", string:file);

      report +=
        '\n' + 'Attached is a copy of the response' + '\n';
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = attach_type;
      attachments[0]["name"] = file;
      attachments[0]["value"] = output;
      security_report_with_attachments(
        port  : port,
        level : attach_level,
        extra : report,
        attachments : attachments
      );
    }
  }

  else if (generic)
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nGizaNE was able to exploit the issue using the following request'
      + s + ' :\n\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    # Allow output to be optional for Generic cases.
    if (!isnull(output))
    {
      report +=
        '\n\n' + 'This produced the following truncated output (limited to ' +
        line_limit + ' lines) :' +
        '\n' + snip +
        '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
        '\n' + snip +
        '\n';
    }

    report = data_protection::sanitize_user_paths(report_text: report);

    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto, extra:report);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto, extra:report);
    else
      security_note(port:port, proto:proto, extra:report);
  }

  else if (report_verbosity < 1 || isnull(extra))
  {
    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto);
    else
      security_note(port:port, proto:proto);
  }
  else
  {
    extra = data_protection::sanitize_user_paths(report_text: extra);
    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto, extra:extra);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto, extra:extra);
    else
      security_note(port:port, proto:proto, extra:extra);
  }
}

global_var GLOBAL_SETTINGS_INC = 1;
