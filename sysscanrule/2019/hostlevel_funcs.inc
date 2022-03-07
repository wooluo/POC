#TRUSTED 3255799765d941178088507c2480fca91322178764aa4709802d47f6588f9d990e4037187cc0af5334112fb9c101b6b7d483b603e34f4f54b2ab3f40a7b749ad7b468f175b5bd43bfad45adc05d88d99ad8aaa87da7dfce3182c5989576c75524169a1fc2175eab38e96bd0444ec7e2060677f4b3c2bd02e8d8b885dd5810e1cf4e91ce4b629e04cd32d79caaea3af25a6151912d54113922c89efc6b2572c6f801e18114fe94d4d7733a09893b6137f3112ce723bcaaf1b40132b8adde72ea7986482ece6eaf1e006ab4105fd25823a23419b8f97e96cd0a9a3354767d7a7d5a64fd97f85cfeb7dc45a787232324dd22d902fb360e2e95e785d9ce8d4951c870d093ea60b348be44af60b2b0da2346a4c982a55768842ea8c209e3f9c8afee64937b8d7f879fd22270a163fa7134543e5546a7ec8d08313aff5821cef31b9c3adc91c5638dd73237300635481fef410bf64f909633d0f0c0bc890f3e82f0164f4ab5d11ed84951b5ea721e059ccd46b6a49ee7619e812998933444752addb642f50e3fe08f57840ed82083ee32749a27f35e68b922ed289bc93e2aaa20a793e332256425caf7e49516133a0e1593e555e4cb3ac3d340479041f2a689ea0d7a61bb1f4db9682ce60df768fd909e2899e9c0ea02d86fe63be32c0bcd54e8c08d0a9c86c8b23cf62c7728abfaba8945c502451b109015c895f177afaadd36610b3
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# hostlevel_funcs.inc
#
# Revision: 1.23
#

global_var report_verbosity, port_g, login, pass;
global_var	info_t, sock_g, sep, c;

INFO_LOCAL  = 1;
INFO_SSH    = 2;
INFO_RSH    = 3;
INFO_REXEC  = 4;
INFO_RLOGIN = 5;
INFO_TELNET = 6;

# Error codes
HLF_OK       =  0;  # No error
HLF_MISMATCH = -1;  # Argument no./template mismatch.
HLF_INVALID  = -2;  # Invalid characters in argument(s)
HLF_NO_ARG   = -3;  # An argument is missing.

##
# Open a telnet connection
#
# @param port telnet port
# @param login user to login with
# @param pass password to login with
#
# @return Returns socket if successful, otherwise returns NULL
##
function telnet_open_cnx(port, login, pass)
{
 local_var	s, res;
 local_var	ps;

 if ( ! get_port_state(port) ) return NULL;
 s = open_sock_tcp(port);
 if (! s) return NULL;

 res = telnet_negotiate(socket: s);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: login + '\r\n');
 res = recv_until(socket: s, pattern: "[pP]assword:");
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: pass + '\r\n');

 ps = '([$#%>] )|([a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+ +(/|(/[^/]+)+/*) *[$#%>])';

 res = recv_until(socket: s, pattern: ps);
 if (strlen(res) == 0)
 {
  close(s);
  return NULL;
 }
 send(socket: s, data: 'thisisnotaknowncommand'+rand()+'\r\n');
 res = recv_until(socket: s, pattern: ps);
#debug_print('Bad command => ', res);
 if ('thisisnotaknowncommand' >!< res)
 {
  close(s);
  return NULL;
 }
 return s;
}

##
# Runs command via rexec
#
# @param port rexec port
# @param login user to login with
# @param pass password to login with 
# @param cmd command to run
#
# @returns NULL if error, or string containing command result
##
function send_rexec(port, login, pass, cmd)
{
  local_var	s, buf;

  if ( ! get_port_state(port) ) return NULL;
  s = open_priv_sock_tcp(dport: port);
  if (! s) return NULL;
  send(socket: s, data: '\0');    # No separate channel for error :-(
  send(socket: s, data: login + '\0' + pass + '\0' + cmd + '\0');
  buf = recv(socket: s, length: 1);  # 0 if OK?
  if ( isnull(buf) || ord(buf[0]) > 0)
  {
   close(s);
   return NULL;
  }
  buf = recv(socket: s, length: 1024*1024);
  close(s);
#debug_print('send_rexec: cmd = ', cmd, '\nbuf = \n', buf, '\n\n');
  return buf;
}

##
# Performs rlogin
#
# @param port rlogin port
# @param login username to login with
# @param pass password to login with
# @param from from user (optional, defaults to 'root')
#
# @return socket if successful, NULL if failure
##
function rlogin(port, login, pass, from)
{
 local_var	s, r;

 if ( ! get_port_state(port) ) return NULL;
 s = open_priv_sock_tcp(dport: port);
 if (!s) return NULL;
 if (! from) from = 'root';
 send(socket: s, data: '\0');
 send(socket: s, data: from + '\0' + login + '\0raw/38400\0');
 r = recv(socket: s, length: 1);
 if (r != '\0') { close(s); return NULL; }
 r = recv(socket: s, length: 1024*1024);
 if (r =~ 'Password *: *$')
 {
  send(socket: s, data: pass + '\r');
  r = recv(socket: s, length: 1024*1024);
  # display("'", ord(r[0]), "' (r)\n");
  if (r =~ 'Password *: *$')
  {
   close(s);
   return NULL;
  }
 }
 return s;
}

##
# Runs command via rsh
# 
# @param port rsh port
# @param login User to login as 
# @param from From user (optional, default is 'root')
# @param cmd Command to run
#
# @return NULL if error or string containing command output
##
function send_rsh(port, login, from, cmd)
{
 local_var	s, buf;

 if (! from) from = 'root';
 s = open_priv_sock_tcp(dport: port);
 if (! s) return NULL;
 send(socket: s, data: '0\0');	# No separate channel for error :-(
 send(socket: s, data: from + '\0' + login + '\0' + cmd + '\0');
 buf = recv(socket: s, length: 1);  # 0 if OK?
 if (ord(buf[0]) > 0)
 {
  close(s);
  return NULL;
 }
 buf = recv(socket: s, length: 1024*1024);
 close(s);
 return buf;
}

##
# Run ssh/telnet/rsh/rexec/local command
#
# @param cmd Command to run
# @param timeout A caller provided timeout (currently SSH only)
# @param nosudo Disables sudo in ssh_cmd
# @param force_priv_escl Passes through to ssh_cmd() to be passed to
#                        sshlib if wrapper functions are enabled
#
# @return NULL if error or result of command as string
##

function info_send_cmd(cmd, timeout, nosudo, force_priv_escl)
{
  local_var	buf, f;

  #debug_print('info_send_cmd: cmd=', cmd);

  if (info_t == INFO_LOCAL)
  {
    if (match(string: cmd, pattern: "cat *") && ">" >!< cmd)
    {
      f = substr(cmd, 4);
      if (! file_stat(f))
      {
        buf = 'info_send_cmd: "' +  f + '" does not exist or cannot be read\n';
        #debug_print(buf);
        local_log_command_and_response(command: "NASL command file_stat (" + f + ")", response: buf);
        return NULL;
      }
      else
      {
        buf = fread(f);
        local_log_command_and_response(command: cmd, response: buf);
        return buf;
      }
    }
    else if (cmd =~ "^cmd /C")
    {
      var arg_list = split(cmd, sep:' ', keep:FALSE);
      buf = pread(cmd: arg_list[0], argv: arg_list);
      local_log_command_and_response(command: cmd, response: buf);
      return buf;
    }
    else
    {
      if ("'" >< cmd) sep = '"';
      else sep = "'";
      buf = pread(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd));
      local_log_command_and_response(command: cmd, response: buf);
      return buf;
    }
  }

  if (info_t == INFO_SSH)
  {
    if (isnull(timeout))
    {
      timeout = 120;
    }
    return ssh_cmd(cmd: cmd, timeout: timeout, nosudo: nosudo,
                   force_priv_escl: force_priv_escl);
  }

  if (info_t == INFO_RSH)
  {
    return send_rsh(login: login, port: port_g, cmd:cmd);
  }
  if (info_t == INFO_REXEC)
  {
    return send_rexec(login: login, pass: pass, port: port_g, cmd:cmd);
  }

  if (info_t == INFO_TELNET)
  {
    send(socket: sock_g, data:
      # Yes! Two spaces (or more) are necessary
      'echo GizaNE  START; ' +  cmd + ' 2>/dev/null; echo GizaNE  END\r\n');
    # But just one space here!
    buf = recv_until(socket: sock_g, pattern: 'GizaNE END');
    #debug_print('buf=>>>\n', buf, '<<<\n');
    recv_until(socket: sock_g, pattern: '[%$#>] ');
    # Only one space here!
    buf = strstr(buf, 'GizaNE START');
    #debug_print('buf=>>>\n', buf, '<<<\n');
    c = buf - 'GizaNE START';
    while (c[0] == '\r' || c[0] == '\n' || c[0] == ' ' || c[0] == '\t')
      c = substr(c, 1);
    c = chomp(c - 'GizaNE END');
    #if (c == buf) debug_print('info_send_cmd: could not extract command output from: ', buf);
    #debug_print('c=>>>\n', c, '<<<\n');
    return c;
  }

  #log_print('info_send_cmd: unhandled case info_t=', info_t, ' - cmd=', cmd, '\n');
  return NULL;
}

##
# determines and sets best connection option
# returns TRUE of FALSE (or exits if 'exit_on_fail' == TRUE)
##
function info_connect(exit_on_fail)
{
  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (islocalhost())
  {
    if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    info_t = INFO_SSH;
    local_var ret = ssh_open_connection();
    if (!ret)
    {
      if(exit_on_fail) exit(1, "Failed to open an SSH connection.");
      return FALSE;
    }
  }
  return TRUE;
}

##
# run a command from a template
# all variables are checked to prevent command injection
#
# @param template : arguments are presented as $<argument_number>$ in template
# @param args : list of arguments (optional)
# @param timeout : timeout in seconds (optional)
# @return array s.t. 'data' contains the return value of the command
#               'error' contains the relevant error code.
function run_cmd_template(template, args, timeout, exit_on_fail)
{
  local_var i, arg, buf, err;
  i = 1;

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (isnull(template))
  {
    err = 'run_cmd_template(): missing required arg "template"';
    if(exit_on_fail)
    {
      ssh_close_connection();
      exit(1, err);
    }

    return make_array('error', HLF_NO_ARG);
  }

  # we shouldn't have variable in template if no arguments are present
  # coding error, so exit
  if (isnull(args) && preg(pattern:"\$[0-9]+\$", string:template))
  {
    err = 'run_cmd_template(): Template variables present with no arguments.';
    if(exit_on_fail)
    {
      ssh_close_connection();
      exit(1, err);
    }
    return make_array('error', HLF_MISMATCH);
  }

  # sanitize arguments to prevent command injection
  # attacks
  foreach arg (args)
  {
    # only allow whitelisted characters to prevent command injection
    # strings starting with '-' aren't allowed unless surrounded by quotes
    if (arg !~ '^(( *[*A-Za-z0-9_./\\[\\]][*A-Za-z0-9_.\\-/\\[\\]]*)*|'+
               '(\'[*A-Za-z0-9_.\\-/\\[\\] ]*\')|'+
               '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$')
    {
      err = 'run_cmd_template(): Invalid characters in argument "args"';
      if(exit_on_fail)
      {
        ssh_close_connection();
        exit(1, err);
      }
      return make_array('error', HLF_INVALID);
    }
    template = ereg_replace(string:template, pattern:"\$" + i + "\$", replace:arg);
    i++;
  }
  # template variable number / argument number mismatch
  # coding error, so exit
  if (preg(pattern:"\$[0-9]+\$", string:template))
  {
    err = "run_cmd_template(): The number of template variables mismatch the number of arguments provided.";
    if(exit_on_fail)
    {
      ssh_close_connection();
      exit(1, err);
    }
    return make_array('error', HLF_MISMATCH);
  }

  buf = info_send_cmd(cmd:template, timeout:timeout);

  return make_array('data', buf, 'error', HLF_OK);
}

##
# Logs results of a command within scratchpad
#
# @param command text version of command being issued locally
# @param response text version of response received by command
# @remark Calls logger for JSON version as well, 
#
# @return No return
##
function local_log_command_and_response(command, response)
{
  if(!get_kb_item("global_settings/enable_plugin_debugging")) {
    return NULL;
  }

  if (isnull(response) || strlen(response) < 1) response = "info_send_cmd: Response empty or null";

  local_var hostname = get_host_name();
  if(!hostname) hostname = get_host_ip();

  local_var message = '{' +
    '"plugin": ' + serialize(SCRIPT_NAME) + ', ' +
    '"command": ' + serialize(command) + ', ' +
    '"response": ' + serialize(response) + ', ' +
    '"hostname": ' + serialize(hostname) +
    '}';
  spad_log(message: message, name: 'local_commands.log');
}

##
# Sets global variables
##
function set_globals()
{
 local_var opt;
 opt = get_kb_item("global_settings/report_verbosity");

 if (opt )
        {
        if ("Verbose" >< opt ) report_verbosity = 2;
        else if ("Normal" >< opt ) report_verbosity = 1;
        else if ("Quiet" >< opt ) report_verbosity = 0;
        }
}

set_globals();

