#TRUSTED 630e0b9f861d786ab73ef5a81311ac0466df76c87964c2cdead654107bdba5bae8371684031b28260e389ba6c4fc4de344cb939fea99b8f3931f56449b5e440cbc3eef301793c5338e2571d69e29d73c3c059fee4ce833ccbad846f3343b954b0a4baaae49a3b0b1d5fcdc0b169e20d95b684c7891c9a7a35314adb9d7924209c120ef5513cf341fc6708747bfd8969a6c43dc01354d95750afb4ff5fa0109c489ee4a67cfce534c759aef9f4935263f3e0a8d8b600d801a5f05bfe0b12adade8a624b3d3ce6c6452c8966cd21590bed854247ab2e5392683ecf92892c5ee109fc789b80e6ff3d50576c54845e02e7738f7007e19f8791a2c7289f142961f11388af9f25c39c77e42e30c98812fa0cf09e1566a7d820f386ec2edab1c4dfd0cab7c67ae3f3739d92dc20a33ea1659b69993d7a414d3e858edea3f96cb222b3e545ec9f14013e0e2f96a38224a706335e1bdb63f69f6f18941b687bfd8926b9a87db4af5b21eaf4171900097e3190da73294a6213b35dae35bde1b7c6641ceb6609e45e7b460c9683db9feeac97101304e48999813d9b0f4ffdd085694e21d55836a873061de771566a75022aa50bc2116c062bca347f899fdf83aba99cf6f388b6a0be25fb1acd67c5091489047ef91fd3f8cbdf7a32668b8438e16adc0468f3c9079201c7b2b34ff6c6d3b256c6148dc08b8de01eafbb0c6974012d809b6be0
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

include("global_settings_nlib.inc");
include("misc_func_nlib.inc");
include("spad_log_func.inc");
include("lcx_globals.inc");

namespace lcx {

  ##
  # Logs debugging message using spad_log()
  #
  # @param [fn:string] Name of the calling function (optional)
  # @param [msg:string] Message to be logged in debugging log
  #
  # @ return NULL
  ##
  function dbg_log(fn, msg)
  {
    if (empty_or_null(msg))
    {
      msg = "lcx::dbg_log(): Argument 'msg' is empty or null";
      if (fn) msg += " from function " + fn + "()";
      msg += ".";
      spad_log(message:msg);
      DBG_LOG[max_index(DBG_LOG)] = msg;
      return NULL;
    }
    var pre = "lcx";
    if (fn) pre += "::" + fn + "()";
    msg = pre + ": " + msg;
    spad_log(message:msg);
    DBG_LOG[max_index(DBG_LOG)] = msg;
    return NULL;
  }

  ##
  # Gets the KB prefix for the issue type
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  #
  # @return string KB prefix associated with the passed type, or NULL
  #                if no matching KB prefix was found
  ##
  function get_issue_kb_prefix(type)
  {
    var fn = "get_kb_prefix";

    if (empty_or_null(type))
      return dbg_log(fn:fn, msg:"No type specified.");

    var kb_prefix = KB_ISSUES[type];
    if (empty_or_null(kb_prefix))
      kb_prefix = KB_PM_ISSUES[type];
    if (empty_or_null(kb_prefix))
      return dbg_log(fn:fn, msg:"No KB prefix found for issue type '" +
        type + "'.");

    return kb_prefix;
  }

  ##
  # Gets the count of how many issues of the passed type have been
  # logged in the KB
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  #
  # @return int The count of how many issues of the passed type have
  # been logged in the KB, or -1 if no matching KB prefix was found
  ##
  function get_issue_count(type)
  {
    var fn = "get_count";

    if (empty_or_null(type))
    {
      dbg_log(fn:fn, msg:"No type specified.");
      return -1;
    }

    var kb_prefix = get_issue_kb_prefix(type:type);
    if (isnull(kb_prefix)) return -1;

    var count = get_kb_item(kb_prefix + "count");
    if (isnull(count)) count = 0;
    var s = "s";
    if (count == 1) s = "";
    dbg_log(fn:fn, msg:count + " " + kb_prefix + " issue" + s +
        " found in the KB.");
    return count;
  }

  ##
  # Looks up the KB prefix for the passed issue type and logs the
  # issue message under that type, incrementing the type count
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  # @param [msg:string] The issue message to be logged to the KB
  # @param [plugin:string] The plugin reporting the issue (optional)
  #                        Defaults to current SCRIPT_NAME
  # @param [proto:int] Global var for protocol
  # @param [user:string] Name of the user account
  # @param [port:int] Port number
  # @param [host:string] Third-party patch mgmt hostname or IP
  # @param [pm_prod:int] Global var for patch mgmt product
  #
  # @return True if successful, NULL if errors were encountered
  ##
  function _store_issue_in_kb(type, msg, plugin, proto, user, port, host, pm_prod)
  {
    var fn = "_store_issue_in_kb";

    var count = get_issue_count(type:type);
    if (count < 0)
    {
      dbg_log(fn:fn, msg:'KB issue count is negative...bailing.:\n');
      return NULL;
    }
    count++;

    var kb_prefix = get_issue_kb_prefix(type:type);
    if (isnull(kb_prefix))
    {
      dbg_log(fn:fn, msg:"Can't find issue type KB prefix." + '\n');
      return NULL;
    }

    dbg_log(fn:fn, msg:'Storing issue in KB:\n' + msg);
    replace_kb_item(name:kb_prefix + "count", value:count);
    kb_prefix += "msgs/" + count;
    replace_kb_item(name:kb_prefix + "/text", value:msg);
    replace_kb_item(name:kb_prefix + "/plugin", value:plugin);
    if (user) replace_kb_item(name:kb_prefix + "/user", value:user);
    if (port) replace_kb_item(name:kb_prefix + "/port", value:port);
    if (!empty_or_null(proto) && !empty_or_null(PROTO_NAMES[proto]))
    {
      replace_kb_item(name:kb_prefix + "/proto", value:proto);
      replace_kb_item(name:kb_prefix + "/proto_name", value:PROTO_NAMES[proto]);
    }
    if (KB_PM_PREFIX >< kb_prefix)
    {
      if (host) replace_kb_item(name:kb_prefix + "/host", value:host);
      if (pm_prod) replace_kb_item(name:kb_prefix + "/pm_prod", value:pm_prod);
    }

    return TRUE;
  }


  ##
  # Stores patch management authentication issues into the scratchpad
  # at the time of their collection.  Later each host  grabs the
  # patch management logged issues and reports them in their own
  # plugin execution scope.
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  # @param [msg:string] The issue message to be logged to the KB
  # @param [plugin:string] The plugin reporting the issue (optional)
  #                        Defaults to current SCRIPT_NAME
  # @param [proto:int] Global var for protocol
  # @param [user:string] Name of the user account
  # @param [port:int] Port number
  # @param [host:string] Third-party patch mgmt hostname or IP
  # @param [pm_prod:int] Global var for patch mgmt product
  #
  # @return True if successful, NULL if errors were encountered
  ##
  function _store_pm_issue(type, msg, plugin, proto, user, port, host, pm_prod)
  {
    local_var query, pm_prod_desc, kb_prefix, kb_prefix_base, pm_solution, count;

    var fn = "_store_pm_issue";

    if(isnull(proto)) proto = '';

    kb_prefix_base = get_issue_kb_prefix(type:type);
    pm_prod_desc = PM_PROD_NAMES[pm_prod];


    if (isnull(kb_prefix_base) || isnull(pm_prod_desc) || isnull(PROTO_NAMES[proto]) || KB_PM_PREFIX >!< kb_prefix_base)
    {
      dbg_log(fn:fn, msg:"Can't make path management issue type KB prefix." + '\n');
      return NULL;
    }

    dbg_log(fn:fn, msg:"Storing PM issue #" + type + " for the " + pm_prod_desc + " at " + host + ".");

    kb_prefix = '/' + pm_prod_desc + '/' + PROTO_NAMES[proto] + '/' + port;
    count = get_kb_item(kb_prefix_base + kb_prefix + "/count");
    if(isnull(count))
      count = 1;
    else
      count = (int(count)) + 1;

    replace_kb_item(name:kb_prefix_base + kb_prefix + "/count", value:count);

    kb_prefix = count + kb_prefix;

    set_global_kb_item(name:kb_prefix_base + kb_prefix + "/text", value:msg);
    set_global_kb_item(name:kb_prefix_base + kb_prefix + "/plugin", value:plugin);
    if (user) set_global_kb_item(name:kb_prefix_base + kb_prefix + "/user", value:user);
    if (host) set_global_kb_item(name:kb_prefix_base + kb_prefix + "/host", value:host);

    return TRUE;
  }


  ##
  # Looks up the KB prefix for the passed issue type and logs the
  # issue message under that type.  In the KB for host issues and into
  # the global KB for patch management issues.
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  # @param [msg:string] The issue message to be logged to the KB
  # @param [plugin:string] The plugin reporting the issue (optional)
  #                        Defaults to current SCRIPT_NAME
  # @param [proto:int] Global var for protocol
  # @param [user:string] Name of the user account
  # @param [port:int] Port number
  # @param [host:string] Third-party patch mgmt hostname or IP
  # @param [pm_prod:int] Global var for patch mgmt product
  #
  # @return True if successful, NULL if errors were encountered
  ##
  function log_issue(type, msg, plugin, proto, user, port, host, pm_prod)
  {
    var fn = "log_issue";

    if (empty_or_null(type))
      return dbg_log(fn:fn, msg:"No type specified.");
    if (empty_or_null(msg))
      return dbg_log(fn:fn, msg:"No msg specified.");
    if (empty_or_null(proto) || empty_or_null(PROTO_NAMES[proto]))
    {
      if (empty_or_null(proto))
        dbg_log(fn:fn, msg:"No proto specified.");
      if (typeof(proto) != "int")
        dbg_log(fn:fn, msg:"Invalid 'proto' argument '"+proto+"'.");
      else if (empty_or_null(PROTO_NAMES[proto]))
        dbg_log(fn:fn, msg:"Unrecognized 'proto' argument '"+proto+"'.");
    }

    if (empty_or_null(plugin)) plugin = THIS_SCRIPT;

    var kb_prefix = get_issue_kb_prefix(type:type);
    if (KB_PM_PREFIX >< kb_prefix)
    {
      dbg_log(fn:fn, msg:'Adding new patch-management issue to global KB:\n' + msg);

      return _store_pm_issue(type:type, msg:msg, plugin:plugin, proto:proto, user:user,
        port:port, host:host, pm_prod:pm_prod);
    }
    else
    {
      dbg_log(fn:fn, msg:'Adding new issue to the KB:\n' + msg);

      return _store_issue_in_kb(type:type, msg:msg, plugin:plugin, proto:proto, user:user,
        port:port, host:host, pm_prod:pm_prod);
    }

    return TRUE;
  }

  ##
  # Wrapper for log_issue() that logs successful auth
  #
  # @param [msg:string] The issue message to be logged to the KB
  #                     (optional)
  # @param [proto:int] Global var for protocol
  # @param [user:string] Name of the user account
  # @param [port:int] Port number
  # @param [host:string] Third-party patch mgmt hostname or IP
  # @param [pm_prod:int] Global var for patch mgmt product
  #
  # @return Return value of log_issue()
  ##
  function log_auth_success(msg, plugin, proto, user, port, clear_failures, host, pm_prod)
  {
    var fn = "log_auth_success";
    var type = AUTH_SUCCESS;
    var is_pm = pm_prod && PM_PROD_NAMES[pm_prod];

    if (is_pm)
      type = PM_AUTH_SUCCESS;

    var kb_prefix = get_issue_kb_prefix(type:type);
    if (empty_or_null(proto) || empty_or_null(PROTO_NAMES[proto]))
    {
      if (empty_or_null(proto))
        dbg_log(fn:fn, msg:"No proto specified.");
      if (typeof(proto) != "int")
        dbg_log(fn:fn, msg:"Invalid 'proto' argument '"+proto+"'.");
      else if (empty_or_null(PROTO_NAMES[proto]))
        dbg_log(fn:fn, msg:"Unrecognized 'proto' argument '"+proto+"'.");
      proto = UNKNOWN;
    }
    if (empty_or_null(user)) user = UNKNOWN;
    if (empty_or_null(port)) port = UNKNOWN;
    if (!msg)
    {
      msg = "Authentication success for ";
      if (user == UNKNOWN) msg += "unknown user ";
      else msg += "user '"+user+"' ";
      if (is_pm)
      {
        msg += "to third-party patch management product " +
          PM_PROD_NAMES[pm_prod] + " ";
        if (host) msg += " at " + host + " ";
      }
      if (port == UNKNOWN) msg += "on unknown port ";
      else msg += "on port " + port + " ";
      if (proto == UNKNOWN) msg += "via unknown protocol.";
      else msg += "via " + PROTO_NAMES[proto] + " protocol.";
    }

    if (clear_failures)
    {
      if(!is_pm)
        _clear_auth_issues(proto:proto, user:user, port:port, host:host);
    }

    return log_issue(type:type, plugin:plugin, proto:proto, user:user,
      port:port, msg:msg, host:host, pm_prod:pm_prod);
  }


  ##
  # Transfers patch management issues from the global KB to an individual
  # host's local KB for reporting.
  #
  # @param [pm_prod:int] Global var for patch mgmt product
  # @param [port:int] Port number
  # @param [proto:int] Global var for protocol
  #
  # @return Returns TRUE if the transfer was successful, FALSE otherwise.
  ##
  function load_pm_issues_to_kb(pm_prod, port, proto)
  {
    local_var kb_prefix, kb_prefix_base, issues, issue_keys, key, issue_key, count;

    var fn = "load_pm_issues_to_kb";

    if(isnull(proto)) proto = '';

    var pm_prod_desc = PM_PROD_NAMES[pm_prod];
    dbg_log(fn:fn, msg:"Storing PM issues for the " + pm_prod_desc + " at port " + port + ".");

    kb_prefix_base = get_issue_kb_prefix(type:PM_AUTH_SUCCESS);
    if (isnull(kb_prefix_base) || isnull(pm_prod_desc) || isnull(PROTO_NAMES[proto]) || KB_PM_PREFIX >!< kb_prefix_base)
    {
      dbg_log(fn:fn, msg:"Can't make path management issue type KB prefix." + '\n');
      return NULL;
    }

    count = 1;
    while(TRUE)
    {
      kb_prefix = count + '/' + pm_prod_desc + '/' + PROTO_NAMES[proto] + '/' + port;
      issues = get_global_kb_list(kb_prefix_base + kb_prefix + '/*');
      issue_keys = keys(issues);
      if(max_index(issue_keys) == 0)
      {
        kb_prefix_base = get_issue_kb_prefix(type:PM_ISSUES_AUTH);
        issues = get_global_kb_list(kb_prefix_base + kb_prefix + '/*');
        issue_keys = keys(issues);
        if(max_index(issue_keys) == 0)
          return TRUE;
      }

      replace_kb_item(name:kb_prefix_base + "count", value:count);

      #This function loads issues for each host so we can start at zero.
      dbg_log(fn:fn, msg:'Saving issue #' + count + ' from global KB\n');
      foreach key(issue_keys)
      {
        issue_key = kb_prefix_base + "msgs/" + count;

        if("/text" >< key)
        {
          replace_kb_item(name:issue_key + "/pm_prod", value:pm_prod_desc);
          replace_kb_item(name:issue_key + "/proto", value:proto);
          replace_kb_item(name:issue_key + "/proto_name", value:PROTO_NAMES[proto]);
          replace_kb_item(name:issue_key + "/port", value:port);
        }

        issue_key += key - (kb_prefix_base + kb_prefix);

        replace_kb_item(name:issue_key, value:issues[key]);

        if("user" >< key)
        {
          if("success" >< issue_key)
            replace_kb_item(name:"PManage/Auth/SOAP/" + port + "/Success", value:issues[key]);
          else
            replace_kb_item(name:"PManage/Auth/SOAP/" + port + "/Failure", value:issues[key]);
        }
      }

      count++;
    }

    # Should never get here
    dbg_log(fn:fn, msg:'Failed to return after the last issue.  Should never get here.\n');
    return NULL;
  }


  ##
  # Gets issues of the passed type from the KB
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  # @param [plugin_id:int] Plugin ID to limit issues to (optional)
  # @param [proto:int] Global var for protocol to limit issues to
  #                    (optional)
  # @param [user:string] Username to limit issues to (optional)
  # @param [port:int] Port number to limit issues to (optional)
  # @param [host:string] Third-party patch mgmt hostname or IP
  # @param [pm_prod:int] Global var for patch mgmt product
  #
  # @return list If successful, a list of arrays, each of which
  #              contains an issue message 'text' that was stored in
  #              the KB for the passed issue type, the reporting
  #              plugin 'plugin', and the protocol 'proto' if present
  #              If no logged issues of the passed type are found, an
  #              empty list is returned. If an error is encountered,
  #              NULL is returned.
  ##
  function get_issues(type, plugin_id, proto, user, port, host, pm_prod)
  {
    var fn = "get_issues";

    if (empty_or_null(type))
      return dbg_log(fn:fn, msg:"No type specified.");

    var kb_prefix = get_issue_kb_prefix(type:type);
    if (isnull(kb_prefix)) return NULL;

    var count = get_issue_count(type:type);
    if (count < 0) return NULL;

    if (count == 0) return make_list();

    # Check filter parameters and debug log
    if (plugin_id)
      dbg_log(fn:fn, msg:"Filtering on plugin_id '"+plugin_id+"'.");
    if (proto)
    {
      if (PROTO_NAMES[proto])
      {
        dbg_log(fn:fn, msg:"Filtering on proto '"+proto+"' " +
          "("+PROTO_NAMES[proto]+").");
      }
      else
      {
        if (typeof(proto) != "int")
          dbg_log(fn:fn, msg:"Invalid 'proto' argument '"+proto+"'.");
        else if (empty_or_null(PROTO_NAMES[proto]))
          dbg_log(fn:fn, msg:"Unrecognized 'proto' argument '"+proto+"'.");
        return NULL;
      }
    }
    if (user) dbg_log(fn:fn, msg:"Filtering on user '"+user+"'.");
    if (port) dbg_log(fn:fn, msg:"Filtering on port '"+port+"'.");
    if (KB_PM_PREFIX >< kb_prefix)
    {
      if (host) dbg_log(fn:fn, msg:"Filtering on host '"+host+"'.");
      if (pm_prod) dbg_log(fn:fn, msg:"Filtering on pm_prod '"+pm_prod+"'.");
    }

    # Gather matching records from the KB
    var ret, i, j, kb_plugin, kb_plugin_id, kb_plugin_name, kb_text;
    var kb_proto, kb_proto_name, kb_prefix2, kb_user, kb_port;
    var kb_host, kb_pm_prod;
    var plugin_data;
    var skip_count = 0;
    ret = make_list();
    j = 0;
    for (i = 0; i < count; i++)
    {
      kb_prefix2 = kb_prefix + "msgs/" + (i+1);

      kb_plugin = get_kb_item(kb_prefix2 + "/plugin");
      kb_plugin_id = get_kb_item(kb_prefix2 + "/plugin_id");
      kb_plugin_name = get_kb_item(kb_prefix2 + "/plugin_name");
      if (!kb_plugin_id && !kb_plugin_name)
      {
        plugin_data = get_plugin_data(plugin:kb_plugin);
        if (plugin_data)
        {
          kb_plugin_id = plugin_data.id;
          kb_plugin_name = plugin_data.name;
          replace_kb_item(name:kb_prefix2 + "/plugin_id", value:plugin_data.id);
          replace_kb_item(name:kb_prefix2 + "/plugin_name", value:plugin_data.name);
        }
      }

      # Check records against filter arguments
      if (plugin_id && kb_plugin_id != plugin_id) continue;
      kb_proto = get_kb_item(kb_prefix2 + "/proto");
      if (proto && kb_proto != proto) continue;
      kb_user = get_kb_item(kb_prefix2 + "/user");
      if (user && kb_user != user) continue;
      kb_port = get_kb_item(kb_prefix2 + "/port");
      if (port && kb_port != port) continue;
      if (KB_PM_PREFIX >< kb_prefix)
      {
        kb_host = get_kb_item(kb_prefix2 + "/host");
        if (host && kb_host != host) continue;
        kb_pm_prod = get_kb_item(kb_prefix2 + "/pm_prod");
        if (pm_prod && kb_pm_prod != pm_prod) continue;
      }

      # Skip "removed" records
      if (get_kb_item(kb_prefix2 + "/removed"))
      {
        skip_count++;
        dbg_log(fn:fn, msg:"Skipping record "+(i+1)+", removed by " +
          get_kb_item(kb_prefix2 + "/removed_by"));
        continue;
      }

      # Retrieve rest of record data
      kb_text = get_kb_item(kb_prefix2 + "/text");
      kb_proto_name = get_kb_item(kb_prefix2 + "/proto_name");

      ret[j] = {'plugin':kb_plugin, 'text':kb_text};
      if (kb_proto) ret[j]['proto'] = kb_proto;
      if (kb_proto_name) ret[j]['proto_name'] = kb_proto_name;
      if (kb_plugin_id) ret[j]['plugin_id'] = kb_plugin_id;
      if (kb_plugin_name) ret[j]['plugin_name'] = kb_plugin_name;
      if (kb_port) ret[j]['port'] = kb_port;
      if (kb_user) ret[j]['user'] = kb_user;
      if (kb_host) ret[j]['host'] = kb_host;
      if (kb_pm_prod) ret[j]['pm_prod'] = kb_pm_prod;
      j++;
    }
    if (plugin_id || proto || user || port)
      dbg_log(fn:fn, msg:max_index(ret)+" records matched the filter.");
    if (skip_count > 0)
      dbg_log(fn:fn, msg:skip_count + " matching records were " +
        "skipped because they were marked as 'removed'.");
    return ret;
  }

  ##
  # Wrapper for get_issues that gets list of users with issues to
  # report
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  # @param [plugin_id:int] Plugin ID to limit issues to (optional)
  # @param [proto:int] Global var for protocol to limit issues to
  #                    (optional)
  # @param [port:int] Port number to limit issues to (optional)
  # @param [db:string] Name of DB to limit issues to (optional)
  #
  # @return List of matching users, or NULL for error
  ##
  function get_users_with_issues(type, plugin_id, proto, port)
  {
    var issues = get_issues(type:type, plugin_id:plugin_id,
      proto:proto, port:port);
    if (!issues) return NULL;
    if (max_index(issues) < 1) return make_list();

    var users = make_array();

    foreach var issue (issues)
      users[issue['user']] = 1;

    if (max_index(keys(users)) < 1) return make_list();
    return sort(keys(users));
  }

  ##
  # Iterates known issue types and gets list of logged issues for each
  #
  # @param [pm:bool] TRUE for Third-party patch mgmt issues
  #
  # @return array An array of types and the list of logged issues for
  #               each. For each type, the value will be a list of
  #               arrays containing 'text' and 'plugin' if successful,
  #               an empty list if no issues were logged for that
  #               type, or NULL if there was an error getting issues
  #               for that type.
  ##
  function get_all_issues(pm)
  {
    var types, ret = make_array();
    if (pm) types = PM_ISSUES;
    else types = ISSUES;
    foreach var type (sort(types))
      ret[type] = get_issues(type:type);

    return ret;
  }

  ##
  # Clears issues of the passed type from the KB
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  #
  # @return NULL
  ##
  function clear_issues(type)
  {
    var fn = "clear_issues";

    if (empty_or_null(type))
      return dbg_log(fn:fn, msg:"No type specified.");

    var kb_prefix = get_issue_kb_prefix(type:type);
    if (isnull(kb_prefix)) return NULL;

    var count = get_issue_count(type:type);
    if (count <= 0) return NULL;

    dbg_log(fn:fn, msg:"Removing issues of type '" + type + "'.");

    var kb, kbs = get_kb_list(kb_prefix + "*");
    foreach kb (keys(kbs)) rm_kb_item(name:kb);

    return NULL;
  }

  ##
  # Marks auth issues of the passed type in the KB as "ignore"
  #
  # @param [type:int] A global variable for an issue type, e.g.
  #                   ISSUES_ERROR
  # @param [proto:int] Global var for protocol to limit issues to
  #                    (optional)
  # @param [user:string] Username to limit issues to (optional)
  # @param [port:int] Port number to limit issues to (optional)
  # @param [host:string] Third-party patch mgmt hostname or IP
  # @param [pm_prod:int] Global var for patch mgmt product
  #
  # @return NULL
  ##
  function _clear_auth_issues(proto, user, port, host, pm_prod)
  {
    var fn = "_clear_auth_issues";

    if (!proto && !user && !port)
      return dbg_log(fn:fn, msg:"Must specify at least one " +
        "argument: proto, port, or user.");

    var kb_prefix = get_issue_kb_prefix(type:ISSUES_AUTH);
    if (isnull(kb_prefix)) return NULL;

    var count = get_issue_count(type:ISSUES_AUTH);
    if (count <= 0) return NULL;

    # Check filter parameters and debug log
    if (proto)
    {
      if (PROTO_NAMES[proto])
      {
        dbg_log(fn:fn, msg:"Filtering on proto '"+proto+"' " +
          "("+PROTO_NAMES[proto]+").");
      }
      else
      {
        if (typeof(proto) != "int")
          dbg_log(fn:fn, msg:"Invalid 'proto' argument '"+proto+"'.");
        else if (empty_or_null(PROTO_NAMES[proto]))
          dbg_log(fn:fn, msg:"Unrecognized 'proto' argument '"+proto+"'.");
        return NULL;
      }
    }
    if (user) dbg_log(fn:fn, msg:"Filtering on user '"+user+"'.");
    if (port) dbg_log(fn:fn, msg:"Filtering on port '"+port+"'.");
    if (KB_PM_PREFIX >< kb_prefix)
    {
      if (host) dbg_log(fn:fn, msg:"Filtering on host '"+host+"'.");
      if (pm_prod) dbg_log(fn:fn, msg:"Filtering on pm_prod '"+pm_prod+"'.");
    }

    # Gather matching records from the KB
    var i, kb_prefix2, ignore_count = 0;
    for (i = 0; i < count; i++)
    {
      kb_prefix2 = kb_prefix + "msgs/" + (i+1);

      # First check to see if it's already been removed
      if (get_kb_item(kb_prefix2 + "/removed")) continue;

      # Check if the record matches the filtering arguments
      if (proto && get_kb_item(kb_prefix2 + "/proto") != proto)
        continue;
      if (port && get_kb_item(kb_prefix2 + "/port") != port)
        continue;
      if (user && get_kb_item(kb_prefix2 + "/user") != user)
        continue;
      if (KB_PM_PREFIX >< kb_prefix)
      {
        if (host && get_kb_item(kb_prefix2 + "/host") != host)
          continue;
        if (pm_prod && get_kb_item(kb_prefix2 + "/user") != pm_prod)
          continue;
      }

      # Mark to ignore record
      replace_kb_item(name:kb_prefix2 + "/removed", value:TRUE);
      replace_kb_item(name:kb_prefix2 + "/removed_by", value:THIS_SCRIPT);
      ignore_count++;
    }
    dbg_log(fn:fn, msg:ignore_count + " out of " + count +
      " records matched the filter and were marked as 'removed'.");

    return NULL;
  }

  ##
  # Gets the count of how many local checks reports have been logged
  # in the KB
  #
  # @return int The count of local checks reports in the KB
  ##
  function get_report_count()
  {
    var fn = "get_report_count";

    var count = get_kb_item(KB_REPORT + "count");
    if (isnull(count)) count = 0;
    var s = "s";
    if (count == 1) s = "";
    dbg_log(fn:fn, msg:count + " report" + s +
        " found in the KB.");
    return count;
  }

  ##
  # Logs the local checks report along with the reporting plugin
  #
  # @param [text:string] The report to be logged to the KB
  # @param [plugin:string] The plugin reporting the issue (optional)
  #                        Defaults to current SCRIPT_NAME
  #
  # @return True if successful, NULL if errors were encountered
  ##
  function log_report(text, plugin)
  {
    var fn = "log_report";

    if (empty_or_null(text))
      return dbg_log(fn:fn, msg:"Missing 'text' argument.");

    var count = get_report_count();
    count++;

    if (empty_or_null(plugin)) plugin = THIS_SCRIPT;

    dbg_log(fn:fn, msg:'Adding new report:\n' + text);
    replace_kb_item(name:KB_REPORT + "count", value:count);
    replace_kb_item(name:KB_REPORT + count + "/text", value:text);
    replace_kb_item(name:KB_REPORT + count + "/plugin", value:plugin);
    var plugin_data = get_plugin_data(plugin:plugin);
    if (plugin_data)
    {
      replace_kb_item(name:KB_REPORT + count + "/plugin_id", value:plugin_data.id);
      replace_kb_item(name:KB_REPORT + count + "/plugin_name", value:plugin_data.name);
    }
    return TRUE;
  }

  ##
  # Gets local checks reports from the KB
  #
  # @param [plugin_id:int] Plugin ID to limit reports to (optional)
  #
  # @return list If successful, a list of arrays containing report
  #              text and reporting plugin. If no reports are found,
  #              an empty list is returned.
  ##
  function get_reports(plugin_id, plugin)
  {
    var fn = "get_reports";

    var count = get_report_count();
    if (count == 0) return make_list();

    var ret, i, j, kb_plugin_id, kb_plugin, plugin_name, text;
    ret = make_list();
    j = 0;
    for (i = 0; i < count; i++)
    {
      # Check values with filter arguments first
      kb_plugin_id = get_kb_item(KB_REPORT + (i+1) + "/plugin_id");
      if (plugin_id && kb_plugin_id != plugin_id) continue;
      kb_plugin = get_kb_item(KB_REPORT + (i+1) + "/plugin");
      if (plugin && kb_plugin != plugin) continue;

      plugin_name = get_kb_item(KB_REPORT + (i+1) + "/plugin_name");
      text = get_kb_item(KB_REPORT + (i+1) + "/text");
      ret[j] = {'plugin':kb_plugin, 'text':text};
      if (kb_plugin_id) ret[j]['plugin_id'] = kb_plugin_id;
      if (plugin_name) ret[j]['plugin_name'] = plugin_name;
      j++;
    }
    return ret;
  }

  ##
  # Gets the plugin data associated with the plugin filename, if possible
  #
  # @param [plugin:string] The filename of the plugin to look up
  #
  # @return array An array of plugin data if successful: 'id' and 'name'
  #               NULL for errors
  ##
  function get_plugin_data(plugin)
  {
    var query, row, rows, fn = "get_plugin_data";

    if (empty_or_null(plugin))
      return dbg_log(fn:fn, msg:"Missing 'plugin' argument.");
    if (nasl_level() < 6000)
      return dbg_log(fn:fn, msg:"This function requires GizaNE 6.x+.");

    # Check cache first
    if(_plugin_tbl_init())
    {
      query = "SELECT * FROM " + _PLUGIN_TBL + " WHERE plugin_fname = ?";
      rows = query_scratchpad(query, plugin);
      row = rows[0];
      if (!isnull(row)) return {'id':row.id, 'name':row.plugin_name};
    }

    # Check plugins-attributes.db (but not if TESTING)
    if (TESTING) return NULL;
    var path, db = 0;
    if (platform() == 'WINDOWS')
      path = GizaNE_get_dir(N_STATE_DIR) + "\plugins-attributes.db";
    else
      path = GizaNE_get_dir(N_STATE_DIR) + '/plugins-attributes.db';

    db = db_open2(path:path, use_default_key:TRUE, readonly:TRUE);
    if (db <= 0) return dbg_log(fn:fn, msg:
      "Failed to open plugins-attributes.db to look up plugin ID.");

    query = 'SELECT id, plugin_name FROM Plugins WHERE plugin_fname = ?';
    rows = db_query(db:db, query:query, plugin);
    db_close(db);
    row = rows[0];
    if (isnull(row)) return dbg_log(fn:fn, msg:
      "Plugin data not found in database for plugin '" + plugin + "'");

    # Cache result
    query = "INSERT or IGNORE INTO " + _PLUGIN_TBL + " (id, plugin_fname, " +
      "plugin_name) VALUES(?,?,?)";
    query_scratchpad(query, row.id, plugin, row.plugin_name);
    return {'id':row.id, 'name':row.plugin_name};
  }

  ##
  # Initializes table to cache plugin metadata
  #
  # @return bool TRUE or FALSE
  ##
  function _plugin_tbl_init()
  {
    var fn = '_plugin_tbl_init';
    if (_plugin_tbl_has_inited()) return TRUE;

    dbg_log(fn:fn, msg:"Initializing table " + _PLUGIN_TBL);
    query_scratchpad(
      "CREATE TABLE IF NOT EXISTS " + _PLUGIN_TBL + " (" +
        "id           INTEGER PRIMARY KEY NOT NULL, "+
        "plugin_fname CHAR(128) NOT NULL, " +
        "plugin_name  CHAR(1024) NOT NULL" +
      ");");

    return _plugin_tbl_has_inited();
  }

  ##
  # Checks to see if plugin metadata table has been initialized
  #
  # @return bool TRUE or FALSE
  ##
  function _plugin_tbl_has_inited()
  {
    if (_PLUGIN_TBL_INIT) return TRUE;

    var ret = query_scratchpad(
      "SELECT COUNT(1) as cnt FROM sqlite_master WHERE type='table'" +
      " AND name='" + _PLUGIN_TBL + "'");

    if(isnull(ret) || ret[0]["cnt"] == 0) _PLUGIN_TBL_INIT = FALSE;
    else _PLUGIN_TBL_INIT = TRUE;

    return _PLUGIN_TBL_INIT;
  }

  ##
  # Determine whether or not SSH commands have failed due to privilege
  # escalation failures or lack of privilege escalation
  #
  # @return bool TRUE or FALSE
  ##
  function has_ssh_priv_failures()
  {
    # Verify table exists
    var tables = query_scratchpad(
      "SELECT name FROM sqlite_master WHERE type='table' AND " +
      "name='ssh_cmd_log'"
    );
    if(tables[0]['name'] != "ssh_cmd_log")
      return FALSE;

    # Check for failed commands
    var cmd_fail_count = 0;

    var res = query_scratchpad(
      "SELECT 1 FROM ssh_cmd_log WHERE failed_needs_escl=1 OR " +
      "priv_escl_failed=1"
    );
    if(!empty_or_null(res)) cmd_fail_count = len(res);

    return cmd_fail_count > 0;
  }

  ##
  # Determine if any local checks ports or services were detected
  #
  # @return bool TRUE or FALSE
  ##
  function svc_available()
  {
    if (
      # Target is localhost
      check_localhost() ||
      # SSH
      get_service_port_list(svc:'ssh') != 0 ||
      get_kb_item("Ports/tcp/22") ||
      # SMB
      get_service_port_list(svc:'smb') != 0 ||
      get_kb_item("Ports/tcp/139") ||
      get_kb_item("Ports/tcp/445") ||
      !isnull(get_kb_list('SMB/transport')) ||
      # SNMP
      get_service_port_list(svc:'snmp') != 0 ||
      get_kb_item("Ports/udp/161") ||
      # NTP (Citrix Netscaler)
      get_service_port_list(svc:'ntp') != 0 ||
      get_kb_item("Ports/udp/123") ||
      # HTTPS (Palo Alto, ESXi)
      (
        # Only certain webservers are used for local checks
        # First check that a webserver was detected
        ( get_service_port_list(svc:'www') != 0 ||
          get_kb_item("Ports/tcp/443") ) &&
        # Then check that a product that supports
        # HTTPS authentication was detected
        ( get_kb_item("Host/VMware/vsphere") ||
          get_kb_item("www/panweb") )
      ) ||
      # TELNET
      get_service_port_list(svc:'telnet') != 0 ||
      get_kb_item("Ports/tcp/23") ||
      # REXEC
      get_service_port_list(svc:'rexec') != 0 ||
      get_kb_item("Ports/tcp/512") ||
      # RLOGIN
      get_service_port_list(svc:'rlogin') != 0 ||
      get_kb_item("Ports/tcp/513") ||
      # RSH
      get_service_port_list(svc:'rsh') != 0 ||
      get_kb_item("Ports/tcp/514")
    )
      return TRUE;
    return FALSE;
  }

  ##
  # Convenience function for offline testing
  #
  # @return bool TRUE or FALSE
  ##
  function check_localhost()
  {
    local_var localhost_overwrite_value = get_kb_item("Test_Plans/lcx/islocalhost_overwrite");
    if (!empty_or_null(localhost_overwrite_value))
      return localhost_overwrite_value;
    return islocalhost();
  }
}
