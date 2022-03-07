#TRUSTED 3927a8e351e50d308f772d77cb234feebf472bb20bb957e5b3c13138b64d6a0bb396d25d3c5150d4703b421f6cc13afab83f163404aeddfe11891be372f8cba44e082dcaed4b3d825ce55c9d9c7a9da4f8e9f7eb6d7f7bf3600fe970ee543e27ebd68663aa0acc3451ce91b08440131b7690094b4c253fdf86c529de1523eeeb546f19a1c07b93d92503b1fc3da5e07e345f8dc93557887f4e37c333cbe830de742b52d3872148d73ce998537a1ef83ca62469ff8a23d8faef185040f407bb4f5f4e11d310f89086aed8bc10f7f7dee076eabc0777986a182a9df7bbe505474db5a7c9ed5af30d9177ef5f669138cb50c6b27f00b66859fbd44c477d19b29c75483c3beb75968dfb8251d416a6c835e7da4d2232fd918c88b221ac5cd390264164128392470e27310c22672b07c62ec298423f35a95a9a5e589eee6b8b4bdefd595f277ca38c52d4b391fabfba2a074f1ff0a57ca91fb87ed5a7ed5b72a8f9cc5f97f79da5d7e6f2d87ebb7aace2ca7140c54f1d8f283e522be403b4203370f644ab3603131f4c131f60a31f62b80f1dc23518ed87fc1cc28edae2e352c395cfa86c4be843f264839d2b7f9b016216da004bac669676970f13d430d348c5d42bf454e567bc03dc762692e3aeeb78b864e4bcfac5066d62d5cd2ed4f666148743574834f9caa079046c2afb9c5988593e100daf1bf8919035439767fe5e4288bd
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
# data_protection.inc
#
# Revision: 1.1

#pragma static

include("misc_func_nlib.inc");
include("audit_nlib.inc");

namespace data_protection
{
  global_var username_location_patterns =
  [
    ["/home/", "(?:^|\s)(/home/([^ /]+))"],
    ["/var/spool/mail/", "(?:^|\s)(/var/spool/mail/([^ /]+))"],
    ["/var/lib/sudo/", "(?:^|\s)(/var/lib/sudo/([^ /]+))"],
    ["/export/home/", "(?:^|\s)(/export/home/([^ /]+))"],
    ["\Documents and Settings\", "(?:^|\s)(\w:\\+Documents and Settings\\+([^ \\]+))"],
    ["\Users\", "(?:^|\s)(\w:\\+Users\\+([^ \\]+))"],
    ["/Users/", "(?:^|\s)(/Users/([^ /]+))"],
    ["/private/var/db/sudo/", "(?:^|\s)(/private/var/db/sudo/([^ /]+))"],
  ];

  global_var installed_sw_path_rewrites = make_array();

  # data protection sanitization flags
  global_var DPKB_IPADDR = "DataProtection/ipaddr/enabled";
  global_var DPKB_USERNAME = "DataProtection/username/enabled";
  global_var DPKB_PHONENUMBER = "DataProtection/phonenumber/enabled";
  global_var DPKB_ENABLED = "DataProtection/enabled";

  ##
  # This function can be used to disable a plugin if 
  # data protection flags are enabled
  #
  # @param flags list of data protection sanitization flags 
  # @remark if flags is null it will exit on any data protection being enabled
  #
  # @return NULL, this function either exits or returns nothing
  ##
  function disable_plugin_if_set(flags)
  {
    local_var status, flag;
    status = get_kb_item(DPKB_ENABLED);
    if (!status) return NULL;

    if (isnull(flags) && status) 
      audit(AUDIT_DISABLED_BY_DATA_PROTECTION);

    foreach flag (flags)
    {
      if (is_sanitize_enabled(flag:flag))
        audit(AUDIT_DISABLED_BY_DATA_PROTECTION);
    }
  }

  ##
  # A general function where you can determine if sanitization 
  # is enabled based a kb item flag
  #
  # @param const string , the kb item flag to check against
  # 
  # @return NULL or value of flag if set 
  ##
  function is_sanitize_enabled(flag)
  {
    local_var status;
    status = get_kb_item(flag);
    return status;
  }
  

  ##
  # determines if ipaddresses need sanitized in reports.
  # 
  # @return null if disabled, kb value if enabled
  ##
  function is_sanitize_ipaddr_enabled()
  {
    return is_sanitize_enabled(flag:DPKB_IPADDR);
  }

  ##
  # determine if usernames need sanitized in reports
  # 
  # @return null if disabled, kb value if enabled
  ##
  function is_sanitize_username_enabled()
  {
    return is_sanitize_enabled(flag:DPKB_USERNAME);
  }

  ##
  # determine if phone number needs sanitized in reports
  #
  # @return null if disabled, kb value if enabled
  ##
  function is_sanitize_phonenumber_enabled()
  {
    return is_sanitize_enabled(flag:DPKB_PHONENUMBER);
  }

  ##
  # sanitize the common file paths on a computer that contain
  # a username
  #
  # @param report_text string the file paths each on a new line
  # @remark filtered on username
  # 
  # @return string of sanitized user paths
  ##
  function sanitize_user_paths(report_text)
  {
    local_var res, start_letter, end_letter, name;
    local_var mask_name_seg, name_seg, pattern, mask_name;
    local_var idx, line, lines, names;

    if (!is_sanitize_username_enabled()) return report_text;

    lines = split(report_text, keep:FALSE);
    names = {};
    #Gather names
    foreach line (lines)
    {
      foreach pattern (username_location_patterns)
      {
        #We'll only handle one name per line until we find a report with two

        #The vast majority of report lines will have no names - this is faster
        #than doing multiple regex matches on each line
        idx = stridx(line, pattern[0], 0);
        if(idx < 0)
          continue;

        res = pregmatch(string:line, pattern:pattern[1]);
        if(!isnull(res) && !names[res[2]])
          names[res[2]] = res[1];
      }
    }

    foreach name (keys(names))
    {
      name_seg = names[name];

      start_letter = name[0];
      end_letter = name[strlen(name) - 1];
      mask_name = start_letter + "***" + end_letter;

      mask_name_seg = str_replace(string: name_seg, find: name, replace: mask_name);
      report_text = str_replace(string: report_text, find: name_seg, replace: mask_name_seg);
    }

    return report_text;
  }
  
  ##
  # Create unique list of default accounts for use in redact_etc_passwd()
  # 
  # @return list of default accounts
  ## 
  function get_default_accounts()
  {
    local_var default_accounts = {};

    default_accounts['sshd']               = TRUE;
    default_accounts['root']               = TRUE;
    default_accounts['bin']                = TRUE;
    default_accounts['daemon']             = TRUE;
    default_accounts['lp']                 = TRUE;
    default_accounts['mail']               = TRUE;
    default_accounts['www']                = TRUE;
    default_accounts['wwwrun']             = TRUE;
    default_accounts['www-data']           = TRUE;
    default_accounts['nobody']             = TRUE;
    default_accounts['mail']               = TRUE;
    default_accounts['news']               = TRUE;
    default_accounts['uccp']               = TRUE;
    default_accounts['messagebus']         = TRUE;
    default_accounts['polkituser']         = TRUE;
    default_accounts['haldaemon']          = TRUE;
    default_accounts['at']                 = TRUE;
    default_accounts['uuid']               = TRUE;
    default_accounts['suse-ncc']           = TRUE;
    default_accounts['cseadmin']           = TRUE;
    default_accounts['vscan']              = TRUE;
    default_accounts['vpconfig']           = TRUE;
    default_accounts['dnsmasq']            = TRUE;
    default_accounts['irc']                = TRUE;
    default_accounts['backup']             = TRUE;
    default_accounts['syslog']             = TRUE;
    default_accounts['systemd-timesync']   = TRUE;
    default_accounts['systemd-network']    = TRUE;
    default_accounts['systemd-resolve']    = TRUE;
    default_accounts['systemd-bus-proxy']  = TRUE;
    default_accounts['gnats']              = TRUE;
    default_accounts['admin']              = TRUE;
    default_accounts['sys']                = TRUE;
    default_accounts['sync']               = TRUE;
    default_accounts['man']                = TRUE;
    default_accounts['uucp']               = TRUE;
    default_accounts['proxy']              = TRUE;
    default_accounts['list']               = TRUE;
    default_accounts['_apt']               = TRUE;
    default_accounts['lxd']                = TRUE;
    default_accounts['uuidd']              = TRUE;
    default_accounts['Debian-exim']        = TRUE;
    default_accounts['administrator']      = TRUE;
    default_accounts['ntp']                = TRUE;
    default_accounts['mysql']              = TRUE;
    default_accounts['apache']             = TRUE;
    default_accounts['shutdown']           = TRUE;
    default_accounts['halt']               = TRUE;
    default_accounts['games']              = TRUE;
    default_accounts['ftp']                = TRUE;
    default_accounts['tomcat']             = TRUE;
    default_accounts['postfix']            = TRUE;
    default_accounts['operator']           = TRUE;

    return default_accounts;
  }

  ##
  # Sanitize output for /etc/passwd related plugins
  #
  # @param output the /etc/passwd string value to sanitize
  # @remark filtered on username
  #
  # @return sanitized string
  ## 
  function redact_etc_passwd(output)
  {
    local_var lines, line, pattern, pat_regex, found;
    local_var redact, match_etc, pii, account;
    local_var default_accounts = {};

    if (!is_sanitize_username_enabled()) return output;

    # null/empty check
    if(isnull(output)) return NULL;
    if(output == "") return "";
    # check if output contains /etc/passwd info
    # return untouched output if not
    pattern = "root:.*:0:[01]:";
    match_etc = preg(string:output, pattern:pattern, multiline:TRUE);
    if(!match_etc) return output;

    redact = "<redacted by WebRAY>";
    lines = split(output, keep:FALSE);
    default_accounts = get_default_accounts();
    foreach line (lines)
    {
      if(line !~ "^[a-zA-Z]+:x:[0-9]" || isnull(line)) continue;
      found = FALSE;
      foreach account (keys(default_accounts))
      {
        pat_regex = "^" + account + ":.*";
        match_etc = pregmatch(string:line, pattern:pat_regex);
        if(match_etc) found = TRUE;
      }
      if(!found)
      {
        output = str_replace(string:output, find:line, replace:redact);
      }
    }
    return output;
  }

  ##
  # sanitize output for user enumeration string. This needs to be passed a string of users to be redacted
  # can be single user line or multiple lines (most existing plugins contain multiple line user output).
  # 
  # @param users string of users to sanitize
  # @remark filtered on username
  #
  # @return string of sanitized users.
  ##
  function sanitize_user_enum(users)
  {
    local_var lines, line, start_letter, end_letter, mask_name, user, match_flag, i;
    # NULL/empty check
    if(isnull(users)) return NULL;
    if(users == "") return "";

    if (!is_sanitize_username_enabled()) return users;
    lines = split(users, keep:FALSE);
    for (i=0; i<max_index(lines); i++)
    {
      line = lines[i];
      user = pregmatch(string:line, pattern:"^[ ]+- [a-zA-Z0-9-_]+\\([A-Za-z0-9-_ \$]+)");
      if(!user) user = pregmatch(string:line, pattern:"^uid=([A-Za-z\d_]+)");
      if(!user) user = pregmatch(string:line, pattern:"[ ]+- ([A-Za-z$-].*)");
      if(!user) user = pregmatch(string:line, pattern:"([A-Za-z0-9$-].*)");
      if(user)
      {
        user = chomp(string(user[1]));
        start_letter = user[0];
        end_letter = user[strlen(user) - 1];
        mask_name = start_letter + "***" + end_letter;
        users = str_replace(string:users, find:user, replace:mask_name, count:1);
      }
    }
    return users;
  }

  ##
  # redact user information for integration systems (Dell Kace/SCCM)
  #
  # @param users string of users to sanitize
  # @return string of sanitized output
  ##
  function sanitize_user_integration(users)
  {
    local_var lines, line, user, replace, i;
    if(isnull(users)) return NULL;
    if(users == "") return "";

    if (!is_sanitize_username_enabled()) return users;
    lines = split(users, keep:FALSE);
    for (i=0; i<max_index(lines); i++)
    {
      line = lines[i];
      user = pregmatch(string:line, pattern:"- Last User +: ([A-Za-z0-9].+)");
      if(user && user[1])
      {
        user = chomp(string(user[1]));
        replace = "<user information redacted by WebRAY>";
        users = str_replace(string:users, find:user, replace:replace, count:1);
      }
    }
    return users;
  }

  ##
  # redact full string provided to function. assumes username data is passed.
  #
  # @param output string output to be fully redacted
  # @return string "<user information redacted by WebRAY>"
  ##
  function sanitize_user_full_redaction(output)
  {
    if(isnull(output)) return NULL;
    if(output == "") return "";

    if (!is_sanitize_username_enabled()) return output;

    output = "<user information redacted by WebRAY>";
    return output;
  }

  ##
  # sanitize uid output. return original input if default user found.
  #
  # @param output string containing id command ouput
  #
  # @return string of sanitized id results.
  ##
  function sanitize_uid(output)
  {
    local_var user, lines, line, uid, uid_val, start_letter, end_letter, mask_name;
    local_var account, default_accounts, match_uid, found;
     # NULL / empty check
    if(isnull(output)) return NULL;
    if(output == "") return output;

    if (!is_sanitize_username_enabled()) return output;

    # bail if no uid output
    match_uid = preg(string:output, pattern:"uid=[0-9]+.*gid=[0-9]+.*", multiline:TRUE);
    if(!match_uid) return output;

    default_accounts = get_default_accounts();
    lines = split(output, keep:FALSE);
    foreach line (lines)
    {
      found = FALSE;
      uid = pregmatch(string:line, pattern:"uid=([0-9]+)\(([a-zA-Z0-9$_-]+)\) gid=[0-9]+\(([a-zA-Z0-9$_-]+)\)");
      if(uid && !isnull(uid[1]) && !isnull(uid[2]))
      {
        user = chomp(uid[2]);
        uid_val = chomp(uid[1]);
        foreach account (keys(default_accounts))
        {
          if(user == account)
          {
            found = TRUE;
            break;
          }
        }
        if(found) continue;
        start_letter = user[0];
        end_letter = user[strlen(user) - 1];
        mask_name = start_letter + "***" + end_letter;
        output = str_replace(string:output, find:user, replace:mask_name, count:3);
        output = str_replace(string:output, find:uid_val, replace:"***", count:3);
      }
    }
    return output;
  }

  # Sanitize output for text with a single IPv4 or IPv6
  #
  # @param text the string value to sanitize
  # @remark filtered on ipAddress
  #
  # @return sanitized string OR
  #         original string if there's nothing to sanitize or sanitization is off
  ##
  function sanitize_ip_address(text)
  {
    local_var ip_v4_pattern, ip_v6_pattern, ip_v4_match_results, ip_v6_match_results, new_ip;
    if (!is_sanitize_ipaddr_enabled()) return text;
    if (isnull(text) || !strlen(text)) return text;
    ip_v4_pattern = "\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\." +
                      "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\." +
                      "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\." +
                      "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b";
    ip_v6_pattern = "\b(([0-9a-fA-F]{1,4}:){7})([0-9a-fA-F]{1,4})\b";
    ip_v4_match_results = pregmatch(string:text, pattern:ip_v4_pattern, icase:TRUE);
    ip_v6_match_results = pregmatch(string:text, pattern:ip_v6_pattern, icase:TRUE);
    if (isnull(ip_v4_match_results) && isnull(ip_v6_match_results))
    {
      return text;
    }
    if (! isnull(ip_v4_match_results))
    {
      #IPv4
      new_ip = ip_v4_match_results[1] + '.' + ip_v4_match_results[2] + '.' + ip_v4_match_results[3] + '.0';
      return new_ip;
    }
    else
    {
      #IPv6
      new_ip = ip_v6_match_results[1] + '0';
      return new_ip;
    }
  }

  ##
  # Sanitize output for text with multiple IPv4 or IPv6 entries
  #
  # @param text the string value to sanitize
  # @remark filtered on ipAddress
  #
  # @return sanitized string OR
  #         original string if there's nothing to sanitize or sanitization is off
  ##
  function sanitize_ip_address_multiple(text)
  {
    local_var text_normalize, ip_list, sanitized, word, words;
    if (!is_sanitize_ipaddr_enabled()) return text;
    ip_list = make_array();
    if (isnull(text) || !strlen(text)) return text;
    text_normalize = ereg_replace(string:text, pattern:'(,|\n)', replace:" ");
    words = split(text_normalize, sep:" ", keep:FALSE);
    foreach word (words)
    {
      sanitized = sanitize_ip_address(text:word);
      if (sanitized != word)
      {
        ip_list[word] = sanitized;
      }
    }
    foreach word (keys(ip_list))
    {
      text = ereg_replace(string:text, pattern:word, replace:ip_list[word]);
    }
    return text;
  }

  ##
  # Sanitize output for a single email adddress
  #
  # @param text the string value to sanitize
  # @remark filtered on username
  #
  # @return sanitized string OR
  #         original string if there's nothing to sanitize or sanitization is off
  ##
  function sanitize_email_address(text)
  {
    local_var email_pattern, match_results, user, domain, suffix, email, replacement;
    if (!is_sanitize_username_enabled()) return text;
    if (isnull(text) || !strlen(text)) return text;
    email_pattern = "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})";
    match_results = pregmatch(string:text, pattern:email_pattern, icase:TRUE);
    if (isnull(match_results))
    {
      return text;
    }
    email =  match_results[0];
    user =   match_results[1];
    domain = match_results[2];
    suffix = match_results[3];
    user =   sanitize_userpass(text:user);
    domain = sanitize_userpass(text:domain);
    replacement = user + '@' + domain + '.' + suffix;
    return ereg_replace(string:text, pattern:email, replace:replacement);
  }

  ##
  # Sanitize output for multiple email adddresses
  #
  # @param text the string value to sanitize
  # @remark filtered on username
  #
  # @return sanitized string OR
  #         original string if there's nothing to sanitize or sanitization is off
  ##
  function sanitize_email_address_multiple(text)
  {
    local_var text_normalize, email_list, email, word, words, sanitized, email_pattern;
    if (!is_sanitize_username_enabled()) return text;
    email_list = make_list();
    if (isnull(text) || !strlen(text)) return text;
    text_normalize = ereg_replace(string:text, pattern:'(,|\n)', replace:" ");
    email_pattern = "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})";
    words = split(text_normalize, sep:" ", keep:FALSE);
    foreach word (words)
    {
      if (pregmatch(pattern:email_pattern, string:word))
      {
        email_list = make_list(email_list, word);
      }
    }
    foreach email (email_list)
    {
      sanitized = sanitize_email_address(text:email);
      text = ereg_replace(string:text, pattern:email, replace:sanitized);
    }
    return text;
  }

  ##
  # Sanitize output for phone numbers
  #
  # @param text the string value to sanitize
  # @remark filtered on username
  #
  # @return sanitized string, it's just going to star out all the numbers
  ##
  function sanitize_phone_numbers(text)
  {
    if (isnull(text) || !strlen(text)) return text;
    if (!is_sanitize_phonenumber_enabled()) return text;
    return ereg_replace(string:text, pattern:"\d", replace:"*");
  }

  ##
  # Sanitize output for a single username or password, removes all parts except the first and last letter
  #
  # @param text the string value to sanitize
  # @remark filtered on username
  #
  # @return sanitized string OR
  #         original string if sanitization is off
  ##
  function sanitize_userpass(text)
  {
    local_var firstchar, lastchar;
    if (!is_sanitize_username_enabled()) return text;
    if (isnull(text) || !strlen(text)) return text;
    if (typeof(text) != 'string' && typeof(text) != 'data') return text;
    firstchar = text[0];
    if (strlen(text) < 2)
    {
      lastchar = text[0];
    }
    else
    {
      lastchar = text[strlen(text)-1];
    }
    return firstchar + '*****' + lastchar;
  }

  ##
  # Sanitizes installed_sw base64 modified paths to not include user paths if they do
  #
  # @param kb_key the string value to sanitize
  # @remark filtered on username
  #
  # @return sanitized string OR
  #         original string if there's nothing to sanitize or sanitization is off
  ##
  function sanitize_installed_sw(kb_key)
  {
    local_var key_split, encoded_path, decoded_path, encoded_sanitized, decoded_sanitized, encoded_fixed;

    if (!is_sanitize_username_enabled()) return kb_key;
    if (isnull(kb_key) || !strlen(kb_key)) return kb_key;
    key_split = split(kb_key, sep:'/', keep:FALSE);
    if (max_index(key_split) < 4 || key_split[0] != 'installed_sw') return kb_key;
    # Have to support both port and portless versions
    # "installed_sw/80/zabbix/L3phYmJpeA$$/Source"
    # "installed_sw/Xen Hypervisor/L3Vzci9sb2NhbC9zYmluL3hs/version"
    if (preg(string:key_split[1], pattern:"^\d+$"))
    {
      encoded_path = key_split[3];
    }
    else
    {
      encoded_path = key_split[2];
    }
    if (!isnull(installed_sw_path_rewrites[encoded_path]))
    {
      encoded_sanitized = installed_sw_path_rewrites[encoded_path];
      return str_replace(string:kb_key, find:encoded_path, replace:encoded_sanitized);
    }
    encoded_fixed = str_replace(string:encoded_path, find:'$', replace:'=');
    encoded_fixed = str_replace(string:encoded_fixed, find:'&', replace:'/');
    decoded_path = base64_decode(str:encoded_fixed);
    decoded_sanitized = sanitize_user_paths(report_text:decoded_path);
    if (decoded_sanitized == decoded_path)
    {
      installed_sw_path_rewrites[encoded_path] = encoded_path;
      return kb_key;
    }

    encoded_sanitized = base64(str:decoded_sanitized);
    encoded_sanitized = str_replace(string:encoded_sanitized, find:'=', replace:'$');
    encoded_sanitized = str_replace(string:encoded_sanitized, find:'/', replace:'&');
    installed_sw_path_rewrites[encoded_path] = encoded_sanitized;

    return str_replace(string:kb_key, find:encoded_path, replace:encoded_sanitized);
  }
}
