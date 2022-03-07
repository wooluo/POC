#TRUSTED 2329e07cae871b6acd11ca26c33b8e33428d4fe8879fb2ce329991ef637e0e6b5dc8358837dc09a13d9018b87e6211d6ddb60f99e0210219463fe1a0d2e26cccfe650b3cfbc0d0b7f56a24aed300700260508d42131ad431524f8d7341b28011f502ebc100ce4a1de6dac691e37c52095470d1db0bc1f764f626e5338c8d215587dfd644f5b6ccdf2b5439b1efbce3770dd51bec6fa7fffc8eca2adf6327a100af11c4fff1351c7d190b0eb0ee02075d3aa4350ce318213bbb15bf97e173ae7c983bc3cbcf1e1de72258600803881318aad62ee99694e5324a5e4646175b8378715e1366bab87481885f0af1a05aca236cb6c05c2e680ea239f62a86f19f62f01e38788235d7577549cf5f36bd1f25d9ae78d67f147cf3f5dfd328e2250f18e2ac0b32ac42653b3a235d899d7dca24370f12d8a8a868f8d1e7d3ace8280b0629b7d05f871becc9022214d4cc90d0995aff971b5c256ce41b3cbfa9ac706ce4410434b15f7f8d3f725e37b37f8c3b966c9695af582c8883b02193741ea4389f9b1ef7123fe59facb9e26a1e613e3898dbf10e4b022f10df8612b551c4831203cc140ff965549cab34466da04eb70e2941b8378c8fb799abe6405ed9e7550d16a4b524a678f9c0b95f99d29ae3dccc854f7606683550a316ff026ce9db5e572affdfbe09dec714f913fa4b29b59560b1ee834d2dce2efbab88a41ca54eff16ce0f
#
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_fortios.inc
#
# Revision: 1.4

include('hostlevel_funcs.inc');
include('vcf.inc');
include('debug.inc');

namespace vcf
{
  namespace fortios
  {
    ##
    # Checks a fortiOS configuration based on several factors
    #
    # @param test_array    array array of config commands to run and config_value to check for.
    # @param regex         bool that determines whether or not to run full regex on the check
    # @param all_required  bool that determines whether or not the configuration needs all conditions.
    # @param not_equal     bool that determines whether or not to use >< or >!< for config value.	   
    ##

    function fortiOS_config_check (app_info, test_array, show_check, regex, all_required, not_equal, severity, flags)
    {
      local_var test, tester, config_command_formatted, buf, report, port, returned_results;
      test = test_array[0];
      port = 0;
      config_command_formatted = str_replace(string:test.config_command,find:" ", replace:"_");
      buf = get_kb_item('Secret/Host/Fortigate/'+ config_command_formatted);
      report = '';
      if (empty_or_null(buf))
      {
        dbg::log(src:SCRIPT_NAME ,msg:'KB entry for Secret/Host/Fortigate/' + config_command_formatted + 'was not found. Checking Host');

        if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
        if ( islocalhost())
        {
          if ( ! defined_func('pread') ) audit(AUDIT_FN_UNDEF, 'pread');
          info_t = INFO_LOCAL;
        }
        else
        { 
          sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
          if (! sock_g) audit(AUDIT_SOCK_FAIL, app_info.port, 'SSH');
          info_t = INFO_SSH;
        }
  
        buf = ssh_cmd(cmd: 'show '+ test.config_command , nosh:TRUE, nosudo:TRUE, noexec:TRUE);
        if (show_check >!< buf)
        {
          dbg::log(src:SCRIPT_NAME ,msg:'While scanning for '+ test.config_command + 'Item '+ test.config_command +' was not found. Checking for Admin_Readonly');
          buf = ssh_cmd(cmd: 'show full-configuration | grep admin_readonly', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
          if ('admin_readonly' >!< buf)
          {
            report +=
            'Check halted due to inability to access configuration via show command,\n'+
            'And FortiOS account in use by Nessus not in admin_readonly mode.\n'+
            '\n'+
            'Ensure that either that the \'show ' + test.config_command + '\' command can be viewed by the Nessus FortiOS account\n,'+
            'Or set admin_readonly for the Nessus FortiOS account to ensure safe and secure access to your data.';
            fortiOS_config_report(app_info:app_info, report:report, severity:severity, flags:flags);
          }
          buf = ssh_cmd(cmd: 'config global', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
          buf = ssh_cmd(cmd: 'show '+ test.config_command , nosh:TRUE, nosudo:TRUE, noexec:TRUE);  
          if (show_check >!< buf)
          {
          report +=
            '\n  Nessus could not confirm system interface config\n'
            +'  Please ensure the policy settings are correct,\n'
            +'  Including the new "Automatically accept detected SSH disclaimer prompts"\n\n'
            +'  Configuration scan aborted as following configuration group was visible to Nessus: ' + show_check;
	  fortiOS_config_report(app_info:app_info, report:report, severity:severity, flags:flags);
          }
          dbg::log(src:SCRIPT_NAME ,msg:'Config was pulled for ' + test.config_command + ' using an admin_readonly command for safety sake.');
        }
        if (info_t == INFO_SSH) ssh_close_connection();
          set_kb_item(name: 'Secret/Host/Fortigate/' + config_command_formatted, value:buf);
          dbg::log(src:SCRIPT_NAME ,msg:'Secret item Secret/Host/Fortigate/' + config_command_formatted +' was set');
      }
      if (regex)
      {
        dbg::log(src:SCRIPT_NAME ,msg:'Regex test for: '+ tester.config_value + ' started. Not Equal was set to:' + not_equal);
        foreach tester (test_array)
        {
          if (!not_equal && !empty_or_null(pregmatch(string:buf, pattern:tester.config_value, multiline:TRUE)) 
            || not_equal && empty_or_null(pregmatch(string:buf, pattern:tester.config_value)))
          {
            if (!all_required) 
	    {
              dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' condition met. Not All Required. Not Equal was set to:' + not_equal);
              return TRUE;          
            }
          }
          else if (all_required) 
          {
            dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' fail condition met. All Required. Not Equal was set to:' + not_equal);
            return FALSE;
          }
        }
      }
      else
      {
        set_kb_item(name:'Host/Fortigate/ConfigCheckRan/Non-Regex/' + config_command_formatted + '/lookingFor/'+test.config_value, value:TRUE);
        foreach tester (test_array)
        {
          dbg::log(src:SCRIPT_NAME ,msg:'Non-Regex test for: '+ tester.config_value + ' started. Not Equal was set to:' + not_equal);
          if ((not_equal == FALSE && tester.config_value >< buf) || (not_equal == TRUE && tester.config_value >!< buf))
          {
            if (!all_required) 
	    {
              dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' condition met. Not All Required. Not Equal was set to:' + not_equal);
              return TRUE;
            }
          }
          else if (all_required) 
          {
            dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ tester.config_value + ' fail condition met. All Required. Not Equal was set to:' + not_equal);
            return FALSE;}
        }
      }
    if (all_required)
      { 
        dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ config_command_formatted + ' condition met. All Required. Not Equal was set to:' + not_equal);
        return TRUE;
      }
    dbg::log(src:SCRIPT_NAME ,msg:'Test: '+ config_command_formatted + ' condition not met. Not All Required. Not Equal was set to:' + not_equal);
    return FALSE;
    }
      ##
      # Reports a configuration based failure relating to FortiOS, so version is currently not included.
      #
      # @param app_info    array containing application info
      # @param report      string consisting config report generated by fortiOS_config_check
      # @param severity    severity used in reporting
      # @param flags       array of reporting flags (xss, sqli, xsrf)
      #
      # @remark This function exits.
      ##

    function fortiOS_config_report(app_info, report, severity, flags)
    {
      local_var version, port;
      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(report)) return arg_error(arg:"report", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      port = app_info.port;
      if (isnull(port)) port = 0;

      security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      return vcf_exit(0);
    }

      ##
      # Checks a macOS or Mac OS X app_info array version/build and reports results
      #
      # @param app_info      array containing application info
      # @param constraints   list of constraint arrays
      # @param severity      severity used in reporting
      # @param strict        bool that determines whether or not version/fix should
      #                      require the same number of fields
      # @param flags         array of reporting flags (xss, sqli, xsrf)
      #
      # @param vuln_settings array of vulnerable configs to check (after passing version check)
      # @param workarounds   array of workarounds to check for (after failing version check)
      #
      # @param show_check    string the is checked against ot confirm proper config read if not checked against full-configuration
      # @param report        string that included additional item to add to any fail report,
      #                      describing vuln settings that either does or could exist.
      #
      # @param regex         bool that determines whether or not to run full regex on the check
      # @param all_required  bool that determines whether or not the configuration needs all conditions.
      # @param not_equal     bool that determines whether or not to use >< or >!< for config value.
      #
      # @remark This function exits.
      ##
    function check_version_and_report(app_info, severity, constraints, workarounds, vuln_settings, show_check, report, regex, all_required, not_equal, strict, flags)
    {
      local_var matching_constraint, workaround_check, vuln_config_check;
      local_var fix = '';
      if (empty_or_null(regex)) regex = FALSE;
      if (empty_or_null(all_required)) all_required = FALSE;
      if (empty_or_null(not_equal)) not_equal = FALSE;
      if (empty_or_null(report)) report = "";
      if (empty_or_null(show_check)) show_check = "config system";
      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if(empty_or_null(matching_constraint))
      {
        if(!empty_or_null(vuln_settings)) 
        {
          vuln_config_check = vcf::fortios::fortiOS_config_check(app_info:app_info, test_array:vuln_settings, show_check: show_check, regex:regex, all_required:all_required, not_equal:not_equal, severity:severity, flags:flags); 
	  if (vuln_config_check == TRUE)
            fortiOS_config_report(app_info:app_info, report:report, severity:severity, flags:flags);
        }
        audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version);
      }
      if (is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);
      if(!empty_or_null(matching_constraint.fixed_display))
        fix = matching_constraint.fixed_display;
      else
        fix = matching_constraint.fixed_version;
      if (!empty_or_null(matching_constraint.fixed_build) &&
        !empty_or_null(matching_constraint.max_version) &&
        vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict) == 0)
      {
        if (empty_or_null(app_info.build) && report_paranoia < 2) vcf::vcf_exit(1, 'Unable to determine FortiOS build.');
        audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version);
      }
      if(!empty_or_null(workarounds)) 
      {
          workaround_check = vcf::fortios::fortiOS_config_check(app_info:app_info, test_array:workarounds, show_check: show_check, regex:regex, all_required:all_required, not_equal:not_equal, severity:severity, flags:flags);
          if (workaround_check == TRUE)   audit(AUDIT_INST_VER_NOT_VULN, app_info.app , app_info.version);
      }
      vcf::report_results(app_info:app_info, fix:fix, severity:severity, flags:flags);
    }

    ##
    # Check if the model indicates it's a fortigate and bail if it isn't.
    # This function does not return a value, but audits if the model doesn't check out.
    #
    # @param check_model  defaults to fortigate, but specify model you're looking for if it's something else
    # @param model_kb     kb that holds the model, defaults for fortigate
    #
    # @return value of next segment (string)
    ##
    function verify_model(model_check, model_kb)
    {
      if (empty_or_null(model_check)) model_check = "fortigate";
      if (empty_or_null(model_kb)) model_kb = "Host/Fortigate/model";
      var product_model = get_kb_item_or_exit(model_kb);

      if (!preg(string:product_model, pattern:model_check, icase:TRUE))
      {
        if (TAP) return vcf::vcf_exit(0);
        var audit_str = 'a ' + model_check + ' device';
        ::audit(AUDIT_HOST_NOT, audit_str);
      }
    }
  }
}
