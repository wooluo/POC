#TRUSTED 515769cecab1d26379dde9d6687b66abcdb0a6a94d90e4f407158a721ed217252a7e8966c5799d8a8d538a0cb00f70f4f8a2f9a1b742520af711fcc43aafd106f82d12ff8bd297749fe3c3d73224a152f7f17a16d8318d1ed73d1f3e55f5f9259ecbe2080e0e8fe95180ce6a1e1b6a2a6c04e0e3dde40b541bda45a4242ba262a249239117ae21b7372b7cf5d7a05a2f056ffc0a239c4a17876a332fefdbef97e9c92859e51eebf7edebecc9ae5c4517bde30cd56649bded1bf9e5bcebf80d653f7f03f1697def0f84f2d933a1bae0ad3dc2c40ce0e023a1315794449b6139e388e6b00ddaae838887cbed88e4ea1ac9093446e117f49f8d0975526289508ea861fe0c0773b9b0ff388df03b771ed429146415c94afe7a994648b49102d0f94cf40700c9222d79d1b711ca19186e5e8204f4c36eed2284ea0b28d064067176ee661308573c2841051a863d3bccef06179d08bbc884b2228b20ec6bd5867e9abee956fc063ac64c4f3a07c2ca6a2a831c9b72284187401761a6b1c1a69dc6cff5b44bd67222df6cc1e62117a5d7670a48cd78192d720452bd4ecdd5c63d99e39490e6b51af1cc3edea935e71f4552def7d440b422663e303a6d832357fee62f47eeee28ed76f5ace67afa0fdf04ad22c8eacb0e1bcc86f3edcfed5916fbd9febbc9b19908941b803cf153690c7180b271bc13616092172246fbe76e550c178096
#
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ccf.inc
#
# Revision: 1.33

include("compat_shared.inc");
include("install_func.inc");
include("lists.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

namespace cisco
{

  global_var PRODUCT_KBS = make_array(
      "Cisco IOS", make_array(
          "version" ,"Host/Cisco/IOS/Version"
          ,"model" ,"Host/Cisco/IOS/Model")
      ,"Cisco IOS XE Software" , make_array(
          "version" ,"Host/Cisco/IOS-XE/Version"
          ,"model" ,"Host/Cisco/IOS-XE/Model")
      ,"Cisco IOS XE SD-WAN Software" , make_array(
          "version" ,"Host/Cisco/SDWAN/Version"
          ,"model" ,"Host/Cisco/SDWAN/Model")
      ,"Cisco IOS XR" , make_array(
          "version" ,"Host/Cisco/IOS-XR/Version"
          ,"model" ,"Host/Cisco/IOS-XR/Model")
      ,"Cisco Identity Services Engine Software", make_array(
          "version" ,"Host/Cisco/ISE/version"
          ,"model" ,"",
          "patches", "Host/Cisco/ISE/patches"
          )
      ,"Cisco Application Control Engine (ACE)" , make_array(
          "version" ,"Host/Cisco/ACE/Version"
          ,"model" ,"")
      ,"Cisco Unified Computing System (Management Software)" ,make_array(
        "version" ,"Host/Cisco/CIMC/version"
        ,"model" ,"Host/Cisco/CIMC/model")
      ,"Cisco Unified Communications Manager" ,make_array(
        "version" ,"Host/Cisco/CUCM/Version"
        ,"display_version", "Host/Cisco/CUCM/Version_Display"
        ,"model" ,"")
      ,"Cisco NX-OS Software" ,make_array(
        "version" ,"Host/Cisco/NX-OS/Version"
        ,"model" ,"Host/Cisco/NX-OS/Model"
        ,"device" ,"Host/Cisco/NX-OS/Device")
      ,"Cisco Email Security Appliance (ESA)" ,make_array(
        "version" ,"Host/AsyncOS/Cisco Email Security Appliance/Version"
        ,"display_version" ,"Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion"
        ,"model" ,"")
      ,"Cisco Content Security Management Appliance (SMA)" ,make_array(
        "version" ,"Host/AsyncOS/Cisco Content Security Management Appliance/Version"
        ,"display_version" ,"Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion"
        ,"model" ,"")
      ,"Cisco Web Security Appliance (WSA)" ,make_array(
        "version" ,"Host/AsyncOS/Cisco Web Security Appliance/Version"
        ,"display_version" ,"Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion"
        ,"model" ,"")
      ,"Cisco APIC"  ,make_array(
        "version" ,""
        ,"model" ,"")
      ,"Cisco Adaptive Security Appliance (ASA) Software" ,make_array(
        "version", "Host/Cisco/ASA"
        ,"model", "Host/Cisco/ASA/model")
      ,"Cisco Wireless LAN Controller (WLC)" ,make_array(
        "version", "Host/Cisco/WLC/Version"
        ,"model", "Host/Cisco/WLC/Model"
        ,"port", "Host/Cisco/WLC/Port")
      ,"Cisco Unity Connection" ,make_array(
        "version", "Host/Cisco/Unity_Connection/Version"
        ,"model", "")
      ,"Cisco Unified Presence" ,make_array(
        "version", "Host/UCOS/Cisco Unified Presence/version"
        ,"model", "")
      ,"Cisco TelePresence VCS" ,make_array(
        "version", "Cisco/TelePresence_VCS/Version"
        ,"model", "")
      ,"Cisco Unified Communications Manager" ,make_array(
        "version", "Host/Cisco/CUCM/Version"
        ,"display_version" ,"Host/Cisco/CUCM/Version_Display"
        ,"model", "")
      ,"Cisco Small Business Series Router Firmware",make_array(
        "version", "Cisco/Small_Business_Router/Version"
        ,"model", "Cisco/Small_Business_Router/Device")
  );

  ##
  # Determines if a Cisco device is a switch
  #
  # @return TRUE if it is known to be a switch OR paranoid > 2
  ##
  function cisco_is_switch()
  {
    if(report_paranoia > 2)  return TRUE;
    return get_kb_item('Host/Cisco/device_type') == 'switch';
  }

  ##
  # Determines if a Cisco device is a router
  #
  # @return TRUE if it is known to be a router OR paranoid > 2
  ##
  function cisco_is_router()
  {
    if(report_paranoia > 2)  return TRUE;
    return get_kb_item('Host/Cisco/device_type') == 'router';
  }

  function get_product_info(name, port)
  {
    # This should check the PRODUCT_KBS array for KBs that do not use
    # register install, otherwise it will default to 

    if(!isnull(PRODUCT_KBS[name]))
    {
      var product_info = make_array();
      var ver_kb = PRODUCT_KBS[name]['version'];
      product_info['version'] = get_kb_item_or_exit(ver_kb);
      var model_kb = PRODUCT_KBS[name]['model'];

      if(model_kb == "")
        product_info['model'] = '';
      else
      {
        product_info['model'] = get_kb_item(model_kb);
        if(isnull(product_info['model']))
          product_info['model'] = '';
      }
      var device_kb = PRODUCT_KBS[name]['device'];
      if(device_kb == "")
        product_info['device'] = '';
      else
      {
        product_info['device'] = get_kb_item(device_kb);
        if(isnull(product_info['device']))
          product_info['device'] = '';
      }
      var display_version = PRODUCT_KBS[name]['display_version'];
      if(display_version == "")
        product_info['display_version'] = '';
      else
      {
        product_info['display_version'] = get_kb_item(display_version);
        if(isnull(product_info['display_version']))
          product_info['display_version'] = '';
      }
      var detection_port = PRODUCT_KBS[name]['port'];
      if(detection_port == "")
        product_info['port'] = 0;
      else
      {
        product_info['port'] = get_kb_item(detection_port);
        if(isnull(product_info['port']))
          product_info['port'] = 0;
      }
      var patches_kb = PRODUCT_KBS[name]['patches'];
      if(patches_kb == "")
        product_info['patches'] = '';
      else
      {
        product_info['patches'] = get_kb_item(patches_kb);
        if(isnull(product_info['patches']))
          product_info['patches'] = '';
      }
    }
    else
    {
      if(isnull(port))
        product_info = get_single_install(app_name:name, exit_if_unknown_ver:TRUE);
      else
        product_info = get_single_install(app_name:name, port:port, exit_if_unknown_ver:TRUE);

      if (!empty_or_null(product_info['Model']) && empty_or_null(product_info['model']))
        product_info['model'] = product_info['Model'];
      if (!empty_or_null(product_info['Version']) && empty_or_null(product_info['version']))
        product_info['version'] = product_info['Version'];
    }

    product_info['name'] = name;
    var sdwan_kb = get_kb_item('Host/Cisco/SDWAN/Version');

    if(product_info['name'] == "Cisco Adaptive Security Appliance (ASA) Software")
      product_info['version'] = extract_asa_version(product_info['version']);
      if (isnull(product_info['version'])) audit(AUDIT_FN_FAIL, 'extract_asa_version');
    else if(product_info['name'] == "Cisco Unified Presence" && !isnull(product_info['version']))
      product_info['version'] = str_replace(string:product_info['version'], find:"-", replace:".");
    else if(product_info['name'] == "Cisco IOS XE Software SDWAN" && !isnull(sdwan_kb))
      {
        product_info['sdwan_version'] = sdwan_kb;
        product_info['version'] = sdwan_kb;
      }

    return product_info;
  }

  ##
  # Wrapper around security_report_cisco to unpack array arguments
  # @reporting array of reporting values
  #
  # @return NULL
  ##
  function security_report_cisco_v2(reporting)
  {
    ##
    # Based on security_report_v4, design for Cisco reporting
    #
    # @param port       Report port number
    # @param proto      Sets the reporting protocol, defaults to tcp
    # @param severity   Report severity (note, warning, hole)
    # @param override   override sate for cisco_caveat
    # @param version    Detected device version
    # @param extra      Any extra text to include in the report output (optional)
    # @param bug_id     Cisco Bug ID (optional)
    # @param fix        Fixed version (optional)
    # @param cmds       List of commands used for confirming that the host is vulnerable (optional)
    # @param pie        Missing IOS XR patch (optional)
    # @param sqli       If TRUE, sets SQLInjection KB item
    # @param xss        If TRUE, sets XSS KB item
    # @param xsrf       If TRUE, sets XSRF KB item
    ##
    var port = reporting['port'];
    var proto = reporting['proto'];
    var severity = reporting['severity'];
    var override = reporting['override'];
    var version = reporting['version'];
    var extra = reporting['extra'];
    var bug_id = reporting['bug_id'];
    var fix = reporting['fix'];
    var cmds = reporting['cmds'];
    var pie = reporting['pie'];
    var sqli = reporting['sqli'];
    var xss = reporting['xss'];
    var xsrf = reporting['xsrf'];
    var disable_caveat = reporting['disable_caveat'];


    # Port, severity, version are all mandatory
    if(isnull(port)) port = 0;
    if(isnull(severity)) exit(1, "security_report_cisco_v2(): parameter severity cannot be null");
    if(isnull(version)) exit(1, "security_report_cisco_v2(): parameter version cannot be null");

    security_report_cisco(
      port:port,
      proto:proto,
      severity:severity,
      override:override,
      version:version,
      extra:extra,
      bug_id:bug_id,
      fix:fix,
      cmds:cmds,
      pie:pie,
      sqli:sqli,
      xss:xss,
      xsrf:xsrf,
      disable_caveat:disable_caveat
    );


    return NULL;
  }

  ##
  # Performs the vulnerability checks for Cisco products
  #
  # @param [product_info:array] array      containing the information of the product being scanned. Required
  # @param [vuln_versions:list]      list of vulnerably versions. Required
  # @param [patched_versions:list]   list of patched versions. Can be NULL.
  # @param [workarounds:array]        array of functions to execute for workaround checks
  # @param [workaround_params:array]
  # @param [models:list]             list of affected models. If NULL, all models are assumed to be affected.
  # @param [required_patch:string]     required patch level
  # @param [reporting:array]          array of reporting info to be passed to security_report_cisco()
  # @param [vuln_ranges:list]          list of arrays of vulnerable ranges with min_ver and fix_ver
  # @param [switch_only:boolean]        vulnerability only applies to switches
  # @param [router_only:boolean]        vulnerability only applies to routers
  # @param [smus:array]              an array with version number keys and values that are smu or service pack names as a list or string
  # @param [require_all_workarounds:boolean]        workarounds should be chained by an and instead of an or
  # @param [firepower_hotfixes:array]   an array with releases like 6.5.0, 6.2.3 as keys and values that are also arrays containing keys of hotfix (with value a string like 'Hotfix_DT-6.2.3.16-3') and ver_compare (with value TRUE or FALSE depending on whether "and later" is specified in the advisory for this hotfix.
  #
  # @return NULL
  ##
  function check_and_report(product_info, vuln_versions, patched_versions, workarounds, workaround_params, models, reporting, vuln_ranges, required_patch, switch_only, router_only, smus, require_all_workarounds, firepower_hotfixes)
  {
    if(isnull(product_info)) exit(1, "cisco_vuln_check(): product_info parameter is required");
    if(isnull(product_info['version'])) exit(1, "cisco_vuln_check(): product_info parameter is missing Version");
    if(isnull(vuln_versions) && isnull(vuln_ranges)) exit(1, "cisco_vuln_check(): vuln_versions or vuln_ranges parameter is required");

    var vuln = FALSE;
    var model_is_vuln = FALSE;

    if(cisco_is_switch() && router_only)
      audit(AUDIT_HOST_NOT, "affected");
    if(cisco_is_router() && switch_only)
      audit(AUDIT_HOST_NOT, "affected");

    # If there is a model parameter, need to check if they match. If no model parameter, all models are assumed to be affected
    if(!isnull(models))
    {
      if(product_info['model'] == '')
        exit(1, 'The model of the device could not be determined');
      var vuln_model = '';
      foreach vuln_model (models)
      {
        if(vuln_model == product_info['model'])
        {
          model_is_vuln = TRUE;
          break;
        }
      }
    }

    var version = product_info['version'];
    var patches = product_info['patches'];

    if(isnull(models) || model_is_vuln)
    {
      if(!isnull(vuln_versions))
      {
        var vuln_ver = '';
        foreach vuln_ver (vuln_versions)
        {
          if(vuln_ver == version)
          {
            vuln = TRUE;
            break;
          }
        }
      }
      if(!isnull(vuln_ranges))
      {
        var range;
        foreach range (vuln_ranges)
        {
          if(isnull(range['min_ver']) || isnull(range['fix_ver'])) exit(1, "cisco_check_and_report():"+
              "vuln_ranges is not properly formatted, it must be a list containing 'min_ver' and 'fixed_ver'");
          # check that the version is greater than or equal to the min ver
          # and less than the fixed version
          if( cisco_gen_ver_compare(a:version, b:range['min_ver']) >= 0 &&
              cisco_gen_ver_compare(a:version, b:range['fix_ver']) < 0
            )
          {
            vuln = TRUE;
            if (isnull(reporting['fix'])) reporting['fix'] = range['fix_ver'];
            break;
          }
          # if required patch passed and version equals fix_ver, check patches
          else if (!empty_or_null(required_patch) &&
            cisco_gen_ver_compare(a:version, b:range['fix_ver']) == 0)
          {
            var patch_missing = TRUE;
            var patch = '';
            patches = split(product_info['patches'], sep:', ', keep:FALSE);

            foreach patch (patches)
            {
              patch = str_replace(string:patch, find:'"', replace:"");
              if(patch >= required_patch)
              {
                patch_missing = FALSE;
                break;
              }
            }
            if (patch_missing)
            {
              vuln = TRUE;
              break;
            }
          }
        }
      }
    }

    if(vuln)
    {
      # We should check SMU patches here
      if(smus)
      {
        var smu_list= get_kb_item('Host/Cisco/SMU');
        if (isnull(smu_list))
        {
          reporting['extra'] = 'Note: We were unable to get the SMU list and thus SMU testing was disabled.';
        }

        var smu = smus[version];
        if (!empty_or_null(smu) && is_list(smu))
        {
          var one_smu;
          foreach one_smu (smu)
            if (one_smu >< smu_list)
              audit(AUDIT_HOST_NOT, 'affected');
        }
        else if (!empty_or_null(smu) && (smu >< smu_list))
        {
          audit(AUDIT_HOST_NOT, "affected");
        }
      }

      # Check for Firepower hotfixes here
      if (firepower_hotfixes)
      {
        var release_ver = pregmatch(string:version, pattern:"^((?:[0-9]+\.){2}[0-9]+)");
        if (!empty_or_null(release_ver))
        {
          release_ver = release_ver[1];
          var hotfix = firepower_hotfixes[release_ver];
          # If "and later" isn't specified in the advisory for this hotfix, search for the hotfix in the output of rpm -qa --last
          if (!hotfix['ver_compare'])
          {
            if (!empty_or_null(hotfix['hotfix']) && hotfix['hotfix'] >< get_kb_item("Host/Cisco/FTD_CLI/1/rpm -qa --last"))
              audit(AUDIT_HOST_NOT, 'vulnerable as a relevant hotfix has been applied');
          }
          # Otherwise, "and later" is present so compare hotfix versions
          else
          {
            var fixed_hotfix_version = pregmatch(string:hotfix['hotfix'], pattern:"Hotfix_[A-Za-z]+-(.*)");
            if (!empty_or_null(fixed_hotfix_version))
            {
              fixed_hotfix_version = fixed_hotfix_version[1];
              fixed_hotfix_version = ereg_replace(string:fixed_hotfix_version, pattern:'-', replace:'.');
              var installed_hotfixes = get_kb_item('Host/Cisco/FTD_CLI/1/hotfix_versions');
              var hotfix_version;
              foreach hotfix_version (split(installed_hotfixes, sep:',', keep:FALSE))
              {
                hotfix_version = ereg_replace(string:hotfix_version, pattern:'-', replace:'.');

                if (ver_compare(ver:hotfix_version, fix:fixed_hotfix_version, strict:FALSE) >= 0)
                  audit(AUDIT_HOST_NOT, 'vulnerable as a relevant hotfix has been applied');
              }
            }
          }
        }
      }

      var result = make_array('flag', vuln, 'override', 0);

      if(get_kb_item('Host/local_checks_enabled'))
      {

        var workaround;
        foreach workaround (workarounds)
        {
          result = workaround(workaround_params);
          # If require_all_workarounds is set to TRUE, chain workarounds with an and. In other words, if even one
          # workaround comes back with a not vulnerable configuration, the host is not vulnerable.
          if (require_all_workarounds)
          {
            if(!result['flag'] && !result['override']) break;
          }
          # By default, workarounds are considered chained by an or
          # Meaning if one workaround comes back with a vulnerable config the host is vulnerable.
          # We do not treat override as a break condition
          else
          {
            if(result['flag'] && !result['override']) break;
          }
        }
        if(!result['flag'] && !result['override']) audit(AUDIT_OS_CONF_NOT_VULN, product_info['name'], version);
      }
      else
      {
        reporting['cmds'] = NULL;
      }

      reporting['override'] = result['override'];
      security_report_cisco_v2(reporting:reporting);
      exit(0);
    }
    else
    {
      audit(AUDIT_HOST_NOT, "affected");
    }
  }

}

