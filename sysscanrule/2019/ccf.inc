#TRUSTED 380cdff759d36882228376e58a08168e445f18975e66fc651932c3ef42321a493960fbeadda5b5ac1b5347c56b3486bf6bd535c6e27515962bcdcd15f3c73cb5ce53046155d3c9c5c860eb604393b420f7991fbe2b6d466fef2d755a76f6734fd0f1cda0e7af43ce8d1d8bc09310e6595524f9a23c010b77814a726b10f33c0486ed423e204ae428c621c8d1be0860a2198ebbce6fad81040a33a09a67945f5769b2a3551db8f3fc087c9b699bcb09673724c059a949bdf9eab6481862688194528f9f9c5b6cfb31e6a5710dc6535689d72aa7f6eea44317e7e6e62a9f3a10f7bc688789a48ac8ea6c77132cb801c3fa4a8aa121b154176cd07bc0a0a5933161ea7ffd64adda5741184fe0eccf40de3df5f3cb21914357d855e3ef19e15afe41323ab92124fb075942e20c942c0874eca907704651e580a1808413c731c3e3dfe28e534ab387c0fe8c5396fa240a1a2436f59609af8abacd71e25d38e5fad2f2194f67370791f2ca8a3486e5dbc1bc0f381a68cb53a5d36141a73ed815b0e8562676b4b83d7e87763994a4ed0b33c73a3bcf7fd2908500edcd21503f75d53d30a7a190fa14378b7f820120ae4a95eef2ec6c4ecd4c86c7a56b58a5ddf49abd4843ea0f2fc422bac6576a40b833d887d495825ae169d354fa47ffc65037cd9001a0150dd8b0dda6b6b414aeb9c6bb3938033a5dcd7870b60f0fbb6eec012079d4
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# ccf.inc
#
# Revision: 1.22

include("global_settings_nlib.inc");
include("install_func.inc");
include("lists.inc");
include("cisco_func.inc");
include("audit_nlib.inc");
namespace cisco
{

  PRODUCT_KBS = make_array(
      "Cisco IOS", make_array(
          "version" ,"Host/Cisco/IOS/Version"
          ,"model" ,"")
      ,"Cisco IOS XE Software" , make_array(
          "version" ,"Host/Cisco/IOS-XE/Version"
          ,"model" ,"Host/Cisco/IOS-XE/Model")
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
        ,"model", "Host/Cisco/WLC/Model")
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
      ,"Cisco Small Business RV Series Router Firmware",make_array(
        "version", "Cisco/Small_Business_Router/Version"
        ,"model", "Cisco/Small_Business_Router/Device")
  );

  function get_product_info(name, port)
  {
    # This should check the PRODUCT_KBS array for KBs that do not use
    # register install, otherwise it will default to register_install
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
    }

    product_info['name'] = name;
    if(product_info['name'] == "Cisco Adaptive Security Appliance (ASA) Software")
      product_info['version'] = extract_asa_version(product_info['version']);
      if (isnull(product_info['version'])) audit(AUDIT_FN_FAIL, 'extract_asa_version');
    else if(product_info['name'] == "Cisco Unified Presence" && !isnull(product_info['version']))
      product_info['version'] = str_replace(string:product_info['version'], find:"-", replace:".");

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
  #
  # @return NULL
  ##
  function check_and_report(product_info, vuln_versions, patched_versions, workarounds, workaround_params, models, reporting, vuln_ranges, required_patch, switch_only, router_only)
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
      var result = make_array('flag', vuln, 'override', 0);

      if(get_kb_item('Host/local_checks_enabled'))
      {

        # Workarounds are considered chained by an or
        # Meaning if one workaround comes back with a vulnerable config the host is vulnerable.
        # We do not treat override as a break condition
        var workaround;
        foreach workaround (workarounds)
        {
          result = workaround(workaround_params);
          if(result['flag'] && !result['override']) break;
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
