#TRUSTED 64318a6816028e1dbbeedb42c35165bc732383dacb4e5ca46c758acc729c913301ce5f2bd41531786ebdcc64935307fe990c8af3c5174f537d502b99e5174a80fcfd615460e7b1631bcbe96b2bbf09330bcb9d3d1ae00d3b7eeaf86f2848afe9424d61d6b579350b35f6d34cd26777379c508040c918b2771c96e9229e992e9a639defa68b7b8c5b8159444ac4f95637badbc20c1d729bc55330f473fdc02a39fbea8b4b2167dab344c7075c544f4d2ff535bdda91d1ded1c45d77d1fbf97fda53d1e757399d11575ddcdcb64418426fbbbecb1755e2d4e44b6576628b788917726e6a0a3d4dd37be8f29c75aa392ddecb6a0ee1b98e890dde7f4e71b92c955c40336ea25c153f728f42dc2b0c45940e7f4449024b8a21b2fa01a43ecd1009579b6dbd538a9be3392219f3a2dd6dc4d16983f5792f616b843867ead7c15d79832555e5ed3a1a3d41476ed28c3b0cf77cd6f528cead03dc462b4dd92d29eb25bdaba0cbf1683252caa654653a69a442378456af11abb7ffc412545a14a3333b3ed555171b2ffc7d720edb2f1e41a4f306c8b479ca0919bdc7ebed7f92847fb0739eac1b9f3d48828262f74c7ebeecc249bb1162eb1488556c9d46c776d33c5ff35aa0cf5f8ac40ac3a4ac8fc3ed78099e38826a4882bf112057941568910dbf63fe7e514e199e5a68fe2d5c1bdd69c71aa03dc04b24f91a3d58bde8c6b8816261
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras.inc
#
# Revision: 1.39

include("spad_log_func.inc");

namespace vcf
{
  ######################
  # Special Snowflakes #
  ######################
  # Items implemented within this file are due to products/vendors/plugin groups
  # that require special implementations of certain features. These are typically
  # re-implementations of the get_app_info() when detections for certain plugins
  # groups do not store the necessary information in one of the usual ways.
  # The primary purpose of this include is to keep things out of the core vcf
  # library and avoid extra bloat and tacked on functionality that is only used
  # in certain, specific scenarios.

  namespace adobe_reader
  {
    ##
    # Get info for Adobe Reader
    # @return an app_info array for Adobe Reader
    ##
    function get_app_info()
    {
      local_var app_info = {};
      local_var install = get_single_install(app_name:"Adobe Reader");
      local_var win_port;

      app_info.app = "Adobe Reader";
      app_info.path = install.path;
      app_info.version = install.version;
      app_info.display_version = install.display_version;

      # use DLL version if > app_info.version
      if (ver_compare(ver:install.DLL_Product_Version, fix:app_info.version, strict:FALSE) == 1)
      {
        app_info.version = install.DLL_Product_Version;
        app_info.display_version = install.DLL_Display_Version;
      }

      app_info.parsed_version = parse_version(app_info.version);

      win_port = get_kb_item("SMB/transport");
      if (!win_port) app_info.port = 445;
      else app_info.port = win_port;

      return app_info;
    }


    # sort constraints to match track.
    # x.y.20zzz = DC Classic
    # x.y.30zzz = DC Continuous
    # https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/whatsnewdc.html

    # @param max_segs Limits the number of segments of the detected version used to max_segs
    #   - We do this because reader/acrobat versions can have 4 segments, but
    #     the listed affected / fixed versions only refer to 3.
    #     So, affected 15.6.30355 effectively means < 15.6.30356 affected
    #     but our current (Jan 2019) max_versions don't account for this.

    function check_version_and_report(app_info, constraints, severity, flags, max_segs)
    {
      local_var filtered_constraints, constraint, split_ver, max_segs_parts, i;

      if (!isnull(max_segs))
      {
        max_segs_parts = make_list();
        split_ver = split(app_info.version, sep:'.', keep:FALSE);
        for (i = 0; i < max_segs; i++)
        {
          if (!isnull(split_ver[i]))
          {
            max_segs_parts[i] = int(split_ver[i]);
          }
        }
        app_info.version = join(max_segs_parts, sep:".");
        app_info.parsed_version = parse_version(app_info.version);
      }

      filtered_constraints = make_list();

      foreach constraint (constraints)
      {
        if (app_info.version =~ "^\d+\.\d+\.20\d+" && constraint.fixed_version !~ "^\d+\.\d+\.20\d+" ||
            app_info.version =~ "^\d+\.\d+\.30\d+" && constraint.fixed_version !~ "^\d+\.\d+\.30\d+" )
          continue;
        else 
          filtered_constraints = make_list(filtered_constraints, make_list2(constraint));
      }

      if (max_index(filtered_constraints) == 0)
      {
        # not affected
        vcf::audit(app_info);
      }
      else
      {
        vcf::check_version_and_report(
          app_info:app_info,
          constraints:filtered_constraints,
          severity:severity,
          flags:flags
        );
      }
    }
  }

  namespace apple
  {
    ##
    # Get info for Apple Safari
    # @return an app_info array for Apple Safari
    ##
    function get_safari_info()
    {
      local_var app_info = {"app" : "Safari"};

      get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
      app_info.path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
      app_info.version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);
      app_info.parsed_version = parse_version(app_info.version);

      return app_info;
    }

    ##
    # Get info for macOS or OS X
    # @return an app_info array for macOS
    ##
    function get_macos_info()
    {
      local_var os, c, matches, version;
      os = get_kb_item("Host/MacOSX/Version");
      if (!os)
      {
        os = get_kb_item_or_exit("Host/OS");
        if ("Mac OS X" >!< os) ::audit(AUDIT_OS_NOT, "macOS / Mac OS X");

        c = get_kb_item("Host/OS/Confidence");
        if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
      }
      if (!os) ::audit(AUDIT_OS_NOT, "macOS / Mac OS X");

      matches = pregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
      if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

      version = matches[1];

      return { "version":version, "parsed_version":parse_version(version) };
    }

    ##
    # Check if the macOS version of the host meets the required version
    #
    # @param restrictions  a list of macOS version that the host is required to be
    # @return NULL or audits
    # @remark This assumes OS version values have 2 or 3 segments. Another other amount
    #         of segments will raise an error.
    ##
    function check_macos_restrictions(restrictions)
    {
      local_var restriction, tmp, upper_bound;
      local_var os = get_macos_info();
      local_var constraints = {};
      local_var i = 0;

      foreach restriction (restrictions)
      {
        # Build fixed_version (used to set upper bounds for the constraint)
        tmp = parse_version(restriction);
        upper_bound = string(tmp[0][0]) + "." + string(int(tmp[0][1]) + 1);

        # Add constraint
        constraints[i++] = { min_version : restriction, fixed_version : upper_bound};
      }

      if (!check_version(version:os.parsed_version, constraints:constraints))
        return vcf_exit(0, "The remote host's OS (macOS " + os.version + ") is not an affected macOS / Mac OS X version (" + join(restrictions, sep:", ") + ").");
    }
  }

  namespace bind
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta, 'P':1});
      add_separator('-');
    }

    ##
    # Filters out constraints based on version.
    # Basically, "-S" versions should only be checked
    # against each other since these versions, while
    # applicable to other releases, are paid releases
    # that not all customers have access to
    #
    # @param  constraints  list of constraints to validate
    # @param  version      the version of bind to validate with
    #
    # @return array of constraints
    ##
    function filter_constraints(constraints, version)
    {
      local_var i, value, filtered_constraints, matched_versions;
      filtered_constraints = make_list();
      # regex101.com test link matching 500+ isc bind releases: https://regex101.com/r/PYTeYo/4/tests
      matched_versions = pregmatch(pattern:"^[0-9]\.[0-9]+(\.[0-9]+($|-W[0-9]|rc[0-9]+|(((-(P|S)[0-9])(-W[0-9])*))$|(a|b|beta)[0-9]$)|-ESV(-R[0-9]+.*|b[0-9])*)", string:version);
      if(!empty_or_null(matched_versions))
      { 
        if ("-S" >< version) # Remove non-subscriber-only constraints
        {
          for (i=0; i<max_index(constraints); i++)
            # some -S versions leverage patches which point to a non-S/Non-P solution - e.g. cve-2018-5738
            # so let's perform the -S check against the min/max versions only and allow the fixed version
            # to be displayed regardless
            if ( "-S" >< constraints[i].min_version || "-S" >< constraints[i].max_version || "-S" >< constraints[i].equal)
              filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
        }
        else # Remove subscriber-only constraints
        {
          for (i=0; i<max_index(constraints); i++)
            if ("-S" >!< constraints[i].fixed_version && "-S" >!< constraints[i].fixed_display)
              filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
        }
      }
      else{
        spad_log(message:"auditing out - ["+version+"]");
        set_kb_item(name: 'bind/'+version+'/backported', value:TRUE);
	::audit(AUDIT_BACKPORT_SERVICE, 53, "Bind Server");
      }
      return filtered_constraints;
    }
  }

  namespace ibm
  {
    ##
    # Verify that the required websphere mq components are installed
    # and that the install is of the desired flavor
    #
    # @param  app_info            an app_info structure for websphere mq
    # @param  required_flavor     the required application flavor
    # @param  required_component  a required component
    #
    # @return NULL or audit
    ##
    function verify_websphere_mq_component(app_info, required_flavor, required_component)
    {
      local_var installed_components, installed_component, required_component_is_present;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);

      if (!isnull(required_flavor))
        if (tolower(required_flavor) != tolower(app_info['Type']))
          ::audit(AUDIT_NOT_INST, "IBM WebSphere MQ type '" + required_flavor + "'");

      # Check or ignore components (explorer, javamsg, server, ...)
      if (!isnull(required_component))
      {
        installed_components = split(app_info['Components'], sep:",", keep:FALSE);

        foreach installed_component (installed_components)
        {
          installed_component = ereg_replace(
            string:installed_component,
            pattern:" ",
            replace:""
          );

          if (tolower(installed_component) == tolower(required_component))
            return;
        }

        ::audit(AUDIT_NOT_INST, "IBM WebSphere MQ component '" + required_component + "'");
      }
    }

    namespace spectrum_protect
    {
      function get_app_info(port)
      {
        local_var win_local;
        local_var app_info;

        if (get_install_count(app_name:"IBM Spectrum Protect") > 0)
        {
          if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;
          app_info = vcf::get_app_info(app:"IBM Spectrum Protect", win_local:win_local);
        }
        else if (get_install_count(app_name:"IBM Tivoli Storage Manager") > 0 && port > 0)
        {
          app_info = vcf::get_app_info(app:"IBM Tivoli Storage Manager", port:port, service:TRUE);
        }
        else
        {
          vcf::audit();
        }

        return app_info;
      }
    }
  }

  namespace idrac
  {
    function get_app_info(port)
    {
      local_var app_info = {};
      local_var install = get_single_install(app_name:"iDRAC", port:port);

      app_info.idrac = install['version'];
      app_info.version = install['Firmware Version'];
      app_info.parsed_version = parse_version(app_info.version);
      app_info.path = install['path'];
      app_info.display_version = "iDRAC" + app_info.idrac + " with firmware " + app_info.version;
      app_info.port = port;
      app_info.webapp = TRUE;

      return app_info;
    }

    # filter out only the constraints for the idrac version we are running
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var i;
      local_var filtered_constraints;
      filtered_constraints = make_list();

      for (i=0; i<max_index(constraints); i++)
      {
        if (constraints[i]["idrac"] == app_info.idrac)
        {
          constraints[i]['fixed_display'] = "iDRAC" + app_info.idrac + " with firmware " + constraints[i]['fixed_version'];
          filtered_constraints = make_list(filtered_constraints, make_list2(constraints[i]));
        }
      }

      if (max_index(filtered_constraints) == 0)
      {
        # not affected
        vcf::audit();
      }
      else
      {
        vcf::check_version_and_report(
          app_info:app_info,
          constraints:filtered_constraints,
          severity:severity,
          flags:flags
        );
      }
    }
  }

  namespace imagemagick
  {
    ##
    # Adds additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_separator('-');
    }

    function get_app_info()
    {
      local_var port = get_kb_item('SMB/transport');
      if(!port) port = 445;
      return vcf::get_app_info(app:'ImageMagick', port:port, kb_ver:'installed_sw/ImageMagick/vcf_version');
    }
  }

  namespace check_mk
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'i':conversions.alpha, 'b':conversions.beta});
    }
  }

  namespace apache_storm
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'incubating':-125, 'security':1});
    }
  }

  namespace agilebit_1password
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'ALPHA':conversions.alpha, 'BETA':conversions.beta});
      add_separator('-');
    }
  }
  
  namespace atlassian_sourcetree
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta});
    }
  }

  namespace pfsense_webui
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'RC':conversions.rc});
      add_separator('-');
    }

    function get_app_info(port)
    {
      local_var app_info = {};
      local_var pfversion, pfbuild, pfpatch;
      local_var install = get_single_install(app_name:"pfSense", port:port);
          
      # version . build . patch
      # Where :
      # version - main product version, e.g., 2.3
      # build   - convert string 'RELEASE' to 0 or leave RC alone as integer (RC1 == 1 via VCF)
      # patch   - should just be an integer (p1 == 1 via VCF)
      #
      # 2.3-RELEASE      becomes 2.3
      # 2.4.2-RELEASE-p1 becomes 2.4.2.0.1
      # 2.4.2-RC1        becomes 2.4.2.-1.1.0
      # 2.0-RC1          becomes 2.0.-1.1.0

      pfversion = install.version;

      if (!empty_or_null(install.Build) && install.Build == 'RELEASE')
        pfbuild = "";
      else
        pfbuild = install.Build;

      if (!empty_or_null(install.Patch))
        pfpatch = install.Patch;
      else
        pfpatch = 0;

      app_info.version = pfversion + "." + pfbuild + "." + pfpatch;
      app_info.parsed_version = parse_version(app_info.version);
      app_info.path = install.path;
      app_info.display_version = install.display_version;
      app_info.port = port;
      app_info.webapp = TRUE;
                               
      return app_info;
    }
  }

  namespace pfsense
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'RC':conversions.rc});
      add_separator('-');
    }

    function get_app_info(port)
    {
      local_var app_info = {};
      local_var version, display_version, build, patch, source;

      # version . build . patch
      # Where :
      # version - main product version, e.g., 2.3
      # build   - convert string 'RELEASE' to 0 or leave RC alone as integer (RC1 == 1 via VCF)
      # patch   - should just be an integer (p1 == 1 via VCF)
      #
      # 2.3-RELEASE      becomes 2.3.0
      # 2.4.2-RELEASE-p1 becomes 2.4.2.0.1
      # 2.4.2-RC1        becomes 2.4.2.-1.1.0
      # 2.0-RC1          becomes 2.0.-1.1.0

      display_version = get_kb_item("Host/pfSense/Full Version");
      version = get_kb_item("Host/pfSense/Version");
      build   = get_kb_item("Host/pfSense/Build");
      patch   = get_kb_item("Host/pfSense/Patch");
      source  = get_kb_item("Host/pfSense/source");

      initialize();

      if (empty_or_null(build) || build == 'RELEASE')
        build = 0;

      if (empty_or_null(patch))
        patch = 0;

      if (empty_or_null(version) || version == UNKNOWN_VER)
        app_info.version = UNKNOWN_VER;
      else
        app_info.version = version + "." + build + "." + patch;

      app_info.source  = source;
      app_info.parsed_version  = parse_version(app_info.version);
      app_info.display_version = display_version;

      return app_info;
    }

    ##   
    # Wrapper for vcf::check_version_and_report mainly to account for fixed versions with patches 
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var i, matches, ver_parts;

      if (empty_or_null(app_info.version) || app_info.version == UNKNOWN_VER)
        vcf::audit(AUDIT_UNKNOWN_DEVICE_VER, "pfSense");

      for (i=0; i<max_index(constraints); i++)
      {
        # Fixed versions with a patch need special handling
        if (constraints[i].fixed_version =~ "-p")
        {
          # SNMP banner does not include any patch info so, for same version, only flag if paranoid
          if (app_info.source == "SNMP" && report_paranoia < 2)
          {
            ver_parts = split(constraints[i]['fixed_version'], sep:"-", keep:FALSE);
            if (ver_compare(ver:app_info.version, fix:ver_parts[0], strict:FALSE) == 0)
            {
              ::audit(AUDIT_POTENTIAL_VULN, "pfSense", app_info.display_version);
            }
          }

          # Versions without a build but with a patch (e.g. 2.3.1-p1) need to be converted
          # to account for the omitted 'RELEASE' build (e.g. 2.3.1.0.1)
          matches = pregmatch(string:constraints[i].fixed_version, pattern:"^([0-9.]+)-p([0-9]+)$", icase:TRUE);
          if (!isnull(matches))
          {
            constraints[i]['fixed_display'] = constraints[i].fixed_version;
            constraints[i]['fixed_version'] = matches[1] + ".0." + matches[2];         
          }
        }
      }

      vcf::check_version_and_report(
        app_info:app_info,
        constraints:constraints,
        severity:severity,
        flags:flags
      );  
    }
  }

  namespace postgresql 
  {

    ##   
    # Wrapper for vcf::check_version_and_report to get extra reporting
    ##
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if (!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if (isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, severity:severity, flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf::vcf_exit(0);
    }


      function report_results(app_info, fix, severity, flags)
      {
        local_var report, version, port, app_source, database;

        if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
        if (isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
        if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

        if (isnull(app_info.display_version)) version = app_info.version;
        else version = app_info.display_version;

        report = '';
        if(app_info.port)
        {
          app_source = get_kb_item_or_exit('database/'+app_info.port+'/postgresql/source');
          database = get_kb_item('database/'+app_info.port+'/postgresql/database_name');
        }

        if(database)
          report += '\n  Database name     : ' + database ;
        if(app_source)
          report +=  '\n  Version source    : ' + app_source;
        report +=
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix + '\n';
        if (vcf::is_error(report)) return vcf::vcf_exit(1, report.message);

        port = app_info.port;
        if (isnull(port)) port = 0;

        security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
        return vcf::vcf_exit(0);

      }

  }

    namespace microsoft_idm
  {
    ##
    # Get info for IDM products
    # @return an app_info array for Apple Safari
    ##
    function get_idm_info()
    {
      local_var app_info = {};

      get_kb_item_or_exit("SMB/Microsoft IDM/installed", exit_code:0);
      app_info["Service and Portal"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Service and Portal/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Service and Portal/path")
      };
      app_info["Synchronization Service"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Synchronization Service/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Synchronization Service/path")
      };
      app_info["Certificate Management"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Certificate Management/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Certificate Management/path")
      };
      app_info["CM Client"] = {
        'version': get_kb_item("SMB/Microsoft IDM/CM Client/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/CM Client/path")
      };
      app_info["CM Bulk Client"] = {
        'version': get_kb_item("SMB/Microsoft IDM/CM Bulk Client/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/CM Bulk Client/path")
      };
      app_info["Add-ins and Extensions"] = {
        'version': get_kb_item("SMB/Microsoft IDM/Add-ins and Extensions/version"),
        'path' : get_kb_item("SMB/Microsoft IDM/Add-ins and Extensions/path")
      };

      return app_info;
    }

    # Wrapper to handle checking / reporting for all components
      function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver, checks, parsed_version;
      local_var component, port, report, vuln;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      report = '\nThe following Microsoft Identity Manager components are affected:\n';
      vuln = 0;
      foreach component (keys(app_info))
      {
        report_ver = app_info[component]['version'];
        checks = constraints[component];
        if(isnull(report_ver) || isnull(checks))
          continue;
        parsed_version = parse_version(report_ver);
        matching_constraint = vcf::check_version(version:parsed_version, constraints:checks, strict:FALSE);
        if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

        if (!isnull(matching_constraint))
        {
          vuln++;
          fix = matching_constraint.fixed_display;
          if (isnull(fix)) fix = matching_constraint.fixed_version;

          report += '\n  ' + component;
          report += '\n  Installed version : ' + report_ver;
          report += '\n  Fixed version     : ' + fix + '\n';
        }
      }
      port = get_kb_item("SMB/transport");
      if(isnull(port)) port = 445;

      if(vuln)
        security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      else vcf::audit();

      return vcf::vcf_exit(0);
    }

  }

  namespace axis
  {
    function get_app_info()
    {
      local_var app_info = {};
      local_var installs, install, pref_install, i;

      installs = get_combined_installs(app_name:"AXIS device", exit_if_not_found:TRUE);
      installs = installs[1];

      pref_install = 0;
      for (i = 0; i < max_index(installs); i++)
      {
        if (installs[i]['confidence'] > installs[pref_install]['confidence'])
          pref_install = i;
      }
      install = installs[pref_install];

      app_info.version = install['version'];
      app_info.parsed_version = parse_version(app_info.version);
      app_info.port = install['port'];
      app_info.model = install['model'];

      return app_info;
    }
    function generate_constraints(app_info, patch_array)
    {
      local_var contraints = [];
      local_var version_list, min_ver, max_ver, last_ver, fix_ver, maj_ver, i;

      if (!app_info) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (!patch_array) return vcf::arg_error(arg:"patch_array", func:FUNCTION_NAME);

      version_list = patch_array[app_info.model];
      if (!version_list)
        vcf::audit();

      foreach fix_ver (version_list)
      {
        maj_ver = split(fix_ver, sep:'.', keep:FALSE);
        maj_ver = maj_ver[0];
        if (maj_ver > max_ver)
          max_ver = maj_ver;
      }

      for (i = 0; i <= max_ver; i++)
      {
        foreach fix_ver (version_list)
        {
          maj_ver = split(fix_ver, sep:'.', keep:FALSE);
          maj_ver = maj_ver[0];
          if (maj_ver == i)
          {
            if (last_ver == 0)
            {
              constraints = make_list(constraints, [{ "fixed_version" : fix_ver }]);
              last_ver = maj_ver;
            }
            else
            {
              constraints = make_list(constraints, [{ "min_version" : string(last_ver + 1), "fixed_version" : fix_ver }]);
              last_ver = maj_ver;
            }
          }
        }
      }
      return constraints;
    }
  }

  namespace xenserver
  {
    function get_app_info()
    {
      local_var app_info, matching_constraint, fix;
      app_info = vcf::get_app_info(app:"Citrix XenServer", kb_ver:"Host/XenServer/version");
      app_info.patches = get_kb_item("Host/XenServer/patches");
      return app_info;
    }
    function check_version_and_report(app_info, severity, constraints, strict, flags)
    {
      local_var matching_constraint, fix, patch, report_items, i, port;
      local_var missing = [];
      local_var ordered_fields = [];

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (!matching_constraint)
        return vcf::audit(app_info);

      if (matching_constraint.fixed_display)
        fix = matching_constraint.fixed_display;
      else if (matching_constraint.fixed_version)
        fix = matching_constraint.fixed_version;

      if (fix)
        vcf::report_results(app_info:app_info, fix:fix, severity:severity, flags:flags);

      if (matching_constraint.patches)
      {
        foreach patch (matching_constraint.patches)
        {
          if (patch >!< app_info.patches)
            missing = make_list(missing, patch);
        }
      }

      if (max_index(missing) > 0)
      {
        report_items['Installed Version'] = app_info.version;
        ordered_fields = make_list(ordered_fields, 'Installed Version');

        if (max_index(missing) == 1)
        {
          report_items['Missing Hotfix'] = missing[0];
          ordered_fields = make_list(ordered_fields, 'Missing Hotfix');
        }
        else
        {
          for (i = 0; i < max_index(missing); i++)
          {
            report_items['Missing Hotfix ' + string(i + 1)] = missing[i];
            ordered_fields = make_list(ordered_fields, 'Missing Hotfix ' + string(i + 1));
          }
        }
        port = app_info.port;
        if (isnull(port)) port = 0;

        security_report_v4(severity:severity, port:port, extra:report_items_str(report_items:report_items, ordered_fields:ordered_fields), xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      }
      else
        vcf::audit(app_info);
    }
  }

  namespace wordpress
  {
    namespace plugin
    {
      function get_app_info(plugin)
      {
        local_var app_info, plugin_info;
        if (isnull(plugin)) return arg_error(arg:"plugin", func:FUNCTION_NAME);

        if (query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'wordpress_plugins';"))
          plugin_info = query_scratchpad("SELECT name, version, friendly_name, path, port
                                          FROM wordpress_plugins WHERE name = ?;", plugin);
        else
          vcf::vcf_exit(0);

        if (plugin_info)
        {
          app_info = branch(plugin_info);
          app_info.parsed_version = vcf::parse_version(app_info.version);
          app_info.webapp = TRUE;
          app_info.app = "WP Plugin: " + app_info.friendly_name;

          return app_info;
        }
        else
          vcf::audit();
      }
    }
  }

  namespace samba
  {
    function get_app_info()
    {
      local_var app_info = {};
      local_var port, lanman, version;

      port = get_kb_item("SMB/transport");
      if (!port) port = 445;

      lanman = get_kb_item_or_exit("SMB/NativeLanManager");
      if ("Samba " >!< lanman) vcf::audit(AUDIT_NOT_LISTEN, "Samba", port);

      version = lanman - 'Samba ';

      app_info.version = version;
      app_info.parsed_version = parse_version(app_info.version);
      app_info.port = port;
      app_info.app = "Samba";

      return app_info;
    }
  }

  namespace joomla
  {
    namespace extension
    {
      function get_app_info(extension, subextension)
      {
        local_var app_info, plugin_info, sp_query, ext_name;
        if (isnull(extension)) return arg_error(arg:"extension", func:FUNCTION_NAME);

        if (query_scratchpad("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'joomla_extensions';"))
        {
          if (subextension)
            plugin_info = query_scratchpad("SELECT
                  joomla_subextensions.'version' AS 'version',
                  joomla_extensions.'pretty_name' AS 'pretty_name',
                  joomla_extensions.'name' AS 'name',
                  joomla_extensions.'port' AS 'port',
                  joomla_extensions.'path' AS 'path',
                  joomla_subextensions.'name' AS 'subextension_name',
                  joomla_subextensions.'version' AS 'version'
                FROM joomla_extensions
                INNER JOIN joomla_subextensions ON joomla_extensions.'id' = joomla_subextensions.'extension_id'
                WHERE joomla_extensions.'extension' = ? AND joomla_subextensions.'subextension' = ?;",
                extension, subextension);
          else
            plugin_info = query_scratchpad("SELECT
                  joomla_extensions.'pretty_name' AS 'pretty_name',
                  joomla_extensions.'name' AS 'name',
                  joomla_extensions.'version' AS 'version',
                  joomla_extensions.'port' AS 'port',
                  joomla_extensions.'path' AS 'path'
                FROM joomla_extensions
                WHERE joomla_extensions.'extension' = ?;",
                extension);
        }
        else
          vcf::vcf_exit(0);

        if (plugin_info)
        {
          app_info = branch(plugin_info);
          app_info.webapp = TRUE;
          app_info.parsed_version = vcf::parse_version(app_info.version);

          if (app_info.pretty_name)
            ext_name = app_info.pretty_name;
          else if (app_info.name)
            ext_name = app_info.name;

          if (ext_name && app_info.subextension_name)
          {
            app_info.app = "Joomla! Extension: " + ext_name + " Subextension: " + app_info.subextension_name;
          }
          else if (ext_name)
          {
            app_info.app = "Joomla! Extension: " + ext_name;
          }
          else
          {
            app_info.app = "Joomla! Extension";
          }

          return app_info;
        }
        else
          vcf::audit();
      }
    }
  }

  namespace oracle_bi_publisher
  {
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver, patch, bundle;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

      if (!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if (isnull(fix)) fix = matching_constraint.fixed_version;
        if (!isnull(matching_constraint.patch)) patch = matching_constraint.patch;
        if (!isnull(matching_constraint.bundle)) bundle = matching_constraint.bundle;

        report_results(app_info:app_info, fix:fix, severity:severity, flags:flags, patch:patch, bundle:bundle);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }
    
    function report_results(app_info, fix, severity, flags, patch, bundle)
    {
      local_var report, version, port;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
      if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(patch)) return arg_error(arg:"patch", func:FUNCTION_NAME);
      if (isnull(bundle)) return arg_error(arg:"bundle", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(
        version:version,
        fix:fix,
        path:app_info.path,
        source:app_info.source,
        webapp:app_info.webapp,
        port:app_info.port,
        patch:patch,
        bundle:bundle
      );
      if (is_error(report)) return vcf_exit(1, report.message);

      port = app_info.port;
      if (isnull(port)) port = 0;

      security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      return vcf_exit(0);
    }

    function build_report(version, path, fix, webapp, port, source, patch, bundle)
    {
      local_var order, report, report_items;

      report_items = {
        "Installed version" : version,
        "Fixed version"     : fix,
        "Required patch"    : patch,
        "Bundled in"        : bundle
      };
      order = ["Installed version", "Fixed version", "Required patch", "Bundled in"];

      if (!empty_or_null(path))
      {
        if (webapp)
        {
          if (isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);
          report_items["URL"] = build_url2(qs:path, port:port);
          order = ["URL", "Installed version", "Fixed version", "Required patch", "Bundled in"];
        }
        else
        {
          report_items["Path"] = path;
          order = ["Path", "Installed version", "Fixed version", "Required patch", "Bundled in"];
        }
      }
      else if (source)
      {
        report_items["Source"] = source;
        order = ["Source", "Installed version", "Fixed version", "Required patch", "Bundled in"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace php
  {
    function initialize()
    {
      add_conversions({'RC':conversions.rc});
    }

    ##
    # Get info for PHP
    # @return an app_info array for PHP
    ##
    function get_app_info(port)
    {
      local_var install = {};
      local_var php, kb_backport, backported;
      local_var parsed_version;

      if (isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);

      install.app = "PHP";

      php = get_php_from_kb(port:port, exit_on_fail:TRUE);

      install.version = php.ver;
      install.source = php.src;

      kb_backport = "www/php/" + port + "/" + install.version + "/backported";
      backported = get_kb_item_or_exit(kb_backport, exit_code:1);
      if (report_paranoia < 2 && backported) ::audit(AUDIT_BACKPORT_SERVICE, port, "PHP " + install.version + " install");

      # Go ahead and parse the app's version here and store it
      parsed_version = parse_version(install.version);
      if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      install.parsed_version = parsed_version;

      return install;
    }
  }

  # HP - Integrated Lights Out
  namespace ilo
  {
        ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta});
    }

    ## 
    # Wrapper for vcf::check_version_and_report to filter out constraints which 
    # don't match the installed version's generation.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var generation = get_kb_item_or_exit('ilo/generation');
      local_var i;
      for (i = 0; i < max_index(constraints); i++)
      {
        if (constraints[i]['generation'] == generation)
        {
          vcf::check_version_and_report(
            app_info:app_info,
            constraints:[constraints[i]],
            severity:severity,
            flags:flags);
        }
      }

      # Generation doesn't match any of constraints so not affected.
      ::audit(
        AUDIT_WEB_APP_NOT_AFFECTED,
        'iLO ' + generation,
        build_url2(qs:app_info.path, port:app_info.port),
        app_info.version);
    }
  }

  namespace grandstream
  {
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if (!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if (isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, severity:severity, flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    function report_results(app_info, fix, severity, flags)
    {
      local_var report, version, port;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(model:app_info.model, version:version, fix:fix, path:app_info.path, source:app_info.source, webapp:app_info.webapp, port:app_info.port);
      if (is_error(report)) return vcf::vcf_exit(1, report.message);

      port = app_info.port;
      if (isnull(port)) port = 0;

      security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      return vcf::vcf_exit(0);
    }

    function build_report(model, version, fix, path, source, webapp, port)
    {
      local_var order, report, report_items;

      report_items = {
        "Model" : model,
        "Installed version" : version,
        "Fixed version" : fix
      };
      order = ["Model", "Installed version", "Fixed version"];

      if (!isnull(path))
      {
        if (webapp)
        {
          if (isnull(port)) return vcf::arg_error(arg:"port", func:FUNCTION_NAME);
          report_items["URL"] = build_url2(qs:path, port:port);
          order = ["URL", "Model", "Installed version", "Fixed version"];
        }
        else
        {
          report_items["Path"] = path;
          order = ["Path", "Model", "Installed version", "Fixed version"];
        }
      }
      else if (source)
      {
        report_items["Source"] = source;
        order = ["Source", "Model", "Installed version", "Fixed version"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace apache_subversion
  {
    function check_version_and_report(app_info, constraints, severity, strict, flags)
    {
      local_var matching_constraint, fix, report_ver;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);
      if (isnull(constraints)) return vcf::arg_error(arg:"constraints", func:FUNCTION_NAME);

      matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
      if (is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

      if (!isnull(matching_constraint))
      {
        fix = matching_constraint.fixed_display;
        if (isnull(fix)) fix = matching_constraint.fixed_version;

        report_results(app_info:app_info, fix:fix, severity:severity, flags:flags);
      }
      # Audit
      else return vcf::audit(app_info);

      return vcf_exit(0);
    }

    function report_results(app_info, fix, severity, flags)
    {
      local_var report, version, port;

      if (isnull(app_info)) return vcf::arg_error(arg:"app_info", func:FUNCTION_NAME);
      if (isnull(fix)) return vcf::arg_error(arg:"fix", func:FUNCTION_NAME);
      if (isnull(severity)) return vcf::arg_error(arg:"severity", func:FUNCTION_NAME);

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      report = build_report(provider:app_info['Packaged with'], version:version, fix:fix, path:app_info.path, source:app_info.source, webapp:app_info.webapp, port:app_info.port);
      if (is_error(report)) return vcf::vcf_exit(1, report.message);

      port = app_info.port;
      if (isnull(port)) port = 0;

      security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
      return vcf::vcf_exit(0);
    }

    function build_report(provider, version, fix, path, source, webapp, port)
    {
      local_var order, report, report_items;

      report_items = {
        "Packaged with" : provider,
        "Installed version" : version,
        "Fixed version" : fix
      };
      order = ["Packaged with", "Installed version", "Fixed version"];

      if (!isnull(path))
      {
        if (webapp)
        {
          if (isnull(port)) return vcf::arg_error(arg:"port", func:FUNCTION_NAME);
          report_items["URL"] = build_url2(qs:path, port:port);
          order = ["URL", "Packaged with", "Installed version", "Fixed version"];
        }
        else
        {
          report_items["Path"] = path;
          order = ["Path", "Packaged with", "Installed version", "Fixed version"];
        }
      }
      else if (source)
      {
        report_items["Source"] = source;
        order = ["Source", "Packaged with", "Installed version", "Fixed version"];
      }

      return report_items_str(report_items:report_items, ordered_fields:order);
    }
  }

  namespace jenkins
  {
    ## 
    # Wrapper for vcf::check_version_and_report to filter out constraints which 
    # don't match the installed version's edition.
    ##
    function check_version_and_report(app_info, constraints, severity, flags)
    {
      local_var edition = app_info['Edition'];
      if (isnull(edition)) return vcf::arg_error(arg:"app_info['Edition']", func:FUNCTION_NAME);
      local_var i;
      for (i = 0; i < max_index(constraints); i++)
      {
        if (constraints[i]['edition'] == edition)
        {
          vcf::check_version_and_report(
            app_info:app_info,
            constraints:[constraints[i]],
            severity:severity,
            flags:flags);
        }
      }

      # Edition doesn't match any of constraints so not affected.
      ::audit(
        AUDIT_WEB_APP_NOT_AFFECTED,
        'Jenkins ' + edition,
        build_url2(qs:app_info.path, port:app_info.port),
        app_info.version);
    }
  }

  namespace commvault
  {

    ##
    # Allow versions / SP to be parsed separately
    # but from same version string by adding conversion
    # 
    # @return app_info
    ##
    function get_webapp_info(port)
    {
      local_var app, parsed_version;
      add_conversions({'SP':0});
      add_separator('-');

      app = vcf::get_app_info(app:"Commvault", webapp:TRUE, port:port);

      if(!isnull(app["Service Pack"]))
        app.version = app.version + "-SP" + app["Service Pack"];

      parsed_version = parse_version(app.version);
      if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      app.parsed_version = parsed_version;

      return app;
    }
  

    function get_app_info_windows()
    {
      local_var app, parsed_version;

      app = vcf::get_app_info(app:"Commvault", win_local:TRUE);
      local_var cvd = app['cvd.exe File Version']; 
      if (isnull(cvd)) return ::audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
      
      # create a simple semantic version
      # if a sp / hf exists tack it onto
      if(!isnull(app["Service Pack"]))
        app.version = app.version + "." + app["Service Pack"];
      else
         app.version = app.version + ".0";
     
      if(!isnull(app["Hotfix Pack"]))
        app.version = app.version + "." + app["Hotfix Pack"];
      else
         app.version = app.version + ".0";

      parsed_version = parse_version(app.version);
      if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

      app.parsed_version = parsed_version;

      return app;
    }
  }

}
