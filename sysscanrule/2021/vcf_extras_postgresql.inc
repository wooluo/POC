#
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras_postgresql.inc
#
# Revision: 1.1

include("compat_shared.inc");
include("lists.inc");
include("vcf.inc");
include("backport.inc");

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

    ##
    # Wrapper for vcf::get_app_info to take into account win_local
    # May audit or exit.
    ##
    function get_app_info(app, port, kb_ver, kb_base, win_local)
    {
      var app_info = NULL;

      if (empty_or_null(app)) vcf::vcf_exit(1, 'get_app_info(): invalid app parameter');
      if (empty_or_null(win_local)) win_local = FALSE;

      if (!empty_or_null(kb_ver))
      {
        if (empty_or_null(kb_base)) vcf::vcf_exit(1, 'get_app_info(): invalid kb_base parameter');
        var kb_backport = NULL;
        var source = get_kb_item(kb_base + 'source');

        if (source)
        {
          get_backport_banner(banner:source);
          if (backported)
            kb_backport = kb_base + 'backported';
            
          app_info = vcf::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);
        }
      }
      else
        app_info = vcf::get_app_info(app:app, win_local:win_local);
      
      if (empty_or_null(app_info)) ::audit(AUDIT_PACKAGE_NOT_INSTALLED, app);

      return app_info;
    }
  }
}
