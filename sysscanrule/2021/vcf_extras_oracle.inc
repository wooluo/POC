include('compat_shared.inc');
include('debug.inc');
include('lists.inc');
include('oracle_rdbms_cpu_func.inc');
include('vcf.inc');

namespace vcf
{
  namespace oracle_rdbms
  {

    ##
    # Returns detected installs in a format VCF can make vulnerability determinations on
    # @return app_info [Array] An array describing a detected install.
    # Audits if No installs are found
    # Note: This function branches.
    ##
    function get_app_info() {
        local_var installs = _get_installs();
         if (empty_or_null(installs)) 
            audit(AUDIT_NOT_INST, 'Oracle Database');
        
        local_var install = branch (installs);
        return _convert_install_to_app_info(install:install);
    }

    ##
    # Wrapper around VCF functionality to report
    # @param app_info       Array containing install info
    # @param severity       Severity of the vulnerability to report
    # @param constraints    List of arrays detailing vulnerable ranges.
    # @param strict         if set, versions MUST have the same number of fields (segments)
    # @param flags          xss, xsrf, and sqli 
    ##
    function check_version_and_report(app_info, severity, constraints, strict, flags) {
        local_var extra, extra_rdbms, extra_ojvm;
        local_var report_items; 
        local_var rdbms_constraints = _filter_constraints(os:app_info.os, component:'db', constraints:constraints);
        local_var ojvm_constraints = _filter_constraints(os:app_info.os, component:'ojvm', constraints:constraints);
        local_var order = ['Component', 'Installed version', 'Fixed version', 'Missing patch'];

        if (isnull(app_info)) 
            return arg_error(arg:'app_info', func:FUNCTION_NAME);
        if (isnull(severity)) 
            return arg_error(arg:'severity', func:FUNCTION_NAME);
        if (isnull(constraints)) 
            return arg_error(arg:'constraints', func:FUNCTION_NAME);

        local_var matching_rdbms_constraint = vcf::check_version(version:app_info.parsed_version, constraints:rdbms_constraints, strict:strict);
        dbg::log(msg:'Matching RDBMS constraint: ' + obj_rep(matching_rdbms_constraint));
        if (vcf::is_error(matching_rdbms_constraint)) 
            return vcf::vcf_exit(1, matching_rdbms_constraint.message);
        
        if (!empty_or_null(matching_rdbms_constraint)) {
            report_items = {
                'Component'         : 'RDBMS',
                'Installed version' : app_info.version,
                'Fixed version'     : matching_rdbms_constraint.fixed_version,
                'Missing patch'     : matching_rdbms_constraint.missing_patch
            };
            extra_rdbms = report_items_str(report_items:report_items, ordered_fields:order); 
        }

        # Now Check OJVM:
        if (!empty_or_null(app_info.ojvm_patchlevel)) 
        {
            app_info.parsed_version = vcf::parse_version(app_info.ojvm_patchlevel);
            app_info.version = app_info.ojvm_patchlevel;
            local_var matching_ojvm_constraint = vcf::check_version(version:app_info.parsed_version, constraints:ojvm_constraints, strict:strict);
            dbg::log(msg:'Matching OJVM constraint: ' + obj_rep(matching_ojvm_constraint));
            if (vcf::is_error(matching_ojvm_constraint)) 
                return vcf::vcf_exit(1, matching_ojvm_constraint.message);
            
            if (!empty_or_null(matching_ojvm_constraint)) {
                report_items = {
                    'Component'         : 'OJVM',
                    'Installed version' : app_info.version,
                    'Fixed version'     : matching_ojvm_constraint.fixed_version,
                    'Missing patch'     : matching_ojvm_constraint.missing_patch
                };
                extra_ojvm = report_items_str(report_items:report_items, ordered_fields:order);
            }
        }

        if(empty_or_null(matching_rdbms_constraint) && empty_or_null(matching_ojvm_constraint))
            vcf::audit(app_info);

        security_report_v4(severity:severity, port:app_info.port, extra:extra_rdbms + extra_ojvm, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli);
    }

    ##
    # Finds Oracle database installs
    #   - Subset of oracle_rdbms_cpu_func.check_oracle_database()
    # @return ret [Array] An array of oracle database installs
    # Audits if:
    #   - OS cannot be identified
    #   - All KB items set by local / remote detection are NULL.
    ##
    function _get_installs() 
    {
        local_var os, port, tnslsnr, lsnrversion, res;
        local_var sids, sid, ohome, installs, ver, dbversion;
        local_var rdbms_patchlevel, ojvm_patchlevel;
        local_var osandport;
        local_var ojvm_installed;
        local_var tns_os;
        os = NULL;

        if (get_kb_item('Oracle/Patches/local'))
        {
            osandport = get_oracledb_host_os_and_port();
            os = osandport['os'];
            port = osandport['port'];

            res = get_kb_list('Oracle/*/RDBMS Patch Level');
            foreach ohome (keys(res))
            {
                # Skip Remote port based entries in case Local and Remote both wrote KBs
                if (preg(string:ohome, pattern:'^Oracle/[0-9]+')) 
                    continue;
                rdbms_patchlevel = res[ohome];
                ohome = ohome - 'Oracle/';
                ohome = ohome - '/RDBMS Patch Level';
                installs[ohome]['rdbms_patchlevel'] = rdbms_patchlevel;

                ver = split(rdbms_patchlevel, sep:'.', keep:FALSE);
                installs[ohome]['version'] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];

                ojvm_patchlevel = get_kb_item('Oracle/' + ohome + '/OJVM Patch Level');
                if (!empty_or_null(ojvm_patchlevel))
                    installs[ohome]['ojvm_patchlevel'] = ojvm_patchlevel;
                 if (!empty_or_null(os)) 
                {
                    if (os =~ "(aix|hpux|linux|solaris)$")
                        installs[ohome]['os'] = 'unix';
                    else if (os =~ "win(32|64)")
                        installs[ohome]['os'] = 'win';
                }
                installs[ohome]['port'] = 0; 
            }
        }
        else if (get_kb_item('Oracle/RDBMS/Patches/Remote'))
        {
            port = get_service(svc:'oracle_tnslsnr', default:1521, exit_on_fail:TRUE);
            tnslsnr = get_kb_item_or_exit('oracle_tnslsnr/' + port + '/version');
            tns_os = get_kb_item("oracle_tnslsnr/"+port+"/tns_os");
            os = get_oracle_os(tnslsnr:tnslsnr, tns_os:tns_os);
            if (os == 'unknown')
            {
                osandport = get_oracledb_host_os_and_port();
                os = osandport['os'];
            }

            sids = get_kb_list('Oracle/' + port + '/*/RDBMS Patch Level');
            foreach sid (keys(sids))
            {
                rdbms_patchlevel = sids[sid];
                sid = sid - ('Oracle/' + port + '/');
                sid = sid - '/RDBMS Patch Level';
                ver = split(rdbms_patchlevel, sep:'.', keep:FALSE);
                installs[sid]['version'] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
                installs[sid]['rdbms_patchlevel'] = rdbms_patchlevel;
                installs[sid]['port'] = port;

                ojvm_installed = get_kb_item('Oracle/' + port + '/' + sid + '/OJVM Installed');
                ojvm_patchlevel = get_kb_item('Oracle/' + port + '/' + sid + '/OJVM Patch Level');

                if (ojvm_installed && !empty_or_null(ojvm_patchlevel))
                    installs[sid]['ojvm_patchlevel'] = ojvm_patchlevel;
                
                if (!empty_or_null(os)) 
                {
                    if (os =~ "(aix|hpux|linux|nix|solaris)$")
                        installs[sid]['os'] = 'unix';
                    else if (os =~ "win(32|64)")
                        installs[sid]['os'] = 'win';
                }
            }
        }
        else if (get_kb_item('Settings/PCI_DSS') || (get_kb_item('Services/oracle_tnslsnr') && report_paranoia > 1))
        {
            port = get_service(svc:'oracle_tnslsnr', default:1521, exit_on_fail:TRUE);
            tnslsnr = get_kb_item_or_exit('oracle_tnslsnr/' + port + '/version');
            tns_os = get_kb_item("oracle_tnslsnr/"+port+"/tns_os");
            os = get_oracle_os(tnslsnr:tnslsnr, tns_os:tns_os);
            if (os == 'unknown')
            {
                osandport = get_oracledb_host_os_and_port();
                os = osandport['os'];
            }

            lsnrversion = get_oracle_version(tnslsnr:tnslsnr);
            ver = split(lsnrversion, sep:'.', keep:FALSE);
            installs[lsnrversion]['version'] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
            installs[lsnrversion]['rdbms_patchlevel'] = lsnrversion;
            installs[lsnrversion]['ojvm_patchlevel'] = lsnrversion;
            if (!empty_or_null(os)) 
            {
                if (os =~ "(aix|hpux|linux|solaris)$")
                    installs[lsnrversion]['os'] = 'unix';
                else if (os =~ "win(32|64)")
                    installs[lsnrversion]['os'] = 'win';
            }
        }
        else
        {
            exit(1, 'No Databases detected on the remote host.');
        }
        if (empty_or_null(os)) 
            exit(1, 'Failed to determine the host OS.');
       return installs;
    }

    ##
    # Convert each install to an app_info VCF can work with
    # @param path           Path where the installation was found
    # @param install        Array of values to be converted
    # @return array         Array with members VCF can use for comparisons.
    ##
    function _convert_install_to_app_info(path, install) {
        local_var app_info = {};

        app_info.app_name = 'Oracle RDBMS';
        app_info.version = install.rdbms_patchlevel;
        app_info.port = install.port;
        app_info.os = install.os;
        app_info.parsed_version = vcf::parse_version(install.rdbms_patchlevel);
        if (!empty_or_null(path))
            app_info.path = path;
        
        if (!empty_or_null(install.ojvm_patchlevel))
            app_info.ojvm_patchlevel = install.ojvm_patchlevel;
        
        return app_info;
    }

    ##
    # Filters constraints by OS
    # @param os - Operating system to filter on.
    # @param constraints - List of arrays detailing vulnerable ranges.
    # @return ret [List] - A list of constraints which are applicable to the given app_info's os
    ##
    function _filter_constraints_for_os(os, constraints) 
    {
        return collib::filter(constraints, args:[os], f:function ()
        {   
            local_var os = _FCT_ANON_ARGS[0];
            local_var constraint = _FCT_ANON_ARGS[1];
            return constraint.os >< os;
        });
    }

    ##
    # Filters constraints by component
    # @param component - Component to filter on (ojvm / db)
    # @param constraints - List of arrays detailing vulnerable ranges.
    # @return ret [List] - A list of constraints which are applicable to the given app_info's component
    ##
    function _filter_constraints_for_component(component, constraints) 
    {   
        return collib::filter(constraints, args:[component], f:function ()
        {   
            local_var component = _FCT_ANON_ARGS[0];
            local_var constraint = _FCT_ANON_ARGS[1];
            return constraint.component == component;
        });
    }
    
    ##
    # Filters constraints by component and OS 
    # @param app_info - Array of install information 
    # @param constraints - List of arrays detailing vulnerable ranges.
    # @return ret [List] - A list of constraints which are applicable to the given app_info's component
    ##
    function _filter_constraints(component, os, constraints) 
    {
        local_var filtered = _filter_constraints_for_os(os:os, constraints:constraints);
        return _filter_constraints_for_component(component:component, constraints:filtered);
    }
  }
}