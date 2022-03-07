#TRUSTED 9f572a77ce989a967215442c7e4c90af390e81051635968041eb7ab43372d929cb1949d2de9dc700fe0c60ef73858e5db5760bd62b1ee1e716d69cb55fa3a4f359f36edfe8339e1d1441625014f99dff4ad406c274245f213ecaa288da7101a210bf3df202b2f031967111c176551e7aeba8dfb99f30d861de4fc2ec8e7bb72f795e00e930ae2417e75015a8edf1e094618b6334c3fa0f61c56a99dc7f6a01c63f46aee6bb5d8c0ef77e1f82b91fdc7ee895737a4d3dc92544bcfaa71c7668659176de3c44f2f16010ac4e20bd6b257c76ddda098f9e034e6a95bfaee317b84f532b4a44ca1f74c0359c60e45a04c97f30254ea7de4a9ed1a3d473ad5accdc78789a3c137ead906482edf40fe0ff303623a7bb4802cf7cf372c9043e7bbc1c4cdfb851ede9acfefdd83524aa5245a0e4e0fb185331208f55101776da617d8cd60994ce6d6660ae7f828484436f98e38444afca4ce6afb834c6591f7f641dabe5a3d4938611709710a532b71bd84c732b6451d4ce1f97b8b32e6b269230731fac79d063553adbfbbbdbffa2083a1889c35cf5ce9b0e41e80bcd279743b3bf094af594a1048cfce2eef9624923656d128c4e90909911f61b94886b82c885e776fc18d6acd2e82d68b02719b3f5d81c285b50f626736e0566abddad27a5a669a9a612d45d13ff3b68dfec2034663df2cfd27dc34ba6d1bf3164bdb4a091a6051d34
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# Revision:1.0
#
###

include("ssh_lib_util.inc");
include('ssh_lib_firepower_shell_manager.inc');

namespace sshlib
{
  object firepower_fxos_shell_handler : sshlib::firepower_shell_manager
  {
    var objname = 'firepower_fxos_shell_handler::';

    ##
    # run given command
    #
    # @param channel channel for ssh session
    # @param command cmd to run
    # @param force_priv_escl force priv escalation flag
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    #
    # @return command result or NULL on failure
    # @category SSH
    ##
    public function run_command(&channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = objname + FUNCTION_NAME;

      return super.run_command(
        channel:channel,
        command:command,
        force_priv_escl:force_priv_escl,
        cmd_timeout_min:cmd_timeout_min,
        inactivity_timeout_min:inactivity_timeout_min,
        cmd_shell:FP_SH_CHASSIS
      );
    }
  }

  object firepower_bootcli_shell_handler : sshlib::firepower_shell_manager
  {
    var objname = 'firepower_bootcli_shell_handler::';

    ##
    # run given command
    #
    # @param channel channel for ssh session
    # @param command cmd to run
    # @param force_priv_escl force priv escalation flag
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    #
    # @return command result or NULL on failure
    # @category SSH
    ##
    public function run_command(&channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = objname + FUNCTION_NAME;

      return super.run_command(
        channel:channel,
        command:command,
        force_priv_escl:force_priv_escl,
        cmd_timeout_min:cmd_timeout_min,
        inactivity_timeout_min:inactivity_timeout_min,
        cmd_shell:FP_SH_MODULE
      );
    }
  }

  object firepower_ftd_shell_handler : sshlib::firepower_shell_manager
  {
    var objname = 'firepower_ftd_shell_handler::';

    ##
    # run given command
    #
    # @param channel channel for ssh session
    # @param command cmd to run
    # @param force_priv_escl force priv escalation flag
    # @param cmd_timeout_min The total number of seconds that may elapse
    #                      waiting for the command response. (optional)
    # @param inactivity_timeout_min The number of seconds that may
    #                             elapse with no data received from
    #                             the target. (optional)
    #
    # @return command result or NULL on failure
    # @category SSH
    ##
    public function run_command(&channel, command, force_priv_escl,
        cmd_timeout_min, inactivity_timeout_min)
    {
      var fn = objname + FUNCTION_NAME;

      return super.run_command(
        channel:channel,
        command:command,
        force_priv_escl:force_priv_escl,
        cmd_timeout_min:cmd_timeout_min,
        inactivity_timeout_min:inactivity_timeout_min,
        cmd_shell:FP_SH_FTD
      );
    }
  }
}
