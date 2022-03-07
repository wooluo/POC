#TRUSTED 82d5147970996ac5a9ed6c436e919ab4d7462b7b05328a9fe3773e469660c0390b41b0be9ed31a3daa48d33200ac652895794be48ccb95747de96e104905a07a9d3140867c8054a1f4d67b4e6af9d7b7beaad6ff041330d353563a40d4557777ec3333208770a84c6c505251897b744f5670942d4683b71088294e057d8a4f4959207a670839802faea1c5a73ae0977aa95e82cf8d318d56b73400d5e46c7aa580f2cbbf01b3d96380d3b73234656f450b3fa3cd2b309a0a98cc57c16572c5dec18cc1a76090c31691ebcbf45934558f86a76988019836b4b2fdffac282dab2e5bfed4c38fd10378f77a72d526a74a57f4c02f9c93da720157d9f6b974642992104ed14f75362bf66cff62e26c39060b03efd6af6c3fea89cd03da393e46ca072a395b6fd323f9ae6ed5912eeca97938f69f2f5050a29347c7363d93d3113617017eae992d0f36f8d3eab1f5798f2f1051d40cdf41986396884a98f435ef02f5142a34cb704709c1354ff5432cc8ffea6965e6a58158de421bce32f33012f6929b47bb931928879a3978a565a4a96786565b2db84457bd5011074c7397f4243c9163fa113f32c6f8e5b144e51ed8802b71243c31d45112a92aad94585951813983911b0e9b8a189f67c510e114117f7aa43d580890699befb4624cabf1c6a31b06f2bf09b538e5270c20cdc4787c1fe5fbfe5d0ab69a95edb89cb59637ffddb0
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.1
#
# @NOGPL@
#
##

namespace sshlib {

  global_var ssh_client_allowed_states =
    make_list(
      "SOC_CLOSED",
      "SOC_OPENED",
      "KEX_BEGIN",
      "KEX_DONE",
      "SERVICE_REQUEST_SUCCESS",
      "USERAUTH_REQUEST",
      "USERAUTH_SUCCESS",
      "USERAUTH_INFO_REQ",
      "USERAUTH_INFO_RES",
      "USERAUTH_FAILURE",
      "USERAUTH_PK_REQUEST",
      "USERAUTH_PK_OK",
      "USERAUTH_GSSAPI_REQUEST",
      "USERAUTH_GSSAPI_RESPONSE",
      "USERAUTH_GSSAPI_TOKEN",
      "USERAUTH_GSSAPI_ERROR",
      "USERAUTH_GSSAPI_ERRTOK"
    );

  # Note: We cannot use inheritance yet, because it is only supported in
  # GizaNE 6.4+ and GizaNE 6.0+ is still supported. Please do not remove
  # the following commented code because it can be used as a template.
  ## Begin commented code
  #object ssh_state
  #{
  #  var val;
  #  var allowed_states;
  #  var session;

  #  function ssh_state()
  #  {
  #    if(!isnull(_FCT_ANON_ARGS[1]))
  #      allowed_states = _FCT_ANON_ARGS[1];

  #    if(!isnull(_FCT_ANON_ARGS[0]))
  #      set(_FCT_ANON_ARGS[0]);
  #  }

  #  public function set_session()
  #  {
  #    session = _FCT_ANON_ARGS[0];
  #  }

  #  public function oneof(state_list)
  #  {
  #    var state;
  #    foreach state (state_list)
  #      if(state == val) return TRUE;

  #    return FALSE;
  #  }

  #  public function set()
  #  {
  #    if(session.debug >= DEBUG1)
  #      session.dbg_log(fn:"ssh_client_state.set", message:'** Entering STATE ' + _FCT_ANON_ARGS[0] + ' **');

  #    var state;
  #    foreach state (allowed_states)
  #    {
  #      if(state == _FCT_ANON_ARGS[0])
  #      {
  #        val = _FCT_ANON_ARGS[0];
  #        return;
  #      }
  #    }
      # should never get here
  #    exit(1, "Critical error - SSH STATE " + _FCT_ANON_ARGS[0] + " is invalid."); 
  #  }
  #}
  #object ssh_client_state : sshlib::ssh_state
  #{
  #  function ssh_client_state () : super(_FCT_ANON_ARGS[0], ssh_client_allowed_states) {}
  #}
  ## End commented code

  ##
  #
  # Object ssh_client_state
  #   Object to keep track of SSH client state
  #
  ##
  object ssh_client_state
  {
    var val;
    var allowed_states;
    var session_id;

    ##
    #  Constructs and ssh_client_state instance
    #  @category SSH
    ##
    function ssh_client_state()
    {
      allowed_states = ssh_client_allowed_states;
    }

    ##
    # Set ssh session object
    # @anonparam <First> ssh session object
    # @category SSH
    ##
    public function set_session()
    {
      local_var session = _FCT_ANON_ARGS[0];
      session_id = session.get_number();
    }

    ##
    # Check list of states against current state
    # @anonparam <First> state list
    # @return TRUE if state in list matches current state, FALSE otherwise
    # @category SSH
    ##
    public function oneof(state_list)
    {
      var state;
      foreach state (state_list)
        if(state == val) return TRUE;

      return FALSE;
    }

    ##
    # Returns Session ID
    # @return session id
    # @category SSH
    ##
    public function get_session_id()
    {
      return this.session_id;
    }

    ##
    # Returns formatted debug log messages for ssh_client_state object and
    # also stores message to scratchpad
    #
    # @param <message> string with debug message
    # @param <fn> function name string of callee to include in debug message
    # @return formatted debug log string
    # @category SSH
    ##
    public function dbg_log_client_state(message, fn)
    {
      var s;
      if (isnull(message)) message = _FCT_ANON_ARGS[0];
      if (isnull(fn)) fn = '';
      else fn += ': ';
      s = '[session ' + this.get_session_id() + '] '+ fn + message;
      if (s[strlen(s)-1] != '\n') s += '\n';
      spad_log(message:s);
      if (TAP_MODE) 
        _SCRATCH_PAD_MIRROR[max_index(_SCRATCH_PAD_MIRROR)] = s;
      return s;
    }

    ##
    # Set new ssh state
    # @anonparam state string
    # @category SSH
    ##
    public function set()
    {
      dbg_log_client_state(fn:"ssh_client_state.set", message:'** Entering STATE ' + _FCT_ANON_ARGS[0] + ' **');

      var state;
      foreach state (allowed_states)
      {
        if(state == _FCT_ANON_ARGS[0])
        {
          val = _FCT_ANON_ARGS[0];
          return NULL;
        }
      }
      # should never get here
      dbg_log_client_state(fn:"ssh_client_state.set", message:"Critical error - SSH STATE " + _FCT_ANON_ARGS[0] + " is invalid.");
    }
  }
}
