#TRUSTED 9536e7c567130d712a7d61fb90fa6c2cbddfc9cab46efbf64429c01d4dccce6edbb1878d17f376847d7beb22c50e8096be7d2c88b31686c49017c692a1e5f4dbd84d0038b97d46cbde11b36e44faab7ba3399f387c7185ddbef813bfd812ebf6efe822e982023791ee3645182b94a49289e74af76e5ebaf35d76b02403bb8018e685c6eeafdc9bdf12a0ecf724010dcf525a1ab21ffc2a49d7241ce2db32068298cdf9f08f16edfcd82ad6ea9a4a7dcdcfc6a100818ee9cd680485a1ec02edb87b80d783a692f1164e68d7ff21c0b06b960ccee85fc06d59ec05b98bf17fe2b05368ca1a4dc549ddcf9aef5d5fcb4e56d28663df9408e7a6cc01ed70c6bfe37d8d72bb9e5838b715ce3651f981095b08a2a315f57b6ac4d2c3e6c1fe3b9831c1142b3033e0e5c6fb0d5fe99f7c9f00a56dc1ae2206921ecf81c89d88e736695fe34350b7cd082872426e15b5e5f72fdf22bfe7ef50d7ba7c7dd240bb98787846b396eb39c106c63462baf34041385461489678a3ff335f074d92105a19a746252a180800c1ead354479793810dfa4fb1178712efb71e5862e17d18da8b6b850c555ad3c71298038f5ebaf51de05f724b91959024e529a658d6adbbc705cd057a777aab2cb4bab54c8d03db174630757573fbd5667866956cf6bdfb67cdfacb8b778e73f87259bb94fa5f4c2374cbee86f9b4ddd5afc5ef13092d1e6ae3a36208

###
# (C) WebRAY, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY, Inc.
#
# @NOGPL@
#
# ssh_lib_channel.inc
# Revision: 2.8
#
###

namespace  sshlib {
  ##
  # Default starting window size, 64000
  ##
  global_var DEFAULT_INIT_WINDOW_SIZE = 64000;
  #global_var DEFAULT_INIT_WINDOW_SIZE = 512000;

  ##
  # Default maximum packet size, 32000
  ##
  global_var DEFAULT_MAX_PACKET_SIZE = 32000;
  #global_var DEFAULT_MAX_PACKET_SIZE = 1024000;
  #global_var WINDOWBASE = 128000;
  ##
  # Default window size, 1024000
  ##
  global_var WINDOWBASE = 1024000;
  ##
  # Default minimum window limit, WINDOWBASE/2, 512000
  ##
  global_var WINDOWLIMIT = WINDOWBASE/2;

  ##
  # Type code for STDERR return type, 1
  ##
  global_var SSH_EXTENDED_DATA_STDERR = 1;

  ## Channel state tracking
  ##
  # Internal channel state tracking value for no state, 0
  ##
  global_var CHANNEL_STATE_NONE    = 0;
  ##
  # Internal channel state tracking value for connection pending state, 1
  ##
  global_var CHANNEL_STATE_PENDING   = 1;
  ##
  # Internal channel state tracking value for connection accepted state, 2
  ##
  global_var CHANNEL_STATE_ACCEPTED  = 2;
  ##
  # Internal channel state tracking value for connection denied state, 3
  ##
  global_var CHANNEL_STATE_DENIED  = 3;
  ##
  # Internal channel state tracking value for connection error state, 4
  ##
  global_var CHANNEL_STATE_ERROR   = 4;
  ##
  # Internal channel state tracking value for connection closed state, 5
  ##
  global_var CHANNEL_STATE_CLOSED  = 5;

  object ChannelManager {

    var channels = make_array();
    var next_id = 0;
    var default_id = 0;
    var session;

    ##
    # Constructor function for ChannelManager object
    #
    # @anonparam First session to initialize this.session to
    #
    # @return implicit NULL return
    # @category SSH
    # @GizaNE 6.0
    ##
    function ChannelManager() {
      this.session =  _FCT_ANON_ARGS[0];
    }

    ##
    # Parses the channel ID from an SSH packet
    #
    # @param sshpkt The SSH packet to parse
    #
    # @return Channel ID from packet, OR
    #         NULL if channel ID dword couldn't be extracted from packet OR
    #         NULL if channel ID dword has no entry in this.channels
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function packets_channel(sshpkt) {
      var err = NULL;
      ## All channel specific packets encode the
      ## recipient channel as the first uint32
      var chid = getdword(blob:sshpkt.payload, pos:0, order:BYTE_ORDER_BIG_ENDIAN);
      if (isnull(chid))
        err = 'Could not read channel ID from packet.';
      else
      {
        var channel = this.channels[chid];
        if (isnull(channel))
          err = 'Channel '+chid+' not found.';
      }
      if (err)
      {
        this.session.dbg_log(
            fn:'ChannelManager.packets_channel',
            level:DEBUG1,
            message:err);
        return NULL;
      }
      return channel;
    }

    ##
    # Creates a new channel object in this.channels
    #
    # @param type The type value to feed into the new channel constructor
    # @param options The options value to feed into the new channel constructor
    # @param window The window value to feed into the new channel constructor
    # @param maxpacket The maxpacket value to feed into the new channel constructor
    #
    # @return Channel ID from newly constructed channel
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function open_new_channel(type, options, window, maxpacket) {
      var chid = this.next_id++;
      var sets = make_array(
        "id", chid,
        "type", type,
        "window", window,
        "maxpacket", maxpacket,
        "options", options,
        "session", this.session
      );
      if (isnull(this.default_id)) default_id = chid;
      this.channels[chid] = new("sshlib::Channel", sets);
      return this.channels[chid];
    }


    ##
    # Returns the default channel if one is available.
    #
    # @return this.default_id value if defined, OR
    #         NULL otherwise
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function get_default_channel ()
    {
      if (isnull(this.default_id)) return NULL;
      return this.channels[this.default_id];
    }

    ##
    # Sets the default channel to channel argument, or first anonymous argument.
    #
    # @param channel The channel to set as the default channel
    # @anonparam First The channel to set as the default channel if channel param missing
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function set_default_channel (channel)
    {
      if (isnull(channel)) channel = _FCT_ANON_ARGS[0];
      #if (this.channels[channel.local_channel] != channel)
      #  exit(1, "Cannot set an unregistered channel to default.");
      this.channels[channel.local_channel] = channel;
      this.default_id = channel.local_channel;
    }

    ##
    # Returns a channel with settings identical to the channel provided,
    # but with a new channel id number.
    #
    # @remark Not currently being used as of 2018/06/12.
    #
    # @param chan The channel to clone
    # @param replace A flag to determine whether or not to remove chan before cloning it
    #
    # @return Channel ID of the new channel
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function clone_channel(chan, replace)
    {
      var sets = chan.settings;
      var chid;
      if (replace)
      {
        chid = sets['id'];
        this.remove_channel(chan);
      }
      else
      {
        chid = this.next_id++;
      }
      this.channels[chid] = new('sshlib::Channel',sets);
      return this.channels[chid];
    }

    ##
    # Initializes a channel with settings identical to the channel provided,
    # but with a new channel id number, and deletes the existing channel.
    #
    # @param old_chan The channel to clone the settings of and remove
    # @param new_chan The channel to initialize with the settings of old_chan
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function replace_channel(old_chan, new_chan) {
      var chid = new_chan.local_channel;
      # If we're replacing the default channel, make the new one the default
      if (!isnull(old_chan))
      {
        new_chan.init(settings:old_chan.settings);
        new_chan.set_id(chid);
        if (old_chan.local_channel == this.default_id) this.default_id = chid;
        this.remove_channel(old_chan);
        if (!isnull(old_chan.shell_handler))
          new_chan.shell_handler.init(settings:old_chan.shell_handler.settings);
      }
      this.channels[chid] = new_chan;
    }

    ##
    # Removes a channel for a provided channel id.
    #
    # @remark Removes the channel from this.channels
    #
    # @param channel The channel id to remove
    # @anonparam First The channel id to remove if channel param is null
    #
    # @return NULL if channel argument and anonparam 1 are null OR
    #         does not return otherwise.
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function remove_channel(channel)
    {
      if (isnull(channel)) channel = _FCT_ANON_ARGS[0];
      if (isnull(channel)) return NULL;
      if (channel.local_channel == this.default_id)
        this.default_id = NULL;
      delete_element(var:this.channels, idx:channel.local_channel);
    }
  }

  object tail_buffer
  {
    var part1 = "";
    var part2 = NULL;

    ##
    # Sets part2 to anonparam 1. If part2 already existed,
    # part1 is set to part2 first. 
    #
    # @anonparam First The new value to assign to part2.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function add()
    {
      var part;
      part = _FCT_ANON_ARGS[0];

      if(isnull(part2))
      {
        part2 = part;
      }
      else
      {
        part1 = part2;
        part2 = part;
      }
    }

    ##
    # Concatenates part1 and part2 
    #
    # @return part1 + part2
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function get() { return part1 + part2; }

    ##
    # Sets part1 to empty string and part2 to NULL.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function clear()
    {
      part1 = "";
      part2 = NULL;
    }
  }

  object Channel {

    # Session that this channel belongs to
    var session;
    var sftp_session;

    var shell_handler;

    var data_buf = '';
    var buf_tail = new("sshlib::tail_buffer");
    var buf_change_counter = 0;

    # last response, TRUE for SUCCESS, otherwise FAIL
    var last_response;
    var last_exit_status;

    # Local channel tracking
    var local_channel;
    var local_window;
    var local_eof;
    var local_maxpacket;

    # Remote channel tracking
    var remote_channel;
    var remote_window;
    var remote_eof = FALSE;
    var remote_maxpacket;

    # "session", "exec", "scp", etc ...
    var type;

    # Specific options for type
    var options;

    # stderr
    var stderr = '';

    var settings; # an immutable copy of the channel's initial settings

    var objname = 'Channel.';

    # Channel state
    var state = CHANNEL_STATE_NONE;

    ##
    # Increments buf_change_counter by one.
    #
    # @remark If buf_change_counter exceeds 1073741824, it is set to 0.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    function incr_buffer_change_counter()
    {
      buf_change_counter++;
      # prevent overflows, counter can be used as a less intensive way
      # to see if data_buf has been updated
      if(buf_change_counter > 1073741824)
      buf_change_counter = 0;
    }

    ##
    # Sets local_channel to anonymous parameter 1.
    #
    # @anonparam First Value to set local_channel to
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function set_id ()
    {
      this.local_channel = _FCT_ANON_ARGS[0];
    }

    ##
    # Sets sftp_session to anonymous parameter 1.
    #
    # @anonparam First Value to set sftp_session to
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function set_sftp_session()
    {
      sftp_session = _FCT_ANON_ARGS[0];
    }

    ##
    # Sets shell_handler to anonymous parameter 1.
    #
    # @param shell_handler shell_handler to set as a reference
    # @anonparam First Value to set shell_handler to
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function set_shell_handler(&shell_handler)
    {
      if (shell_handler) this.shell_handler = shell_handler;
      else this.shell_handler = _FCT_ANON_ARGS[0];
    }

    ##
    # Either tail_buffer.clears and clears the entirety of data_buf,
    # or tail_buffer.adds the first len characters of data_buf to the tail buffer
    #
    # @param len Optional value to specify to tail_buffer add len chars of data_buf
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function clear_data_buf(len)
    {
      if(!isnull(len) && len < strlen(data_buf))
      {
        incr_buffer_change_counter();
        data_buf = substr(data_buf, len);
        buf_tail.add(substr(data_buf, len));
      }
      else
      {
        incr_buffer_change_counter();
        data_buf = '';
        buf_tail.clear();
      }
    }

    ##
    # Either sets stderr to empty string or truncates stderr to len characters
    # if len is present and less than the length of stderr.
    #
    # @param len Optional value to specify to truncate to len characters of stderr.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function clear_stderr_buf(len)
    {
      if(!isnull(len) && len < strlen(stderr)) stderr = substr(stderr, len);
      else stderr = '';
    }

    ##
    # Sets channel state to closed, sshends the session if necessary, and
    # deletes session, shell_handler, and sftp_session if they are existing objects.
    #
    # @return NULL if state is already closed, or session is non-null and closed,
    #         otherwise does not return.
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function close()
    {
      if(this.state == CHANNEL_STATE_CLOSED) return NULL;
      this.state = CHANNEL_STATE_CLOSED;
      if(isnull(this.session) || this.session.cur_state.val == "SOC_CLOSED") return NULL;

      var pkt = "";
      pkt += mkdword(this.remote_channel, order:BYTE_ORDER_BIG_ENDIAN);
      this.session.sshsend(data:pkt, code:PROTO_SSH2_MSG_CHANNEL_CLOSE);

      if (!isnull(this.session) && typeof(this.session) == 'object') delete(this.session);
      if (!isnull(this.shell_handler) && typeof(this.shell_handler) == 'object') delete(this.shell_handler);
      if (!isnull(this.sftp_session) && typeof(this.sftp_session) == 'object') delete(this.sftp_session);
    }

    ##
    # Sets last_response to anonymous parameter 1.
    #
    # @anonparam First Value to set last_response to
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function set_response()
    {
      last_response = _FCT_ANON_ARGS[0];
    }

    ##
    # Sets remote_eof to TRUE.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function remote_eof()
    {
      remote_eof = TRUE;
    }

    ##
    # Constructor function for Channel object. Sets settings to
    # anonymous parameter 1, initializes state, runs init.
    #
    # @anonparam First Value to set settings to.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    function Channel() {
      this.settings = _FCT_ANON_ARGS[0];
      this.state = CHANNEL_STATE_NONE;
      this.init();
    }

    ##
    # Initializes object variables based on supplied or existing settings
    # and known defaults.
    #
    # @param settings Array of settings to initialize object with
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function init(settings)
    {
      if (!isnull(settings)) this.settings = settings;
      this.local_channel = this.settings['id'];
      this.session = this.settings['session'];
      this.local_window = this.settings['window'];
      this.local_maxpacket = this.settings['maxpacket'];
      this.type = this.settings['type'];
      this.options = this.settings['options'];

      # Set defaults
      if (isnull(this.local_window)) {
        this.local_window = DEFAULT_INIT_WINDOW_SIZE;
      }
      if (isnull(this.local_maxpacket)) {
        this.local_maxpacket = DEFAULT_MAX_PACKET_SIZE;
      }
      if (isnull(this.type)) {
        this.type = "";
      }
      if (isnull(this.options)) {
        this.options = "";
      }
    }

    ##
    # Returns truthy if remote_window <= 0, or falsy otherwise.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function remote_window_exhausted() 
    {
      return (this.remote_window <= 0);
    }

    ##
    # Increases the size of remote_window by the dword in sspkt position 4.
    #
    # @param sshpkt The packet containing the window size to increase by
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function handle_window_adjust(sshpkt) 
    {
      ## Payload:
      ## uint32  recipient channel
      ## uint32  bytes to add
      var adds = getdword(blob:sshpkt.payload, pos:4, order:BYTE_ORDER_BIG_ENDIAN);
      this.remote_window += adds;
    }

    ##
    # Parses a channel confirmation packet, assigning remote_channel,
    # remote_window, remote_maxpacket based on the packet, and setting
    # state to CHANNEL_STATE_ACCEPTED.
    #
    # @param sshpkt The packet containing the data to parse
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function handle_channel_confirmation(sshpkt) 
    {
      ## Payload:
      ## uint32  recipient channel
      ## uint32  sender channel
      ## uint32  initial window size
      ## uint32  maximum packet size
      ## ....    channel type specific data follows
      var pos = 4; ## Skip recipient channel id
      this.remote_channel = getdword(blob:sshpkt.payload, order:BYTE_ORDER_BIG_ENDIAN, pos:pos);
      pos += 4;
      this.remote_window = getdword(blob:sshpkt.payload, order:BYTE_ORDER_BIG_ENDIAN, pos:pos);
      pos += 4;
      this.remote_maxpacket = getdword(blob:sshpkt.payload, order:BYTE_ORDER_BIG_ENDIAN, pos:pos);
      this.state = CHANNEL_STATE_ACCEPTED;
    }

    ##
    # Parses a channel open failure packet, assigning session.set_cmd_error
    # based on the parsed packet, and setting state to CHANNEL_STATE_DENIED.
    #
    # @param sshpkt The packet containing the data to parse
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function handle_channel_open_failure(sshpkt)
    {
      ## Payload:
      ## uint32  recipient channel
      ## uint32  reason code
      ## string  description
      ## string  language tag
      var pos = 4; ## Skip recipient channel id
      var reason = getdword(blob:sshpkt.payload, order:BYTE_ORDER_BIG_ENDIAN, pos:pos);
      pos += 4;
      var desc = get_ssh_string(buffer:sshpkt.payload, pos:pos);
      var err = "Failed to open channel with reason code " + reason;
      if(!empty_or_null(desc)) err += ": " + desc;
      err += ".";
      this.session.set_cmd_error(err);
      this.state = CHANNEL_STATE_DENIED;
    }

    ##
    # Parses a data packet, handling the window size as necessary
    # and aggregating data in data_buf and tail_buf.
    #
    # @param sshpkt The packet containing the data to parse
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function handle_data_recieved(sshpkt) {

      ## Payload:
      ## uint32  recipient channel
      ## string  data
      var fn = "Channel.handle_data_recieved";
      var data, data_orig;
      data_orig = get_ssh_string(buffer:sshpkt.payload, pos:4);
      data = remove_escape_sequences(data_orig);
      if(data != data_orig)
        this.session.dbg_log(fn:fn, ddata:data, message:
          "Data after removing escape sequences:");

      var dlen = strlen(data);
      if (dlen <= this.local_window) {
        this.local_window -= dlen;
      }
      else {
        ## Should never happen unless remote is stupid
        this.local_window = 0;
      }
      window_adjust_packet();
      incr_buffer_change_counter();
      buf_tail.add(data);
      data_buf += data;
    }

    ##
    # Parses an stderr data packet, handling the window size as necessary
    # and aggregating data in data_buf and tail_buf.
    #
    # @param sshpkt The packet containing the data to parse
    #
    # @return NULL if the type code isn't for SSH_EXTENDED_DATA_STDERR
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function handle_extended_data_recieved(sshpkt)
    {
      ## uint32  recipient channel
      ## uint32  data_type_code
      ## string  data

      var type_code = getdword(blob:sshpkt.payload, pos:4, order:BYTE_ORDER_BIG_ENDIAN);
      if(type_code != SSH_EXTENDED_DATA_STDERR)
        return NULL;
      var fn = "Channel.handle_extended_data_recieved";
      var data, data_orig;
      data_orig = get_ssh_string(buffer:sshpkt.payload, pos:8);
      data = remove_escape_sequences(data_orig);
      if(data != data_orig)
        this.session.dbg_log(fn:fn, ddata:data, message:
          "Data after removing escape sequences:");

      var dlen = strlen(data);
      if (dlen <= this.local_window) {
        this.local_window -= dlen;
      }
      else {
        ## Should never happen unless remote is stupid
        this.local_window = 0;
      }
      window_adjust_packet();
      stderr += data;
      this.session.set_cmd_error(data);
    }

    ##
    # Constructs a packet for the data parameter to sshsend to the session.
    #
    # @param data The packet containing the data to send
    # @param redact Boolean. If set to true redact value
    #                        sent to remote host in logging output (optional).
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function window_send_data(data, redact) {
      var pos = 0;
      var dlen = strlen(data);
      var end;
      var maxpkt = this.remote_maxpacket - 10; # Allow 10 bytes for header
      while (pos < dlen) {
        end = pos + maxpkt;
        if (end > dlen) {
          end = dlen;
        }
        var pkt = '';
        var buf = substr(data, pos, end);
        pkt += mkdword(this.remote_channel, order:BYTE_ORDER_BIG_ENDIAN);
        pkt += mk_ssh_string(buf);
        this.remote_window -= strlen(buf);
        if(redact) this.session.set_redact(TRUE);
        this.session.sshsend(data:pkt, code:PROTO_SSH2_MSG_CHANNEL_DATA);
        if(redact) this.session.set_redact(FALSE);
        pos += end;
      }
    }


    ##
    # Constructs and sends a window adjust packet to session
    #
    # @param minimumsize The new window size
    #
    # @remark if minimumsize is less than WINDOWBASE, WINDOWBASE will be used
    #
    # @return NULL if the new window size == local_window
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function window_adjust_packet(minimumsize)
    {
      if (this.state == CHANNEL_STATE_CLOSED)
        return NULL;

      var newwindow;
      if (isnull(minimumsize)) {
        minimumsize = 0;
      }
      if (minimumsize > WINDOWBASE) {
        newwindow = minimumsize;
      }
      else {
        newwindow = WINDOWBASE;
      }

      var adjust = (newwindow - this.local_window);

      ## Window does not need to grow
      #if(adjust < (newwindow / 2)) return NULL; # solaris has a problem with this...
      if(adjust == 0) return NULL;

      this.local_window += adjust;

      var pkt = '';
      pkt += mkdword(this.remote_channel, order:BYTE_ORDER_BIG_ENDIAN);
      pkt += mkdword(adjust, order:BYTE_ORDER_BIG_ENDIAN);
      this.session.sshsend(data:pkt, code:PROTO_SSH2_MSG_CHANNEL_WINDOW_ADJUST);
    }

    ##
    # Parses an a request packet, setting last_exit_status if
    # the request is of exit-status type.
    #
    # @param sshpkt The packet containing the data to parse
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function handle_request(sshpkt)
    {
      var pos = 4; ## Skip recipient channel id
      var request = get_ssh_string(buffer:sshpkt.payload, pos:pos);
      pos += strlen(request) + 4;
      if(request == "exit-status")
      {
        pos += 1;
        this.last_exit_status = getdword(blob:sshpkt.payload, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
      }
    }

    ##
    # Crafts a request packet using the paramters, and sends it to session.
    #
    # @param type The type of request, fed to mk_ssh_string()
    # @param want_reply Flag indicating whether or not a reply is wanted
    # @param extra Extra data to append to request packet
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function make_request(type, want_reply, extra)
    {
      #  byte    SSH_MSG_CHANNEL_REQUEST
      #  uint32  recipient channel
      #  string  request type in US-ASCII characters only
      #  boolean   want reply
      #  ....    type-specific data follows
 
      var pkt = '';
      pkt += mkdword(this.remote_channel, order:BYTE_ORDER_BIG_ENDIAN);
      pkt += mk_ssh_string(type);

      if(want_reply) want_reply = 1;
      else want_reply = 0;

      pkt += mkbyte(want_reply);

      if(!isnull(extra))
        pkt += extra;
      this.session.sshsend(data:pkt, code:PROTO_SSH2_MSG_CHANNEL_REQUEST);
    }

    ##
    # Crafts a channel open packet based on the values of local object
    # values, and sets the state to CHANNEL_STATE_PENDING.
    #
    # @return implicit NULL return
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function open_channel() {
      var pkt = '';
      pkt += mk_ssh_string(this.type);
      pkt += mkdword(this.local_channel, order:BYTE_ORDER_BIG_ENDIAN);
      pkt += mkdword(this.local_window, order:BYTE_ORDER_BIG_ENDIAN);
      pkt += mkdword(this.local_maxpacket, order:BYTE_ORDER_BIG_ENDIAN);
      if(this.options != "")
        pkt += this.options;
      this.state = CHANNEL_STATE_PENDING;
      this.session.sshsend(data:pkt, code:PROTO_SSH2_MSG_CHANNEL_OPEN);
    }

    ##
    # Check channel state and shell handler state to see if channel
    # can be used to run a shell command
    #
    # @category SSH
    # @GizaNE 6.0
    ##
    public function usable_for_shell_command()
    {
      var reason = '';
      if (this.state != CHANNEL_STATE_ACCEPTED)
        reason += '\n  channel state : ' + this.state;
      if (this.shell_handler.last_cmd_error)
        reason += '\n  shell_handler.last_cmd_error : ' + this.shell_handler.last_cmd_error;
      if (this.shell_handler.timed_out)
        reason += '\n  shell_handler.timed_out : ' + this.shell_handler.timed_out;

      if (!reason) return TRUE;

      var fn = this.objname + FUNCTION_NAME;
      var msg = 'Channel is unusable for shell commands.' + reason;
      if (this.session) this.session.dbg_log(fn:fn, level:DEBUG3, message:msg);
      else spad_log(message: fn + '(): ' + msg);
      return FALSE;
    }
  }
}
