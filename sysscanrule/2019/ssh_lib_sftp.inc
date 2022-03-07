#TRUSTED 98e64246a836687479d34a7be58682d0e6d6a99b8f0936134d314a3e03e56051148df39ce6856e3bd6e616d6419573f88f53d1af1001cf2e9af333d7e481a9211ac67de0d5db4ad64648051db675f8ce67b26a1c771f404c4e9050226bf54a4ad7a5197684d2d245b906fc5b7f24483fa1710bf1e3d6aecfe945314613caa9504d3a01114f5aab2ebd9474056684fd6859ee511ec2eb37a3b1e7f088f45f7cab169bce764f1fdfc1c7b0c3f48a7a334576e90ca285dd91d22a75c785411a71f6539929d9beaeda14324b48ce72c4584842e89ee30b3dd985577e3541c6b2a7e8569106dd5dcd0d243526006f7ff8e82bdb5fa68f163f6134cb12cce5f807548905cce6576affe0a922fde14f0971d88e716901f8b533a77be51e0dea3266e4d791a8838b19adc7a893f9901e210f8d9ea0f4b7b4e358d218470d193aeee7772cedbc74925e038d7447add80ecf6572862a6c18f0d3165df16a0462b5647ce3365776efabd9fbd381a41dcf5e266312b60a7e3bdfb150de3448a33e92e338221002f8f19ee9f7f66c6a0b6be86eef76c8c0349509c402aab4c941d4e4953095f33a52a1006b444f769e0aa841cde9faca0b5183ffcd42e682d1c495b633134a0771633b779ea90ee28436d36484f1fbf65d18fddc454175038f11ecbc95467a1df7d341c8a8efa9cf28b82c3c6249f0331c620b1fb04a4d011bb0b73596f18cf0
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# Revision:1.2
#
# @NOGPL@
#
# Usage:
#
# # session is existing sshlib session
# sftp_session = session.get_sftp_session();
#
# if(!sftp_session.init())
# {
#   session.close_connection();
#   exit(0, session.error);
# }
#
# # read file
# file_contents = sftp_session.read_file(dir_path:'/test123');
#
# # get directory listing
# files = sftp_session.list_directory(dir_path:"/");
# foreach file (files)
#   display(file.get_printable_listing() + '\n');
#
# # get file permissions
# attrs = sftp_session.file_stat(dir_path:"/etc/shadow");
# # need include string.inc for ltostr()
# display(attrs.permissions + ' (' + ltostr(base:8,attrs.permissions) + ')\n');
#

namespace sshlib {

  global_var SSH_FXP_INIT          =  1;
  global_var SSH_FXP_VERSION       =  2;
  global_var SSH_FXP_OPEN          =  3;
  global_var SSH_FXP_CLOSE         =  4;
  global_var SSH_FXP_READ          =  5;
  global_var SSH_FXP_WRITE         =  6;
  global_var SSH_FXP_LSTAT         =  7;
  global_var SSH_FXP_FSTAT         =  8;
  global_var SSH_FXP_SETSTAT       =  9;
  global_var SSH_FXP_FSETSTAT      =  10;
  global_var SSH_FXP_OPENDIR       =  11;
  global_var SSH_FXP_READDIR       =  12;
  global_var SSH_FXP_REMOVE        =  13;
  global_var SSH_FXP_MKDIR         =  14;
  global_var SSH_FXP_RMDIR         =  15;
  global_var SSH_FXP_REALPATH      =  16;
  global_var SSH_FXP_STAT          =  17;
  global_var SSH_FXP_RENAME        =  18;
  global_var SSH_FXP_READLINK      =  19;
  global_var SSH_FXP_SYMLINK       =  20;
  global_var SSH_FXP_STATUS        =  101;
  global_var SSH_FXP_HANDLE        =  102;
  global_var SSH_FXP_DATA          =  103;
  global_var SSH_FXP_NAME          =  104;
  global_var SSH_FXP_ATTRS         =  105;
  global_var SSH_FXP_EXTENDED      =  200;
  global_var SSH_FXP_EXTENDED_REPLY = 201;

  global_var SSH_FILEXFER_ATTR_SIZE         = 0x00000001;
  global_var SSH_FILEXFER_ATTR_UIDGID       = 0x00000002;
  global_var SSH_FILEXFER_ATTR_PERMISSIONS  = 0x00000004;
  global_var SSH_FILEXFER_ATTR_ACMODTIME    = 0x00000008;
  global_var SSH_FILEXFER_ATTR_EXTENDED     = 0x80000000;

  global_var SSH_FILEXFER_TYPE_REGULAR      = 0x1;
  global_var SSH_FILEXFER_TYPE_DIRECTORY    = 0x2;
  global_var SSH_FILEXFER_TYPE_SYMLINK      = 0x3;
  global_var SSH_FILEXFER_TYPE_SPECIAL      = 0x4;
  global_var SSH_FILEXFER_TYPE_UNKNOWN      = 0x5;
  global_var SSH_FILEXFER_TYPE_SOCKET       = 0x6;
  global_var SSH_FILEXFER_TYPE_CHAR_DEVICE  = 0x7;
  global_var SSH_FILEXFER_TYPE_BLOCK_DEVICE = 0x8;
  global_var SSH_FILEXFER_TYPE_FIFO         = 0x9;

  // ace-mask flags from 7.8
  global_var ACE4_READ_DATA        = 0x00000001;
  global_var ACE4_LIST_DIRECTORY   = 0x00000001;
  global_var ACE4_WRITE_DATA       = 0x00000002;
  global_var ACE4_ADD_FILE         = 0x00000002;
  global_var ACE4_APPEND_DATA      = 0x00000004;
  global_var ACE4_ADD_SUBDIRECTORY = 0x00000004;
  global_var ACE4_READ_NAMED_ATTRS = 0x00000008;
  global_var ACE4_WRITE_NAMED_ATTR = 0x00000010;
  global_var ACE4_EXECUTE          = 0x00000020;
  global_var ACE4_DELETE_CHILD     = 0x00000040;
  global_var ACE4_READ_ATTRIBUTES  = 0x00000080;
  global_var ACE4_WRITE_ATTRIBUTES = 0x00000100;
  global_var ACE4_DELETE           = 0x00010000;
  global_var ACE4_READ_ACL         = 0x00020000;
  global_var ACE4_WRITE_ACL        = 0x00040000;
  global_var ACE4_WRITE_OWNER      = 0x00080000;
  global_var ACE4_SYNCHRONIZE      = 0x00100000;


  // POSIX modes
  global_var O_RDONLY   = 0x0000;
  global_var O_WRONLY   = 0x0001;
  global_var O_RDWR     = 0x0002;
  global_var O_ACCMODE  = 0x0003;
  global_var O_CREAT    = 0x0100;
  global_var O_EXCL     = 0x0200;
  global_var O_NOCTTY   = 0x0400;
  global_var O_TRUNC    = 0x0800;
  global_var O_APPEND   = 0x1000;
  global_var O_NONBLOCK = 0x2000;
  
  // Permissions
  global_var S_IRUSR  = 0400;
  global_var S_IWUSR  = 0200;
  global_var S_IXUSR  = 0100;
  global_var S_IRGRP  = 040;
  global_var S_IWGRP  = 020;
  global_var S_IXGRP  = 010;
  global_var S_IROTH  = 04;
  global_var S_IWOTH  = 02;
  global_var S_IXOTH  = 01;
  global_var S_ISUID  = 04000;
  global_var S_ISGID  = 02000;
  global_var S_ISVTX  = 01000;

  global_var SSH_FXF_READ   = 0x00000001;
  global_var SSH_FXF_WRITE  = 0x00000002;
  global_var SSH_FXF_APPEND = 0x00000004;
  global_var SSH_FXF_CREAT  = 0x00000008;
  global_var SSH_FXF_TRUNC  = 0x00000010;
  global_var SSH_FXF_EXCL   = 0x00000020;

  // Flags from 8.1.1.3
  global_var SSH_FXF_CREATE_NEW              = 0x00000000;
  global_var SSH_FXF_CREATE_TRUNCATE         = 0x00000001;
  global_var SSH_FXF_OPEN_EXISTING           = 0x00000002;
  global_var SSH_FXF_OPEN_OR_CREATE          = 0x00000003;
  global_var SSH_FXF_TRUNCATE_EXISTING       = 0x00000004;
  global_var SSH_FXF_APPEND_DATA             = 0x00000008;
  global_var SSH_FXF_APPEND_DATA_ATOMIC      = 0x00000010;
  global_var SSH_FXF_TEXT_MODE               = 0x00000020;
  global_var SSH_FXF_BLOCK_READ              = 0x00000040;
  global_var SSH_FXF_BLOCK_WRITE             = 0x00000080;
  global_var SSH_FXF_BLOCK_DELETE            = 0x00000100;
  global_var SSH_FXF_BLOCK_ADVISORY          = 0x00000200;
  global_var SSH_FXF_NOFOLLOW                = 0x00000400;
  global_var SSH_FXF_DELETE_ON_CLOSE         = 0x00000800;
  global_var SSH_FXF_ACCESS_AUDIT_ALARM_INFO = 0x00001000;
  global_var SSH_FXF_ACCESS_BACKUP           = 0x00002000;
  global_var SSH_FXF_BACKUP_STREAM           = 0x00004000;
  global_var SSH_FXF_OVERRIDE_OWNER          = 0x00008000;


  global_var SSH_FX_OK                = 0;
  global_var SSH_FX_EOF               = 1;
  global_var SSH_FX_NO_SUCH_FILE      = 2;
  global_var SSH_FX_PERMISSION_DENIED = 3;
  global_var SSH_FX_FAILURE           = 4;
  global_var SSH_FX_BAD_MESSAGE       = 5;
  global_var SSH_FX_NO_CONNECTION     = 6;
  global_var SSH_FX_CONNECTION_LOST   = 7;
  global_var SSH_FX_OP_UNSUPPORTED    = 8;

  global_var SFTP_LOG = SCRIPT_NAME - '.nasl' - '.nbin' + '_sftp.log';

  ##
  # sftp packet object
  # https://tools.ietf.org/html/draft-ietf-secsh-filexfer-04#section-3
  ##
  object sftp_packet
  {
    var type, data, length;

    ##
    # Constructor for sftp_packet object
    #
    # @anonparam [First:integer] packet type
    # @anonparam [Second:raw_string] packet data
    # @category SSH
    ##
    function sftp_packet()
    {
      if(!isnull(_FCT_ANON_ARGS[0]))
        type = _FCT_ANON_ARGS[0];
      if(!isnull(_FCT_ANON_ARGS[1]))
        data = _FCT_ANON_ARGS[1];
    }

    ##
    # Set packet type
    #
    # @anonparam [First:int] packet type
    # @category SSH
    ##
    public function set_type () { type = _FCT_ANON_ARGS[0]; }

    ##
    # Set packet data
    #
    # @anonparam [First:raw_string] packet data
    # @category SSH
    ##
    public function set_data () { data = _FCT_ANON_ARGS[0]; }

    ##
    # Parse packet, results stored in data object attribute
    #
    # @param [raw:raw_string] raw packet data to parse
    # @category SSH
    ##
    public function parse(raw)
    {
      length = getdword(blob:raw, pos:0, order:BYTE_ORDER_BIG_ENDIAN);
#      if(length != strlen(raw) - 4) return NULL;
      type = getbyte(blob:raw, pos:4);
      data = substr(raw, 5, 3 + length);
    }

    ##
    # Build and return an SFTP packet
    #
    # @category SSH
    # @return returns an SFTP packet
    ##
    public function build()
    {
      return mkdword(1 + strlen(data), order:BYTE_ORDER_BIG_ENDIAN) +
        mkbyte(type) + data;
    }
  }

  ##
  # Callback to check if we've received all SFTP data
  #
  # @param [session:session_object] Session
  # @param [channel:channel_object] Channel
  #
  # @category SSH
  #
  # @remark calls sftp_recv_check_done()
  #
  # @return TRUE of FALSE
  ##
  function sftp_session_check_recv_done_cb(session, channel)
  {
    return channel.sftp_session.sftp_recv_check_done();
  }

  ##
  # SFTP file attribute object
  ##
  object sftp_file_attrs
  {
    var flags;
    var uid, gid, permissions, atime, mtime, extended, filesize;
    var type, size, alloc_size, atime_ns, ctime, ctime_ns;
    var mtime_ns, acl, attrib_bits, attrib_bits_valid, text_hint;
    var mime_type, link_count, untranslated_name, extended_count;

    /*
       uint32   valid-attribute-flags
       byte     type                   always present
       uint64   size                   if flag SIZE
       uint64   allocation-size        if flag ALLOCATION_SIZE
       string   owner                  if flag OWNERGROUP
       string   group                  if flag OWNERGROUP
       uint32   permissions            if flag PERMISSIONS
       int64    atime                  if flag ACCESSTIME
       uint32   atime-nseconds            if flag SUBSECOND_TIMES
       int64    createtime             if flag CREATETIME
       uint32   createtime-nseconds       if flag SUBSECOND_TIMES
       int64    mtime                  if flag MODIFYTIME
       uint32   mtime-nseconds            if flag SUBSECOND_TIMES
       int64    ctime                  if flag CTIME
       uint32   ctime-nseconds            if flag SUBSECOND_TIMES
       string   acl                    if flag ACL
       uint32   attrib-bits            if flag BITS
       uint32   attrib-bits-valid      if flag BITS
       byte     text-hint              if flag TEXT_HINT
       string   mime-type              if flag MIME_TYPE
       uint32   link-count             if flag LINK_COUNT
       string   untranslated-name      if flag UNTRANSLATED_NAME
       uint32   extended-count         if flag EXTENDED
       extension-pair extensions
     */

    ##
    # set file type
    #
    # @anonparam [First:integer] file type
    # @category SSH
    ##
    public function set_filetype() { type = _FCT_ANON_ARGS[0]; }

    ##
    # set filesize
    #
    # @anonparam [First:integer] filesize
    # @category SSH
    ##
    public function set_filesize()
    {
      flags = flags | SSH_FILEXFER_ATTR_SIZE;
      filesize = _FCT_ANON_ARGS[0];
    }

    ##
    # set uid
    #
    # @anonparam [First:integer] uid
    # @category SSH
    ##
    public function set_uid()
    {
      flags = flags | SSH_FILEXFER_ATTR_UIDGID;
      uid = _FCT_ANON_ARGS[0];
    }

    ##
    # set gid
    #
    # @anonparam [First:integer] gid
    # @category SSH
    ##
    public function set_gid()
    {
      flags = flags | SSH_FILEXFER_ATTR_UIDGID;
      gid = _FCT_ANON_ARGS[0];
    }

    ##
    # set permissions
    #
    # @anonparam [First:integer] permissions
    # @category SSH
    ##
    public function set_permissions()
    {
      flags = flags | SSH_FILEXFER_ATTR_PERMISSIONS;
      permissions = _FCT_ANON_ARGS[0];
    }

    ##
    # Sets default attributes
    #
    # @category SSH
    ##
    public function set_default_permissions()
    {
      set_permissions(0664 << 8);
    }

    ##
    # Sets default attributes with exec permissions added
    #
    # @category SSH
    ##
    public function set_exec_permissions()
    {
      // uint32 is used, but permissions are in the middle two bytes
      set_permissions(0774 << 8);
    }

    ##
    # set atime
    #
    # @anonparam [First:integer] atime 
    # @category SSH
    ##
    public function set_atime()
    {
      flags = flags | SSH_FILEXFER_ATTR_ACMODTIME;
      atime = _FCT_ANON_ARGS[0];
    }

    ##
    # set mtime
    #
    # @anonparam [First:integer] mtime
    # @category SSH
    ##
    public function set_mtime()
    {
      flags = flags | SSH_FILEXFER_ATTR_ACMODTIME;
      mtime = _FCT_ANON_ARGS[0];
    }

    ##
    # set ctime
    #
    # @anonparam [First:integer] mtime
    # @category SSH
    ##
    public function set_ctime()
    {
      flags = flags | SSH_FILEXFER_ATTR_ACMODTIME;
      ctime = _FCT_ANON_ARGS[0];
    }

    ##
    # set extended
    #
    # @anonparam [First:integer] set extended
    # @category SSH
    ##
    public function set_extended() { extended = _FCT_ANON_ARGS[0]; }

    ##
    # return buffer to send over the wire
    #
    # @category SSH
    #
    # @return buffer to include in ssh channel message
    ##
    public function to_buf()
    {
      var buf = mkdword(flags, order:BYTE_ORDER_BIG_ENDIAN);
      buf += mkbyte(type);
      if((flags & SSH_FILEXFER_ATTR_SIZE) == SSH_FILEXFER_ATTR_SIZE)
      {
        # can't handle 64 bit ints yet
        buf += mkdword(0, order:BYTE_ORDER_BIG_ENDIAN);
        buf += mkdword(filesize, order:BYTE_ORDER_BIG_ENDIAN);
      }
      if((flags & SSH_FILEXFER_ATTR_UIDGID) == SSH_FILEXFER_ATTR_UIDGID)
      {
        buf += mkdword(uid, order:BYTE_ORDER_BIG_ENDIAN);
        buf += mkdword(gid, order:BYTE_ORDER_BIG_ENDIAN);
      }
      if((flags & SSH_FILEXFER_ATTR_PERMISSIONS) == SSH_FILEXFER_ATTR_PERMISSIONS)
      {
        buf += mkdword(permissions, order:BYTE_ORDER_BIG_ENDIAN);
      }
      if((flags & SSH_FILEXFER_ATTR_ACMODTIME) == SSH_FILEXFER_ATTR_ACMODTIME)
      {
        buf += mkdword(atime, order:BYTE_ORDER_BIG_ENDIAN);
        buf += mkdword(mtime, order:BYTE_ORDER_BIG_ENDIAN);
      }
      // handle other flags here

      return buf;
    }
  }

  function create_attrs(type)
  {
    if(isnull(type))
        type = SSH_FILEXFER_TYPE_REGULAR;
    var attrs = new("sshlib::sftp_file_attrs");
    attrs.set_filetype(type);
    return attrs;
  }

  ##
  # SFTP file object
  ##
  object sftp_file
  {
    var name, longname, attrs;

    ##
    # set filename
    #
    # @anonparam [First:string] filename
    # @category SSH
    ## 
    public function set_name() { name = _FCT_ANON_ARGS[0]; }

    ##
    # set long filename (ls -l like output)
    #
    # @anonparam [First:string] longname contents
    # @category SSH
    ##
    public function set_longname() { longname = _FCT_ANON_ARGS[0]; }

    ##
    # sftp_file constructor
    #
    # @anonparam [First:string] file name
    # @category SSH
    ##
    function sftp_file()
    {
      attrs = new("sshlib::sftp_file_attrs");
      name = _FCT_ANON_ARGS[0];
    }

    ##
    # get printable file list
    #
    # @category SSH
    # @return long listing string (ls -l style) if available, otherwise filename
    ##
    public function get_printable_listing()
    {
      if(!isnull(longname)) return longname;
      else return name;
    }
  }

  ##
  # sftp session object
  ##
  object sftp_session
  {
    var channel,session;
    var req_id = 0;

    # maximum buffer allocation size for GizaNE engine, -1MB for some extra room
    var max_alloc_size = 1024*1024*39;

    var version = 3;
    var remote_version;

    # status code / error message for last operation
    var status_code;
    var status_error_message;
    var status_error_message_lang;



    ##
    # sftp_session object constructor
    #
    # @anonparam [Fist:channel_obj] channel
    # @category SSH
    ##
    function sftp_session()
    {
      this.channel = _FCT_ANON_ARGS[0];
      this.session = this.channel.session;
      this.channel.set_sftp_session(this);
    }

    ##
    # send sftp packet
    #
    # @param [type:integer] packet type
    # @param [data:raw_string] packet data
    # @category SSH
    ##
    function sftp_send(type, data)
    {
      var pkt = new("sshlib::sftp_packet", type, data);
      this.channel.window_send_data(data:pkt.build()); 
    }

    ##
    # callback to check if we are done receiving sftp data
    #
    # @remark called by sftp_session_check_recv_done_cb()
    # @category SSH
    #
    # @return TRUE or FALSE
    ##
    public function sftp_recv_check_done()
    {
      if(!this.channel.last_response && !isnull(this.channel.last_response)) return TRUE; # channel failure (most likely on FXP_INIT)
      if(strlen(this.channel.data_buf) < 4) return FALSE;

      if((strlen(this.channel.data_buf) - 4) >= getdword(blob:this.channel.data_buf, pos:0, order:BYTE_ORDER_BIG_ENDIAN))
        return TRUE;

      return FALSE;
    }

    ##
    # receive SFTP packet
    #
    # @category SSH
    # @return sftp packet
    ##
    function sftp_recv()
    {
      var cb = @sftp_session_check_recv_done_cb; 
      this.session.sshrecv_until(end_states:make_list("SOC_CLOSED"), check_callback:cb, channel:channel);
      var pkt = new("sshlib::sftp_packet");
      pkt.parse(raw:this.channel.data_buf);
      this.channel.clear_data_buf(len:pkt.length + 4);
      return pkt;
    }

    ##
    # parses file attributes
    #
    # @param [data:raw_string] SFTP data to parse
    # @param [pos:integer_reference] position in data
    # @param [attrs:sftp_file_attrs_reference] attributes
    # @category SSH
    ##
    function parse_file_attributes(data, &pos, &attrs)
    {
      var flags, filesize, uid, gid, permissions, atime, mtime, extended, j;

      flags = getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
      pos += 4;

      if(flags & SSH_FILEXFER_ATTR_SIZE)
      {
        # can't handle 64 bit ints yet
        if(getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN) != 0)
          filesize = "overflow";
        else filesize = uint(getdword(blob:data, pos:pos + 4, order:BYTE_ORDER_BIG_ENDIAN));

        attrs.set_filesize(filesize);
        pos += 8;
      }
      if(flags & SSH_FILEXFER_ATTR_UIDGID)
      {
        uid = getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
        gid = getdword(blob:data, pos:pos + 4, order:BYTE_ORDER_BIG_ENDIAN);
        attrs.set_uid(uid);
        attrs.set_gid(gid);
        pos += 8;
      }
      if(flags & SSH_FILEXFER_ATTR_PERMISSIONS)
      {
        permissions = getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
        attrs.set_permissions(permissions);
        pos += 4;
      }
      if(flags & SSH_FILEXFER_ATTR_ACMODTIME)
      {
        atime = getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
        mtime = getdword(blob:data, pos:pos + 4, order:BYTE_ORDER_BIG_ENDIAN);
        attrs.set_atime(atime);
        attrs.set_mtime(mtime);
        pos += 8;
      }
      if(flags & SSH_FILEXFER_ATTR_EXTENDED)
      {
        var tmp1, tmp2;
        extended = make_array();
        var pairs = getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
        pos += 4;
        for(j=0; j<pairs; j++)
        {
          tmp1 = get_ssh_string(buffer:data, pos:pos);
          pos += strlen(tmp1) + 4;
          tmp2 = get_ssh_string(buffer:data, pos:pos);
          pos += strlen(tmp2) + 4;
          extended[tmp1] = tmp2;
        }
        attrs.set_extended(extended);
      }
    }

    ##
    # parse fxp file name packet
    #
    # @param [data:raw_string] packet data to parse
    # @category SSH
    #
    # @return sftp_file
    ##
    function parse_fxp_name(data)
    {
      var files = make_list();
      var count = getdword(blob:data, pos:4, order:BYTE_ORDER_BIG_ENDIAN);
      var tmp_filename, tmp_longname;
      var i, j;

      var pos;
      pos = 8;
      for (i=0; i<count; i++)
      {
        tmp_filename = get_ssh_string(buffer:data, pos:pos);
        var file = new("sshlib::sftp_file", tmp_filename);

        pos += strlen(tmp_filename) + 4;
        tmp_longname = get_ssh_string(buffer:data, pos:pos);
        file.set_longname(tmp_longname);

        pos += strlen(tmp_longname) + 4;

        var attrs = file.attrs;
        parse_file_attributes(data:data, pos:pos, attrs:attrs);

        files = make_list(files, file);
      }
      return files;
    }

    ##
    # initialize SFTP session
    #
    # @remark we currently only support version 3 of SFTP protocol
    # @category SSH
    #
    # @return TRUE or FALSE (on error)
    ##
    public function init()
    {
      var fn = 'sftp_session.init';
      this.channel.make_request(type:"subsystem", want_reply:TRUE, extra:mk_ssh_string("sftp"));

      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'sending SSH_FXP_INIT on channel ' + this.channel.local_channel + '...\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);

      sftp_send(type:SSH_FXP_INIT, data:mkdword(version, order:BYTE_ORDER_BIG_ENDIAN));

      var tmp_pkt = sftp_recv();

      if(tmp_pkt.type != SSH_FXP_VERSION)
        return this.session.set_error("Error starting sftp session on channel " +
            this.channel.local_channel + ", did not receive SSH_FXP_VERSION.");

      remote_version = getdword(blob:tmp_pkt.data, pos:0, order:BYTE_ORDER_BIG_ENDIAN);

      if(remote_version != 3)
        return this.session.set_error(
            'sftp_session: remote server does not support version 3 (version ' +
              remote_version + ' required by server).');

      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'SFTP session initialized on channel ' +
            this.channel.local_channel + ', remote sftp version = ' +
            remote_version + '\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);

      return TRUE;
    }

    ##
    # open directory
    #
    # @param [dir_path:string] directory path
    # @category SSH
    #
    # @return file handle string or NULL
    ##
    function open_directory(dir_path)
    {
      var fn = 'sftp_session.open_directory';
      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'Sending SSH_FXP_OPENDIR on channel ' +
            this.channel.local_channel + '...\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);

      var tmp_data = mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
        mk_ssh_string(dir_path);
      sftp_send(type:SSH_FXP_OPENDIR, data:tmp_data);

      var tmp_pkt = sftp_recv();

      if(tmp_pkt.type == SSH_FXP_HANDLE)
      {
        this.session.dbg_log(
            fn:fn,
            level:DEBUG2,
            message:'got sftp handle : ' +
              hexstr(get_ssh_string(buffer:tmp_pkt.data, pos:4)) +
              ' on channel ' + this.channel.local_channel + '\n',
            sftp:SFTP_LOG,
            sftp_channel:this.channel.local_channel);
        return get_ssh_string(buffer:tmp_pkt.data, pos:4);
      }
      if(tmp_pkt.type == SSH_FXP_STATUS)
        parse_status(data:tmp_pkt.data);
    }

    ##
    # Read directory
    #
    # @param [handle:file_handle_str] file handle
    # @category SSH
    #
    # @return list of sftp_file objects or NULL
    ## 
    function read_directory(handle)
    {
      var fn = 'sftp_session.read_directory';
      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'Sending SSH_FXP_READDIR on channel ' +
            this.channel.local_channel + '...\n',
            sftp:SFTP_LOG,
            sftp_channel:this.channel.local_channel);
      var tmp_data = mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
        mk_ssh_string(handle);
      sftp_send(type:SSH_FXP_READDIR, data:tmp_data);
      var tmp_pkt = sftp_recv();
      if(tmp_pkt.type == SSH_FXP_NAME)
        return parse_fxp_name(data:tmp_pkt.data);
      if(tmp_pkt.type == SSH_FXP_STATUS)
        parse_status(data:tmp_pkt.data);
    }

    ##
    # Parse SSH_FXP_STATUS packet
    #
    # @param [data:raw_string] packet data
    # @category SSH
    ##
    function parse_status(data)
    {
      var pos = 4;
      status_code = getdword(blob:data, pos:pos, order:BYTE_ORDER_BIG_ENDIAN);
      pos += 4;
      status_error_message = get_ssh_string(buffer:data, pos:pos);

      this.session.dbg_log(
          message:"sftp_session: got SSH_FXP_STATUS (" + status_code + " - " +
            status_error_message + ")",
          level:DEBUG2,
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);

      pos += strlen(status_error_message) + 4;
      status_error_message_lang = get_ssh_string(buffer:data, pos:pos);
    }

    ##
    # Close a file
    #
    # @param [handle:file_handle_str]
    # @category SSH
    ##
    public function close_file(handle)
    {
      var fn = 'sftp_session.close_file';
      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'Sending SSH_FXP_CLOSE on channel ' + this.channel.local_channel +
            '...\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);
      var tmp_data = mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
        mk_ssh_string(handle);
      sftp_send(type:SSH_FXP_CLOSE, data:tmp_data);
      var tmp_pkt = sftp_recv();
      if(tmp_pkt.type == SSH_FXP_STATUS)
        parse_status(data:tmp_pkt.data);
    }

    ##
    # Open a file
    #
    # @param [dir_path:string]
    # @category SSH
    #
    # @return file handle (string)
    ##
    public function open_file(dir_path, attrs)
    {
      var fn = 'sftp_session.open_file';
      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'Sending SSH_FXP_OPEN on channel ' +
            this.channel.local_channel + '...\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);


      # byte SSH_FXP_OPEN
      # uint32 request-id
      # string filename
      # uint32 desired-access
      # uint32 flags
      # ATTRS attrs - not required for read only

      var tmp_data;
      if(isnull(attrs))
      {
        tmp_data =
          mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
          mk_ssh_string(dir_path) +
          mkdword(SSH_FXF_READ, order:BYTE_ORDER_BIG_ENDIAN) +
          mkdword(0, order:BYTE_ORDER_BIG_ENDIAN);
      }
      else
      {
        tmp_data =
          mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
          mk_ssh_string(dir_path) +
          mkdword(SSH_FXF_WRITE|SSH_FXF_CREAT, order:BYTE_ORDER_BIG_ENDIAN) +
          attrs.to_buf();
      }


      sftp_send(type:SSH_FXP_OPEN, data:tmp_data);
      var tmp_pkt = sftp_recv();

      if(tmp_pkt.type == SSH_FXP_HANDLE)
      {
        var handle = get_ssh_string(buffer:tmp_pkt.data, pos:4);
        return handle;
      }
      if(tmp_pkt.type == SSH_FXP_STATUS)
        parse_status(data:tmp_pkt.data);
    }

    ##
    # Stat a file
    #
    # @param [dir_path:string] Directory path
    # @category SSH
    #
    # @return sftp_file_attrs object or NULL
    ##
    public function file_stat(dir_path)
    {
      var fn = 'sftp_session.file_stat';
      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'Sending SSH_FXP_STAT on channel ' +
            this.channel.local_channel +'...\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);
      var tmp_data = mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
        mk_ssh_string(dir_path);
      var attrs = new("sshlib::sftp_file_attrs");
      sftp_send(type:SSH_FXP_STAT, data:tmp_data);

      var tmp_pkt = sftp_recv();
      if(tmp_pkt.type == SSH_FXP_ATTRS)
      {
        var pos = 4;
        parse_file_attributes(data:tmp_pkt.data, pos:pos, attrs:attrs);
        return attrs;
      }
      if(tmp_pkt.type == SSH_FXP_STATUS)
        parse_status(data:tmp_pkt.data);
    }

    ##
    # Read file from sftp server
    #
    # @param [dir_path:string] Directory path
    # @param [offset:integer] Offset to read from
    # @param [length:integer] Amount of data to read
    #
    # @category SSH
    #
    # @return file contents
    ##
    public function read_file(dir_path, offset, length)
    {
      var fn = 'sftp_session.read_file';
      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'entering read_file() on channel ' +
            this.channel.local_channel + '\n',
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);
      var attrs = file_stat(dir_path:dir_path);

      var file_size = attrs.filesize;

      var handle = open_file(dir_path:dir_path);
      if(!isnull(handle))
      {
        if(isnull(length) || typeof(length) != 'int')
          length = file_size;

        if("int" >!< typeof(length) || length > max_alloc_size) length = max_alloc_size;
        if(isnull(offset)) offset = 0;

        if(length > file_size) length = file_size;

        var tmp_data =
          mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
          mk_ssh_string(handle) +
          mkdword(0, order:BYTE_ORDER_BIG_ENDIAN) +
          mkdword(offset, order:BYTE_ORDER_BIG_ENDIAN) +
          mkdword(length, order:BYTE_ORDER_BIG_ENDIAN);

        this.session.dbg_log(
            fn:fn,
            level:DEBUG2,
            message:'sending SSH_FXP_READ on channel ' +
              this.channel.local_channel + '\n',
            sftp:SFTP_LOG,
            sftp_channel:this.channel.local_channel);

        sftp_send(type:SSH_FXP_READ, data:tmp_data);

        var tmp_pkt;
        tmp_pkt = sftp_recv();

        var res = '';
        if(tmp_pkt.type == SSH_FXP_DATA)
          res = get_ssh_string(buffer:tmp_pkt.data, pos:4);
        while(tmp_pkt.type == SSH_FXP_DATA && strlen(res) < length)
        {
          tmp_data =
            mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
            mk_ssh_string(handle) +
            mkdword(0, order:BYTE_ORDER_BIG_ENDIAN) +
            mkdword(strlen(res), order:BYTE_ORDER_BIG_ENDIAN) +
            mkdword(length, order:BYTE_ORDER_BIG_ENDIAN);

          this.session.dbg_log(
              fn:fn,
              level:DEBUG2,
              message:'sending SSH_FXP_READ on channel ' +
                this.channel.local_channel + '\n',
              sftp:SFTP_LOG,
              sftp_channel:this.channel.local_channel);

          sftp_send(type:SSH_FXP_READ, data:tmp_data);

          tmp_pkt = sftp_recv();
          if(tmp_pkt.type == SSH_FXP_DATA)
            res += get_ssh_string(buffer:tmp_pkt.data, pos:4);
        }

        close_file(handle:handle);
        return res;
      }
    }

    public function write_file(dir_path, data, exec)
    {
      var fn = 'sftp_session.write_file';
      var failed = FALSE;
      var tmp_data, i, pieces, data_piece, maxpkt, maxwin, maxsz, filesize;
      var offset, attrs, handle, tmp_pkt, padlen;

      padlen = this.session.cipherset.get_block_size(mode:MODE_OUT) - 1;

      session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'entering write_file() on '+this.channel.local_channel,
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);

      filesize = strlen(data);
      offset = 0;

      attrs = create_attrs();
      attrs.set_filesize(strlen(data));
      if(exec)
        attrs.set_exec_permissions();
      else
        attrs.set_default_permissions();

      handle = open_file(dir_path:dir_path, attrs:attrs);

      if(isnull(handle))
        return FALSE;

      while (offset < filesize)
      {
        maxpkt = this.channel.remote_maxpacket -
          10 -                            # Allow 10 bytes for header, 
          strlen(handle) - 4 -            # allow room for ssh string handle
          8 - padlen;                     # allow room for uint64 offset and padding
        maxwin = this.channel.remote_window -
          10 -                            # Allow 10 bytes for header, 
          strlen(handle) - 4 -            # allow room for ssh string handle
          8 - padlen;                     # allow room for uint64 offset and padding

        if(maxpkt < maxwin)
          maxsz = maxpkt;
        else
          maxsz = maxwin;

        data_piece = substr(data, offset, offset + maxsz);

        # byte SSH_FXP_WRITE
        # uint32 request-ed
        # string handle
        # uint64 offset
        # string data

        tmp_data =
          mkdword(req_id++, order:BYTE_ORDER_BIG_ENDIAN) +
          mk_ssh_string(handle) +
          mkdword(0, order:BYTE_ORDER_BIG_ENDIAN) +
          mkdword(offset, order:BYTE_ORDER_BIG_ENDIAN) +
          mk_ssh_string(data_piece);

        sftp_send(type:SSH_FXP_WRITE, data:tmp_data);
        offset += maxsz;

        tmp_pkt = sftp_recv();
        if(tmp_pkt.type == SSH_FXP_STATUS)
          parse_status(data:tmp_pkt.data);
        else
        {
          this.session.dbg_log(
              fn:fn,
              level:DEBUG1,
              message:'received unexpected packet type '+tmp_pkt.type+' : ',
              sftp:SFTP_LOG,
              sftp_channel:this.channel.local_channel);
          failed = TRUE;
          break;
        }

        if(this.status_code != SSH_FX_OK) // parse_status already logged the error
        {
          this.session.dbg_log(fn:fn,
              level:DEBUG1,
              message:'got bad status: '+status_error_message,
              sftp:SFTP_LOG,
              sftp_channel:this.channel.local_channel);
          failed = TRUE;
          break;
        }
      }

      close_file(handle:handle);

      this.session.dbg_log(
          fn:fn,
          level:DEBUG1,
          message:'failed = '+failed,
          sftp:SFTP_LOG,
          sftp_channel:this.channel.local_channel);

      if(failed)
        return FALSE;
      else
        return TRUE;
    }



    ##
    # List directory
    #
    # @param [dir_path:string] Directory path
    # @category SSH
    #
    # @return list of sftp_file objects
    ##
    public function list_directory(dir_path)
    {
      var handle = open_directory(dir_path:dir_path);
      if(!isnull(handle))
        return read_directory(handle:handle);
    }
  } 
}
