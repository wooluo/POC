#TRUSTED a2060c2c9d7b216622521778064a151264c728f9276bbb076265cc029c3ec976f6d45df0d0d53cde6b871424da3d4b74c75ead82bd434749e10a45d969faf7abc0cc1cabca018d54e693bf1a2da13668a9664ad74cdf4f40f3514daaf4c3826c47589c662c8c1a4b803e92cdbe1f8a21cbc94760d8a7a52982e78c7c5db94189e1a09441a42ed67a6e84fa948feedc1e746ee69fe009c26bf4ac32df1e6021e05b3fdb8b76443c81c403100f30f1693986f8ebb0314ab9a03add99ad76f5d9c41fbad50399fc110e7941cbba9e52fc3869caa8947ec7c0d55a6240fca2f9156186825701f21fe741bb3029d8dba990bf200bb6a91994eeb415fe616fc5fcf62a70b1de27d5b0577dd1d35e5340fa8ac95c92abe687a9a8d66b5be3d4f0db82dd2a77e2df608268c3846065cbb2e1a1c1015d412ed4f1097a7f4cdc2941303e4e15cd22c182b03fbffdc8a6ca7f24021ea707ea8976d83d8e5b41992d2cb202c889c1a9a972e8fde8f487b9ccc195aeb4c89cba19fa7d4e1d6d51766377e11e50a10f4645e3eb9c08c34826678bf8476007ca3622eb0883e19a6a5c6b2bdebe19010a9bfe65cd7f98e70eaba5ab71344befda5d69bc3afe3931b3bfc912b6dd085211d61ce2d6ac10c5aeca4737f3ac3f5cfe7d9ebc580407cb17fca69b9f9342b42169ea6c85b3946d94db25bf3fc187cf184fe98f618f0ba9866c5fb70c871f
#
# (C) WebRAY Network Security, Inc.
#
# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by WebRAY Network Security
#
# Revision 1.1

#pragma static
include("global_settings_nlib.inc");
include("misc_func_nlib.inc");
include("audit_nlib.inc");
include("data_protection_nlib.inc");
include("obj_nlib.inc");

#
# Backward compatibility functions
#
namespace compat {
  function this_host()
  {
    if (nasl_level() < 80102) return system::this_host();

    # Workaround for GizaNE 8.1.2+ bug where first call returns NULL
    system::this_host();
    return system::this_host();
  }
}
