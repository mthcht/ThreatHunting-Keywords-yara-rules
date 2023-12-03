rule SMBCrunch
{
    meta:
        description = "Detection patterns for the tool 'SMBCrunch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBCrunch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string1 = /.{0,1000}\s\-c\s.{0,1000}\s\-s\s.{0,1000}\s\-o\sshare_listing\s\-m\s150.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string2 = /.{0,1000}\s\-i\sportscan445\.gnmap\s\-o\sshares_found\.txt.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string3 = /.{0,1000}\sSMBGrab\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string4 = /.{0,1000}\sSMBHunt\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string5 = /.{0,1000}\sSMBList\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string6 = /.{0,1000}\/SMBCrunch\.git.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string7 = /.{0,1000}\/SMBGrab\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string8 = /.{0,1000}\/SMBHunt\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string9 = /.{0,1000}\/SMBList\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string10 = /.{0,1000}\/tmp\/smb_auth_temp_.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string11 = /.{0,1000}\\SMBGrab\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string12 = /.{0,1000}\\SMBHunt\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string13 = /.{0,1000}\\SMBList\.pl.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string14 = /.{0,1000}No\scredentials\ssupplied.{0,1000}\slooking\sfor\snull\ssession\sshares\!.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string15 = /.{0,1000}Raikia\/SMBCrunch.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string16 = /.{0,1000}share_listing\/ALL_COMBINED_RESULTS\.TXT.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string17 = /.{0,1000}smbclient\s\-N\s\-A\s.{0,1000}\\\\\\\\.{0,1000}\\\\.{0,1000}temp_out\.txt.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string18 = /.{0,1000}SMBCrunch\-master.{0,1000}/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string19 = /.{0,1000}Starting\senumerating\sfile\sshares\susing\sdomain\scredential\sfor\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
