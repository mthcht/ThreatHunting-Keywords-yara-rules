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
        $string1 = /\s\-c\s.{0,1000}\s\-s\s.{0,1000}\s\-o\sshare_listing\s\-m\s150/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string2 = /\s\-i\sportscan445\.gnmap\s\-o\sshares_found\.txt/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string3 = /\sSMBGrab\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string4 = /\sSMBHunt\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string5 = /\sSMBList\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string6 = /\/SMBCrunch\.git/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string7 = /\/SMBGrab\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string8 = /\/SMBHunt\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string9 = /\/SMBList\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string10 = /\/tmp\/smb_auth_temp_.{0,1000}\.txt/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string11 = /\\SMBGrab\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string12 = /\\SMBHunt\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string13 = /\\SMBList\.pl/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string14 = /No\scredentials\ssupplied.{0,1000}\slooking\sfor\snull\ssession\sshares\!/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string15 = /Raikia\/SMBCrunch/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string16 = /share_listing\/ALL_COMBINED_RESULTS\.TXT/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string17 = /smbclient\s\-N\s\-A\s.{0,1000}\\\\\\\\.{0,1000}\\\\.{0,1000}temp_out\.txt/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string18 = /SMBCrunch\-master/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string19 = /Starting\senumerating\sfile\sshares\susing\sdomain\scredential\sfor\s/ nocase ascii wide

    condition:
        any of them
}
