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
        $string1 = /\s\-c\s.{0,100}\s\-s\s.{0,100}\s\-o\sshare_listing\s\-m\s150/ nocase ascii wide
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
        $string10 = /\/tmp\/smb_auth_temp_.{0,100}\.txt/ nocase ascii wide
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
        $string14 = /No\scredentials\ssupplied.{0,100}\slooking\sfor\snull\ssession\sshares\!/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string15 = /Raikia\/SMBCrunch/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string16 = /share_listing\/ALL_COMBINED_RESULTS\.TXT/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string17 = /smbclient\s\-N\s\-A\s.{0,100}\\\\\\\\.{0,100}\\\\.{0,100}temp_out\.txt/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string18 = /SMBCrunch\-master/ nocase ascii wide
        // Description: SMBCrunch allows a red teamer to quickly identify Windows File Shares in a network - performs a recursive directory listing of the provided shares  and can even grab a file from the remote share if it looks like a juicy target.
        // Reference: https://github.com/Raikia/SMBCrunch
        $string19 = /Starting\senumerating\sfile\sshares\susing\sdomain\scredential\sfor\s/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
