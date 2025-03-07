rule RemoteKrbRelay
{
    meta:
        description = "Detection patterns for the tool 'RemoteKrbRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RemoteKrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string1 = /\s\.exe\s\-addgroupmember\s\-victim\s.{0,100}\s\-target\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string2 = /\s\.exe\s\-chp\s\-victim\s.{0,100}\s\-target\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string3 = /\s\.exe\s\-laps\s\-victim\s.{0,100}\s\-target\s.{0,100}\s\-clsid\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string4 = /\s\.exe\s\-ldapwhoami\s\-victim\s.{0,100}\s\-target\s.{0,100}\s\-clsid\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string5 = /\s\.exe\s\-rbcd\s\-victim\s.{0,100}\s\-target\s.{0,100}\s\-clsid\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string6 = " -forceshadowcred " nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string7 = " -local dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAAA" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string8 = " -shadowcred -victim " nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string9 = /\s\-smb\s\-\-smbkeyword\s.{0,100}\s\-victim\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string10 = /\sSystem\saccount\.\sOn\svictim\scomputer\sshould\sbe\sinstalled\sAD\sCS/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string11 = " --victimdn " nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string12 = /\/RemoteKrbRelay\.git/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string13 = /\[\!\]\sDont\sforget\sabout\sadding\syour\sattack\sin\sAcceptSecurityContext\(/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string14 = /\[\!\]\sI\swill\sdump\sall\scomputer\spasswords/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string15 = /\[\!\]\sPlease\sspecify\ssmb\sattack\skeyword\s\-\-smbkeyword\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string16 = /\[\-\]\sGot\serror\s\'LDAP_INSUFFICIENT_ACCESS\'\swhen\strying\sto\sadd\snew\sKeyCredential/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string17 = /\[\+\]\sClearing\smsDS\-KeyCredentialLink\sbefore\sadding\sour\snew\sKeyCredential/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string18 = /\[\+\]\sGot\sKrb\sAuth\sfrom\sNT\/System\.\sRelaying\sto\sADCS\snow/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string19 = /\\\\windows\\\\temp\\\\sam\.tmp/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string20 = /\\\\windows\\\\temp\\\\sys\.tmp/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string21 = /\\Checkerv2\.0\.exe\s\-outfile\s.{0,100}\s\-outformat\s/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string22 = /\\RemoteKrbRelay\\/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string23 = /\\RemoteKrbRelay\-main/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string24 = /\\windows\\\\temp\\\\sec\.tmp/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string25 = /\\windows\\temp\\sam\.tmp/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string26 = /\\windows\\temp\\sec\.tmp/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string27 = /\\windows\\temp\\sys\.tmp/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string28 = "0db0228defb8d913de486d4f799be97bc75b5aa2ae72c2fc1e99389aeb92b170" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string29 = "3b3b3491978395ddceeab0ee18aa25ae8fcb1a8df43ef80ab4423517e9c5f566" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string30 = "41d38b945928ee53bd8b1f3b230ecf3101f6c2249d1ec4d3d920a163045373b8" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string31 = "5494EDD3-132D-4238-AC25-FA384D78D4E3" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string32 = "79806039befe2c12c794ab8951aa17edf316843a8b968d22bd7abc9937252014" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string33 = "8d43a02d409a31297b2d1a997dbeaeaf10f97f499e2da819eef1318c0df652e4" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string34 = "8d7870f61a93a1466b02cad2cc5c036e1a7dc76753a6b90a38f41a6558c65146" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string35 = "906a7f9794d035af75552674eaa775b1584a129d1cd16d49c15bb5aa8032661a" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string36 = "B00DC126-D32B-429F-9BB5-97AF33BEE0E1" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string37 = "BC74B071-B36A-4EE8-8F03-5CF0A02C32DA" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string38 = "c973abdd59e75eda169065c64631477fa9ad6f01e3536d6f0754c27d0aeeec72" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string39 = "CICADA8 Research Team" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string40 = "CICADA8-Research/RemoteKrbRelay" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string41 = "F8317556-F82B-4FE2-9857-3E8DE896AA32" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string42 = "f96112996f7f6cc45c382096b622d7b8b909c38c116affbdb8cdd26f890763d2" nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string43 = /FindAvailablePort\.exe/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string44 = /From\sMichael\sZhmaylo\s\(MzHmO\)/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string45 = /RemoteKrbRelay\.exe/ nocase ascii wide
        // Description: similar to KrbRelay and KrbRelayUp but With RemoteKrbRelay this can be done remotely
        // Reference: https://github.com/CICADA8-Research/RemoteKrbRelay
        $string46 = "Small tool that allow you to bypass the firewall during COM operations" nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
