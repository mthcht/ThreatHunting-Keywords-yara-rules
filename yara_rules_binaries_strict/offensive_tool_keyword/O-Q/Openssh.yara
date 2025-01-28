rule Openssh
{
    meta:
        description = "Detection patterns for the tool 'Openssh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Openssh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Infecting SSH Public Keys with backdoors
        // Reference: https://blog.thc.org/infecting-ssh-public-keys-with-backdoors
        $string1 = /\&\&\scat\s\/etc\/motd.{0,100}exec\s\-a\s\-\$\(basename\s\$SHELL\)\s\$SHELL/
        // Description: Infecting SSH Public Keys with backdoors
        // Reference: https://blog.thc.org/infecting-ssh-public-keys-with-backdoors
        $string2 = "5b5b20242873746174202d632559202f62696e2f73682920213d20242873746174202d632559202e73736829205d5d202626207b203a3b746f756368202d72202f62696e2f7368202e7373683b6578706f7274204b45593d22223b62617368202d63202224286375726c202d6673534c207468632e6f72672f737368782922" nocase ascii wide
        // Description: Infecting SSH Public Keys with backdoors
        // Reference: https://blog.thc.org/infecting-ssh-public-keys-with-backdoors
        $string3 = "6563686f2048656c6c6f204261636b646f6f72" nocase ascii wide
        // Description: Infecting SSH Public Keys with backdoors
        // Reference: https://blog.thc.org/infecting-ssh-public-keys-with-backdoors
        $string4 = /command\=.{0,100}\#\#\#\-\-\-POWERSHELL\-\-\-.{0,100}eval\s\$\(echo\s/ nocase ascii wide
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
