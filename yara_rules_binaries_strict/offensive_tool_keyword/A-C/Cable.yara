rule Cable
{
    meta:
        description = "Detection patterns for the tool 'Cable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cable"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string1 = /\.NET\spost\-exploitation\stoolkit\sfor\sActive\sDirectory\sreconnaissance\sand\sexploitation\s/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string2 = /\[\-\]\sNo\sKerberoastable\saccounts\sfound/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string3 = /\[\+\]\sFinding\sKerberoastable\saccounts/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string4 = /\[\+\]\sSID\sadded\sto\smsDS\-AllowedToActOnBehalfOfOtherIdentity/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string5 = "06B2AE2B-7FD3-4C36-B825-1594752B1D7B" nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string6 = "16717cf09d49d252b21c5768092a557ea5a7899d781656da909a7766b6c55074" nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string7 = "fff1c91cf41743e46dc2b43b256680ce9015d0a705b31cf19c2cfb48f48c616f" nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string8 = "logangoins/Cable" nocase ascii wide
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
