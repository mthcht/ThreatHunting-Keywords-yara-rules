rule TokenStealer
{
    meta:
        description = "Detection patterns for the tool 'TokenStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string1 = /\.exe\s\-u\s.{0,100}\s\-s\s2\s\-c\scmd\.exe/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string2 = /\/TokenStealer\.git/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string3 = /\[\+\]\sMy\spersonal\ssimple\sand\sstupid\s\sToken\sStealer\.\.\.\s/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string4 = /\[\+\]\sv1\.0\s\@decoder_it\s2023/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string5 = /\]\sToken\sdoes\sNOT\shave\sSE_ASSIGN_PRIMARY_NAME.{0,100}\susing\sCreateProcessAsWithToken\(\)\sfor\slaunching\:/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string6 = "<SessionId>: list/steal token from specific session" nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string7 = "ABC32DBD-B697-482D-A763-7BA82FE9CEA2" nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string8 = "decoder-it/TokenStealer" nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string9 = /list\/steal\stoken\sof\suser\s\<user\>.{0,100}default\sNT\sAUTHORITY\\\\SYSTEM\sfor\scomamnd\sexecution/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string10 = "-t: force use of Impersonation Privilege" nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string11 = /TokenStealer\.cpp/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string12 = /TokenStealer\.exe/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string13 = /TokenStealer\.sln/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string14 = /TokenStealer\.vcxproj/ nocase ascii wide
        // Description: stealing Windows tokens
        // Reference: https://github.com/decoder-it/TokenStealer
        $string15 = "TokenStealer-master" nocase ascii wide
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
