rule blackvision
{
    meta:
        description = "Detection patterns for the tool 'blackvision' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackvision"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string1 = /\/blackvision\.git/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string2 = /\/blackvision_c\.cpp/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string3 = /31abb963d6b98c0d5068bb32c6d13c98694a45a4cd9af738b215d7ff96944140/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string4 = /4527ed46e39c8486c0f9d7f48fa7c4ae58a980db49ebcb881c174d88925a551b/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string5 = /agent\/blackvision\.cpp/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string6 = /d56d56e534a399f0130e77ee424fc4c0c81e296a9c3a3560a97500a970119c1a/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string7 = /e4ce017fd52b2dab10d33e9fbe51dcb8e5b74b496121d8d121d228d5fbdb58e8/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string8 = /e7e397ee350cadf7f2b49b85c440a340a090881e58e3238d266164b095a4a82d/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string9 = /ea1f91ef5b0a9befefc831e9c1093cc202e214673b7fbbb1b737fab9f5326c53/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string10 = /from\sserver\.changehostnPort\simport\s/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string11 = /lynxmk\/blackvision/ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string12 = /Remote\sAccess\.\\n\\nA\swrapper\saround\scommands\sto\smake\sagent\sgeneration\seasy4u\./ nocase ascii wide
        // Description: Command line Remote Access tool (RAT) for Windows.
        // Reference: https://github.com/quantumcore/blackvision
        $string13 = /server\.sin_port\s\=\shtons\(3567\)/ nocase ascii wide
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
