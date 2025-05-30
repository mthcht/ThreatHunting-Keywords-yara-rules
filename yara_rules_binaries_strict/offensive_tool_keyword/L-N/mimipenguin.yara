rule mimipenguin
{
    meta:
        description = "Detection patterns for the tool 'mimipenguin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimipenguin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string1 = "/mimipenguin/releases/download/"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string2 = "37aaa060ddae57e5457ffc47f65362682d64da54775c2211705b8a7becc9e657"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string3 = "4d29f1251e4ef23a8e22ed209d547e84c421fa736b87646ddd8269c3a0e84093"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string4 = "7e158727df39c819d0b51228683ec4d1f1e9a949da480d6852445fa968814f46"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string5 = "af763332f70cf0137ebcb1d237e55a00c6fc0698982fec44fb012db4cb1be5df"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string6 = "c7d41f5a0fe15661632d70cde6b34787f87e4818d7c592ffa0c5b074fdb15712"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string7 = "e80bda100b7b75500bd6f4cc09e566e5467c784876bc01ba934ea8792daf8b11"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string8 = "f04f854c5bbfa8a33358efd2bb3e700e9be687250548a1cb21de1d661b5f04ff"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string9 = "fd8303c18bb8893e7d539cced09d4765805a37bd9ac5c92951ab381c70eec2a7"
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string10 = /mimipenguin\./
        // Description: A tool to dump the login password from the current linux user
        // Reference: https://github.com/huntergregal/mimipenguin
        $string11 = /mimipenguin_.{0,100}\.tar\.gz/
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
