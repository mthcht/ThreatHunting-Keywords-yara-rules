rule AutoSmuggle
{
    meta:
        description = "Detection patterns for the tool 'AutoSmuggle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSmuggle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string1 = /\/AutoSmuggle\.git/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string2 = /\[.{0,100}\]\sSmuggling\sin\sHTML/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string3 = /\[.{0,100}\]\sSmuggling\sin\sSVG/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string4 = /\\AutoSmuggle\\.{0,100}\.cs/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string5 = /57A893C7\-7527\-4B55\-B4E9\-D644BBDA89D1/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string6 = /AutoSmuggle\.csproj/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string7 = /AutoSmuggle\.exe/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string8 = /AutoSmuggle\.sln/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string9 = /AutoSmuggle\-master/ nocase ascii wide
        // Description: Utility to craft HTML or SVG smuggled files for Red Team engagements
        // Reference: https://github.com/surajpkhetani/AutoSmuggle
        $string10 = /surajpkhetani\/AutoSmuggle/ nocase ascii wide
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
