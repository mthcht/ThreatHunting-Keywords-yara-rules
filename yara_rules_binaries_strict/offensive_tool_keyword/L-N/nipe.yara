rule nipe
{
    meta:
        description = "Detection patterns for the tool 'nipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nipe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string1 = /\/etc\/init\.d\/tor\sstart/
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string2 = /\/etc\/init\.d\/tor\sstop/
        // Description: An engine to make Tor Network your default gateway.
        // Reference: https://github.com/htrgouvea/nipe
        $string3 = /\/nipe\.git/ nocase ascii wide
        // Description: An engine to make Tor Network your default gateway.
        // Reference: https://github.com/htrgouvea/nipe
        $string4 = /\/nipe\.pl/ nocase ascii wide
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string5 = "/var/run/tor/control"
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string6 = /\/var\/run\/tor\/tor\.pid/
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string7 = "htrgouvea/nipe" nocase ascii wide
        // Description: An engine to make Tor Network your default gateway.
        // Reference: https://github.com/htrgouvea/nipe
        $string8 = "htrgouvea/nipe" nocase ascii wide
        // Description: An engine to make Tor network your default gateway. Tor enables users to surf the internet. chat and send instant messages anonymously.  and is used by a wide variety of people for both licit and illicit purposes. Tor has. for example. been used by criminals enterprises. hacktivism groups. and law enforcement  agencies at cross purposes. sometimes simultaneously. Nipe is a script to make the Tor network your default gateway.This Perl script enables you to directly route all your traffic from your computer to the Tor network through which you can surf the internet anonymously without having to worry about being tracked or traced back.
        // Reference: https://github.com/htrgouvea/nipe
        $string9 = /nipe\.pl\s/ nocase ascii wide
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string10 = /perl\snipe\.pl\sinstall/ nocase ascii wide
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string11 = /perl\snipe\.pl\sstart/ nocase ascii wide
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string12 = "systemctl start tor" nocase ascii wide
        // Description: An engine to make Tor network your default gateway
        // Reference: https://github.com/GouveaHeitor/nipe
        $string13 = /tor\s\-f\s\.configs\/.{0,100}\-torrc/ nocase ascii wide
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
