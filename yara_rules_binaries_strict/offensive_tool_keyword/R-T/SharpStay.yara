rule SharpStay
{
    meta:
        description = "Detection patterns for the tool 'SharpStay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpStay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string1 = " action=BackdoorLNK " nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string2 = /\saction\=CreateService\sservicename\=.{0,100}\scommand\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string3 = " action=ElevatedRegistryKey keyname=Debug keypath" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string4 = " action=ElevatedUserInitKey command=" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string5 = /\saction\=JunctionFolder\sdllpath\=.{0,100}\.dll\sguid\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string6 = /\saction\=NewLNK\sfilepath\=.{0,100}\\"\slnkname\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string7 = /\saction\=ScheduledTask\staskname\=.{0,100}\scommand\=.{0,100}runasuser/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string8 = /\saction\=ScheduledTaskAction\staskname\=.{0,100}\scommand\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string9 = " action=SchTaskCOMHijack clsid=" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string10 = " action=UserRegistryKey keyname=Debug keypath=HKCU:" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string11 = /\saction\=WMIEventSub\scommand\=.{0,100}\seventname\=/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string12 = /\.exe\saction\=GetScheduledTaskCOMHandler/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string13 = /\.exe\saction\=ListRunningServices/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string14 = /\.exe\saction\=ListScheduledTasks/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string15 = /\.exe\saction\=ListTaskNames/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string16 = "/0xthirteen/" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string17 = /\/SharpStay\.git/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string18 = "/SharpStay/" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string19 = /\[\+\]\sCreated\sElevated\sHKLM\:/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string20 = /\[\+\]\sUpdated\sElevated\sHKLM\:Software\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Winlogon\skey\sUserInit/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string21 = "0xthirteen/SharpStay" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string22 = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string23 = "2963C954-7B1E-47F5-B4FA-2FC1F0D56AEA" nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string24 = "action=SchTaskCOMHijack " nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string25 = /SharpStay\.csproj/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string26 = /Sharpstay\.exe/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string27 = /SharpStay\.sln/ nocase ascii wide
        // Description: SharpStay - .NET Persistence
        // Reference: https://github.com/0xthirteen/SharpStay
        $string28 = "SharpStay-master" nocase ascii wide
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
