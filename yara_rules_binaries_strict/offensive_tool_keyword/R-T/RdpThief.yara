rule RdpThief
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string1 = /\/RdpThief\.git/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string2 = /\\RdpThief\./ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string3 = /\\RdpThief_x64\./ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string4 = /0x09AL\/RdpThief/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string5 = /71461ca71bcebb5fefa9394fe8e9a5a47c102195064d1f4cb5f24d330c9be97d/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string6 = /ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string7 = /ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string8 = /BEBE6A01\-0C03\-4A7C\-8FE9\-9285F01C0B03/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string9 = /BEBE6A01\-0C03\-4A7C\-8FE9\-9285F01C0B03/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string10 = /cd7e4cd71cb803de24f7b8fc6c6946f96e9b9a95dd3c0888309b42446ba87b94/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string11 = /d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string12 = /d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string13 = /Disabling\sRdpThief/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string14 = /RdpThief\senabled\s/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string15 = /RdpThief/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string16 = /RdpThief\.dll/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string17 = /RdpThief\.exe/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string18 = /RdpThief_x64\.tmp/ nocase ascii wide
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
