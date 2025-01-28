rule SharpADWS
{
    meta:
        description = "Detection patterns for the tool 'SharpADWS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpADWS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string1 = /\scan\snow\simpersonate\susers\son\s.{0,100}\svia\sS4U2Proxy/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string2 = " Kerberoastable -action list" nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string3 = " Kerberoastable -action write -target " nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string4 = /\sRBCD\s\-action\swrite\s\-delegate\-to\s.{0,100}\s\-delegate\-from\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string5 = /\.exe\sacl\s\-dn\s.{0,100}\s\-scope\s.{0,100}\s\-trustee\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string6 = /\.exe\sCertify\s\-action\sfind\s\-enrolleeSuppliesSubject\s\-clientAuth/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string7 = /\.exe\sCertify\s\-action\sfind/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string8 = /\.exe\sDCSync\s\-action\slist/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string9 = /\.exe\sDCSync\s\-action\swrite\s\-target\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string10 = /\.exe\sDontReqPreAuth\s\-action\slist/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string11 = /\.exe\sDontReqPreAuth\s\-action\swrite\s\-target\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string12 = /\.exe\sRBCD\s\-action\sread\s\-delegate\-to\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string13 = /\.exe\sWhisker\s\-action\sadd\s\-target\s.{0,100}\s\-cert\-pass\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string14 = /\.exe\sWhisker\s\-action\slist\s\-target\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string15 = /\/SharpADWS\.git/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string16 = /\[\-\]\sAccount\sto\skerberoast\sdoes\snot\sexist\!/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string17 = /\[\-\]\sElevating\s.{0,100}\swith\sDCSync\sprivileges\sfailed/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string18 = /\\SharpADWS\.csproj/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string19 = /\\SharpADWS\.sln/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string20 = /\\SharpADWS\\/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string21 = /\\SharpADWS\-master/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string22 = /\]\sFound\skerberoastable\susers\:\s/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string23 = /\]\sKerberoast\suser\s.{0,100}\ssuccessfully\!/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string24 = "70ef0d3588b87bd71c2774c1bb177f59ae31a99b1a4ef82f7d2a16175c3caaf6" nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string25 = "AA488748-3D0E-4A52-8747-AB42A7143760" nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string26 = /SharpADWS\s1\.0\.0\-beta\s\-\sCopyright/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string27 = /SharpADWS\.exe/ nocase ascii wide
        // Description: SharpADWS Active Directory reconnaissance and exploitation for Red Teams via the Active Directory Web Services (ADWS)
        // Reference: https://github.com/wh0amitz/SharpADWS
        $string28 = "wh0amitz/SharpADWS" nocase ascii wide
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
