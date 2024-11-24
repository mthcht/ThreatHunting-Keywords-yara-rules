rule MozillaCookiesView
{
    meta:
        description = "Detection patterns for the tool 'MozillaCookiesView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MozillaCookiesView"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string1 = /\/mzcv\.exe/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string2 = /\/mzcv\-x64\.zip/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string3 = /\\mzcv\.exe/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string4 = /\\mzcv\-x64\.zip/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string5 = ">MZCookiesView<" nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string6 = "0fbcaa65ada37326741259d2ebc96d52e61d38cd6c28823194f2ffb4bf906ebe" nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string7 = "cace36a7ea185c8a675356f6e3eeb5b1d466666f7853aa9813df486c5178cbdf" nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string8 = /MZCookiesView.{0,100}cookies\.sqlite/ nocase ascii wide
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
