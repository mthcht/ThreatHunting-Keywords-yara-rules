rule libprocesshider
{
    meta:
        description = "Detection patterns for the tool 'libprocesshider' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "libprocesshider"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string1 = /\sevil_script\.py/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string2 = /\slibprocesshider\.so\s/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string3 = /\/bin\/processhider/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string4 = /\/evil_script\.py/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string5 = /\/libprocesshider\.git/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string6 = /\/libprocesshider\.so/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string7 = /\/processhider\.c/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string8 = /\\evil_script\.py/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string9 = /16d765e024adacabe84e9fd889030f5481546ef711bba0043e7e84eadd257d1a/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string10 = /eb5fee1e402f321c8e705776faf2be7bbede5d2a24fe3ac40be082a75429f927/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string11 = /gianlucaborello\/libprocesshider/ nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string12 = /https\:\/\/sysdig\.com\/blog\/hiding\-linux\-processes\-for\-fun\-and\-profit\// nocase ascii wide
        // Description: Hide a process under Linux using the ld preloader
        // Reference: https://github.com/gianlucaborello/libprocesshider
        $string13 = /sock\.send\(\\"\\"I\sAM\sA\sBAD\sBOY\\"\\"\)/ nocase ascii wide
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
