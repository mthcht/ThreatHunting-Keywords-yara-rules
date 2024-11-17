rule CursedChrome
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string1 = /\/CursedChrome\.git/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string2 = /\/extension_injection\.sh/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string3 = /\/redirect\-hack\.html\?id\=/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string4 = /127\.0\.0\.1\:8118/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string5 = /A\snew\sbrowser\shas\sconnected\sto\sus\svia\sWebSocket\!/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string6 = /bash\sextension_injection\.sh/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string7 = /const\ssubscription_id\s\=\s\`TOPROXY_/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string8 = /COPY\sanyproxy\/\s\.\/anyproxy\// nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string9 = /CursedChrome\sAPI\sserver\sis\snow\slistening\son\sport/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string10 = /CursedChrome\sWebSocket\sserver\sis\snow\srunning\son\sport/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string11 = /CursedChrome\-master\.zip/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string12 = /DATABASE_PASSWORD\:\scursedchrome/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string13 = /DATABASE_USER\:\scursedchrome/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string14 = /docker\simages\s\|\sgrep\scursed/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string15 = /docker\sps\s\-a\s\|\sgrep\scursed/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string16 = /docker\-compose\sup\scursedchrome/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string17 = /http\:\/\/localhost\:8118/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string18 = /logit\(\`New\ssubscriber\:\sTOBROWSER__/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string19 = /mandatoryprogrammer\/CursedChrome/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string20 = /new\sWebSocket\(\\"ws\:\/\/127\.0\.0\.1\:4343\\"\)/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string21 = /publisher\.publish\(\`TOBROWSER_/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string22 = /Wat\,\sthis\sshouldn\'t\shappen\?\sOrphaned\smessage\s\(somebody\smight\sbe\sprobing\syou\!\)\:/ nocase ascii wide
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
