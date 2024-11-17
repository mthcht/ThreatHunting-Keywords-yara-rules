rule EvilnoVNC
{
    meta:
        description = "Detection patterns for the tool 'EvilnoVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilnoVNC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string1 = /\s\/tmp\/resolution\.txt/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string2 = /\sEvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string3 = /\/bin\/bash\s\-c\s\\"php\s\-q\s\-S\s0\.0\.0\.0\:80\s\&\\"\s\>\s\/dev\/null\s2\>\&1/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string4 = /\/Downloads\/Keylogger\.txt/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string5 = /\/Downloads\/keypress\.log/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string6 = /\/EvilnoVNC\.git/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string7 = /\/noVNC\/utils\/novnc_proxy/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string8 = /\/start\.sh\sdynamic\s/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string9 = /\/startVNC\.sh/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string10 = /\/tmp\/resolution\.txt.{0,100}server\.sh/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string11 = /\\EvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string12 = /\\Keylogger\.txt/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string13 = /1a571ac5b806ffce2605b57753f74653ddb392e5afdb0e49c3e9e8d76e561568/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string14 = /docker\srmi\sevilnginx/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string15 = /docker\srmi\sevilnovnc/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string16 = /echo\s\'user\sALL\=\(ALL\)\sNOPASSWD\:ALL\'\s\>\>\s\/etc\/sudoers/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string17 = /EvilnoVNC\sby\s\@JoelGMSec/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string18 = /EvilnoVNC\sServer/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string19 = /evilnovnc\.Dockerfile/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string20 = /EvilnoVNC\-main/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string21 = /Import\sstealed\ssession\sto\sChromium\.\./ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string22 = /JoelGMSec\s\-\shttps\:\/\/darkbyte\.net/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string23 = /JoelGMSec\/EvilnoVNC/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string24 = /keylogger\.py/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string25 = /kiosk\.sh.{0,100}startVNC\.sh/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string26 = /nandydark\/Linux\-keylogger/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string27 = /novnc_proxy\s\-\-vnc\slocalhost\:/ nocase ascii wide
        // Description: EvilnoVNC is a Ready to go Phishing Platform
        // Reference: https://github.com/JoelGMSec/EvilnoVNC
        $string28 = /Wanetty\sinspired\sby\s\@JoelGMSec/ nocase ascii wide
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
