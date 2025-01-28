rule kiglogger
{
    meta:
        description = "Detection patterns for the tool 'kiglogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kiglogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string1 = "/bin/kidlogger"
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string2 = "/etc/kidlogger"
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string3 = /\/KidLogger\.app\//
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string4 = /\/kidlogger\.desktop/
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string5 = "/srv/kidlogger"
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string6 = "/usr/share/kidlogger"
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string7 = /\\KidLogger\\/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string8 = /\\KidLogger_is1/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string9 = /\\Program\sFiles\s\(x86\)\\KidLogger/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string10 = /\\Software\\Kidlogger/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string11 = /\\WOW6432Node\\Kidlogger/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string12 = "3170917f0dbe26d4a09283394af0b9a9e9724589cd650d0b451b2c834aab3bf6" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string13 = "3ec8a46dfacff51b3a19034479c2c68b74c92342e483295152754f939a8d1d31" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string14 = "4fcf193202e55eff267792c86cea4098711b24d3fa0cca8e03027da2ddb3206a" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string15 = "89a687f0367983c98008e9bd2d82e6aa579e24f2d702b6912eeae74b21e85dc9" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string16 = "c8bdc5ce227d167f87797e8f7b3d91d24cd40c0925f5f6406085ad8cdf455617" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string17 = /github\.com\/SafeJKA\/Kidlogger/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string18 = /KidLogger\-.{0,100}\.dmg/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string19 = /kidlogger\.conf/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string20 = /Kidlogger\.exe/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string21 = /KidLogger\.lnk/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string22 = /KidLogger\.net/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string23 = /KidLogger\.pif/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string24 = /KidLogger\.url/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string25 = "kidlogger_install" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string26 = /kidlogger_user\.exe/ nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string27 = "make shared dir for kidlogger ini files" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string28 = "package kidlogger" nocase ascii wide
        // Description: malware parental control software - keylogger
        // Reference: https://kidlogger.net/download.html
        $string29 = /window\-state\@safejka\.eu/ nocase ascii wide
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
