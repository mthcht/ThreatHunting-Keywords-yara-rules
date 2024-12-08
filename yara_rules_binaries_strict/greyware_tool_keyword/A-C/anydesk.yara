rule anydesk
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: command line used with anydesk in the notes of the ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = " /c echo mar3pora " nocase ascii wide
        // Description: command line used with anydesk in the notes of the ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /\s\/c\secho\sPa\$\$w0rd\s\|\sC\:\\ProgramData\\anydesk\.exe/ nocase ascii wide
        // Description: command line used with anydesk in the notes of the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = /\sInvoke\-WebRequest\s\-Uri\shttp\:\/\/download\.anydesk\.com\/AnyDesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string4 = /\/\.anydesk\/\.anydesk\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string5 = /\/\.anydesk\/service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string6 = /\/\.anydesk\/system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string7 = /\/\.anydesk\/user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string8 = /\/Anydesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string9 = /\/Applications\/Anydesk\.app\// nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string10 = /\/etc\/systemd\/system\/anydesk\.service/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string11 = /\/home\/.{0,100}\/\.anydesk\// nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string12 = /\/log\/anydesk\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string13 = "/usr/bin/anydesk" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string14 = "/usr/lib64/anydesk" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string15 = "/usr/libexec/anydesk" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string16 = /\\adprinterpipe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string17 = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string18 = /\\AnyDesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string19 = /\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string20 = /\\AnyDesk\\ad\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string21 = /\\AnyDesk\\ad_svc\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string22 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string23 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string24 = /\\anydesk\\printer_driver/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string25 = /\\AnyDesk\\service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string26 = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string27 = /\\anydeskprintdriver\.inf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string28 = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string29 = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string30 = /\\ControlSet001\\Services\\AnyDesk/ nocase ascii wide
        // Description: anydesk added in safeboot - abused by attackers to maintain persistence and bypass detection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string31 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string32 = /\\Pictures\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string33 = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string34 = /\\ProgramFile.{0,100}\\previous\-version/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string35 = /\\SOFTWARE\\Clients\\Media\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string36 = /\\Temp\\AnyDeskUninst/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string37 = /\\Videos\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string38 = "0DBF152DEAF0B981A8A938D53F769DB8" nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string39 = "9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE" nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string40 = "9D7620A4CEBA92370E8828B3CB1007AEFF63AB36A2CBE5F044FDDE14ABAB1EBF" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string41 = "AnyDesk Software GmbH" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string42 = /Anydesk.{0,100}\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
        // Description: setting the AnyDesk service password manually
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string43 = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string44 = /boot\.net\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string45 = /C\:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string46 = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string47 = /download\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string48 = /HKCR\\\.anydesk\\/ nocase ascii wide
        // Description: command line used with anydesk in the notes of the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string49 = /programdata\\.{0,100}\s\-\-start\-with\-win\s\-\-remove\-first\s\-\-silent\s\-\-start\-service/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string50 = /relay\-.{0,100}\.net\.anydesk\.com/ nocase ascii wide
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
