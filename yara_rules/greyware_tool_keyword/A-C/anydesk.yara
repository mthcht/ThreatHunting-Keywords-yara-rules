rule anydesk
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string1 = /\/\.anydesk\/\.anydesk\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string2 = /\/\.anydesk\/service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string3 = /\/\.anydesk\/system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string4 = /\/\.anydesk\/user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string5 = /\/Anydesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string6 = /\/Applications\/Anydesk\.app\// nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string7 = /\/etc\/systemd\/system\/anydesk\.service/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string8 = /\/home\/.{0,1000}\/\.anydesk\// nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string9 = /\/log\/anydesk\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string10 = /\/usr\/bin\/anydesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string11 = /\/usr\/lib64\/anydesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string12 = /\/usr\/libexec\/anydesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string13 = /\\adprinterpipe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string14 = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string15 = /\\AnyDesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string16 = /\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string17 = /\\AnyDesk\\ad\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string18 = /\\AnyDesk\\ad_svc\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string19 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string20 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string21 = /\\anydesk\\printer_driver/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string22 = /\\AnyDesk\\service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string23 = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string24 = /\\anydeskprintdriver\.inf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string25 = /\\anydeskprintdriver\.inf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string26 = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string27 = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string28 = /\\ControlSet001\\Services\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string29 = /\\Pictures\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string30 = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string31 = /\\ProgramFile.{0,1000}\\previous\-version/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string32 = /\\SOFTWARE\\Clients\\Media\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string33 = /\\Temp\\AnyDeskUninst/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string34 = /\\Videos\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string35 = /0DBF152DEAF0B981A8A938D53F769DB8/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string36 = /9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string37 = /9D7620A4CEBA92370E8828B3CB1007AEFF63AB36A2CBE5F044FDDE14ABAB1EBF/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string38 = /AnyDesk\sSoftware\sGmbH/ nocase ascii wide
        // Description: setting the AnyDesk service password manually
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string39 = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string40 = /boot\.net\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string41 = /C\:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string42 = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string43 = /HKCR\\\.anydesk\\/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string44 = /relay\-.{0,1000}\.net\.anydesk\.com/ nocase ascii wide

    condition:
        any of them
}
