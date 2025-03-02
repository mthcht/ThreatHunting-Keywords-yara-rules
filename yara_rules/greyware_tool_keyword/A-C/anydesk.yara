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
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string4 = /\$outputPath\s\=\s\\"C\:\\AnyDesk\.exe\\"/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string5 = /\/\.anydesk\/\.anydesk\.trace/
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string6 = /\/\.anydesk\/service\.conf/
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string7 = /\/\.anydesk\/system\.conf/
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string8 = /\/\.anydesk\/user\.conf/
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string9 = /\/Anydesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string10 = /\/Applications\/Anydesk\.app\// nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string11 = /\/etc\/systemd\/system\/anydesk\.service/
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string12 = /\/home\/.{0,1000}\/\.anydesk\//
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string13 = /\/log\/anydesk\.trace/
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string14 = "/usr/bin/anydesk"
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string15 = "/usr/lib64/anydesk"
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string16 = "/usr/libexec/anydesk"
        // Description: Anydesk RMM usage
        // Reference: https://www.inversecos.com/2021/02/forensic-analysis-of-anydesk-logs.html
        $string17 = /\\ad_svc\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string18 = /\\adprinterpipe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string19 = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string20 = /\\AnyDesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string21 = /\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string22 = /\\AnyDesk\\ad\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string23 = /\\AnyDesk\\ad_svc\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string24 = /\\AnyDesk\\AnyDesk_Output\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string25 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string26 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string27 = /\\anydesk\\printer_driver/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string28 = /\\AnyDesk\\service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string29 = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string30 = /\\anydeskprintdriver\.inf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string31 = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string32 = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string33 = /\\ControlSet001\\Services\\AnyDesk/ nocase ascii wide
        // Description: anydesk added in safeboot - abused by attackers to maintain persistence and bypass detection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string34 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://upadhyayraj.medium.com/beyond-connection-logs-understanding-file-transfer-artifacts-in-anydesk-forensics-b5812c817aad
        $string35 = /\\file_transfer_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string36 = /\\Pictures\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string37 = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string38 = /\\ProgramFile.{0,1000}\\previous\-version/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-003/
        $string39 = /\\SOFTWARE\\Clients\\Media\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string40 = /\\Temp\\AnyDeskUninst/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string41 = /\\Videos\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string42 = "0DBF152DEAF0B981A8A938D53F769DB8" nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string43 = "9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE" nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string44 = "9D7620A4CEBA92370E8828B3CB1007AEFF63AB36A2CBE5F044FDDE14ABAB1EBF" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string45 = "Ab4y98/VerySimpleAnyDeskBackdoor" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string46 = /AnyDesk\sID\sis\:\s\$ID\sAND\sPassword\sis\:\sAa123456\!/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string47 = "AnyDesk Software GmbH" nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string48 = /Anydesk.{0,1000}\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string49 = /AnyDesk\.exe\s\-\-install\s\\"C\:\\Program\sFiles\s\(x86\)\\AnyDesk\\"\s\-\-start\-with\-win\s\-\-silent/ nocase ascii wide
        // Description: setting the AnyDesk service password manually
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string50 = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://www.inversecos.com/2021/02/forensic-analysis-of-anydesk-logs.html
        $string51 = /Anydesk\\ad\.trace/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string52 = /AnydeskBackdoor\.ps1/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string53 = /boot\.net\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string54 = /C\:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://github.com/Ab4y98/VerySimpleAnyDeskBackdoor/blob/main/AnydeskBackdoor.ps1
        $string55 = /cmd\s\/c\s\'echo\sAa123456\!\s.{0,1000}\s\-\-set\-password/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string56 = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string57 = /download\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string58 = /HKCR\\\.anydesk\\/ nocase ascii wide
        // Description: command line used with anydesk in the notes of the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string59 = /programdata\\.{0,1000}\s\-\-start\-with\-win\s\-\-remove\-first\s\-\-silent\s\-\-start\-service/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string60 = /relay\-.{0,1000}\.net\.anydesk\.com/ nocase ascii wide

    condition:
        any of them
}
