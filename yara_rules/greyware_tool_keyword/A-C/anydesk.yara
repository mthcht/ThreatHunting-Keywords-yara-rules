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
        // Reference: https://anydesk.com/
        $string1 = /\\adprinterpipe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string2 = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string3 = /\\AnyDesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string4 = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string5 = /\\anydesk\\printer_driver/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string6 = /\\AnyDesk\\service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string7 = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string8 = /\\anydeskprintdriver\.inf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string9 = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string10 = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string11 = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate (rumor) - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string12 = /0DBF152DEAF0B981A8A938D53F769DB8/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate (rumor) - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string13 = /9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE/ nocase ascii wide
        // Description: Anydesk RMM usage - compromised certificate (rumor) - https://anydesk.com/en/changelog/windows
        // Reference: https://anydesk.com/
        $string14 = /9D7620A4CEBA92370E8828B3CB1007AEFF63AB36A2CBE5F044FDDE14ABAB1EBF/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string15 = /AnyDesk\sSoftware\sGmbH/ nocase ascii wide
        // Description: setting the AnyDesk service password manually
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string16 = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string17 = /boot\.net\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string18 = /C:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string19 = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string20 = /HKCR\\\.anydesk\\/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string21 = /relay\-.{0,1000}\.net\.anydesk\.com/ nocase ascii wide

    condition:
        any of them
}
