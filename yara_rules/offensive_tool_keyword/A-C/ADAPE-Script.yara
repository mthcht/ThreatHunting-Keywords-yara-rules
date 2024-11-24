rule ADAPE_Script
{
    meta:
        description = "Detection patterns for the tool 'ADAPE-Script' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADAPE-Script"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string1 = " \"Sniffy boi sniffin\"" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string2 = /\sADAPE\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string3 = /\$Kerberoast/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string4 = /\.ps1\s\-GPP\s\-PView\s\-Kerberoast/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string5 = /\.ps1\s\-PrivEsc/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string6 = /\/ADAPE\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string7 = /\/ADAPE\-Script\.git/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string8 = /\/Inveigh\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string9 = /\/PowerUp\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string10 = /\/PowerView\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string11 = /\/PrivEsc\.psm1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string12 = /\/PView\.psm1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string13 = /\\ADAPE\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string14 = /\\ExploitableSystem\.txt/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string15 = /\\PrivEsc\.txt/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string16 = /\\ShareFinder\.txt/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string17 = "7f99e59cb3242638aa4967180674b98dd770fae51a85ff364238faf52e02a586" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string18 = "Attemping WPAD, LLMNR, and NBTNS poisoning" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string19 = "Author: @haus3c" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string20 = "Collecting Privesc methods" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string21 = "function PrivEsc" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string22 = "Get-ExploitableSystem -Verbose" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string23 = /Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string24 = "hausec/ADAPE-Script" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string25 = /Import\-Module\s.{0,1000}\/PView\.psm1/ nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string26 = "Invoke-Kerberoast" nocase ascii wide
        // Description: Active Directory Assessment and Privilege Escalation Script
        // Reference: https://github.com/cjoan75/ADAPE-Script
        $string27 = "Invoke-ShareFinder -CheckShareAccess" nocase ascii wide

    condition:
        any of them
}
