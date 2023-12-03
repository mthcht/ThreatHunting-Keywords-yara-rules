rule ACLight
{
    meta:
        description = "Detection patterns for the tool 'ACLight' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACLight"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string1 = /.{0,1000}\s\-\sSensitive\sAccounts\.csv.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string2 = /.{0,1000}\/ACLight\.git.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string3 = /.{0,1000}\/ACLight\/.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string4 = /.{0,1000}\\scanACLsResults\.csv.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string5 = /.{0,1000}Accounts\swith\sextra\spermissions\.txt.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string6 = /.{0,1000}ACLight\.ps1.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string7 = /.{0,1000}ACLight\.psd1.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string8 = /.{0,1000}ACLight\.psm1.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string9 = /.{0,1000}ACLight2\.ps1.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string10 = /.{0,1000}ACLight2\.psd1.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string11 = /.{0,1000}ACLight2\.psm1.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string12 = /.{0,1000}ACLight\-master.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string13 = /.{0,1000}cyberark\/ACLight.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string14 = /.{0,1000}Execute\-ACLight\.bat.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string15 = /.{0,1000}Execute\-ACLight2\.bat.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string16 = /.{0,1000}Invoke\-ACLcsvFileAnalysis.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string17 = /.{0,1000}Invoke\-ACLScanner\s.{0,1000}\s\-Filter\s.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string18 = /.{0,1000}Invoke\-ACLScanner\s.{0,1000}\s\-Name\s.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string19 = /.{0,1000}Privileged\sAccounts\s\-\sLayers\sAnalysis\.txt.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string20 = /.{0,1000}Privileged\sAccounts\sPermissions\s\-\sFinal\sReport\.csv.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string21 = /.{0,1000}Privileged\sAccounts\sPermissions\s\-\sIrregular\sAccounts\.csv.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string22 = /.{0,1000}Start\-ACLsAnalysis\s\-Domain.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string23 = /.{0,1000}Start\-domainACLsAnalysis.{0,1000}/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string24 = /.{0,1000}starting\sMulti\-Layered\sACLight\sscan.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
