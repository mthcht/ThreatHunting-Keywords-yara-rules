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
        $string1 = /\s\-\sSensitive\sAccounts\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string2 = /\/ACLight\.git/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string3 = /\/ACLight\// nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string4 = /\\scanACLsResults\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string5 = /Accounts\swith\sextra\spermissions\.txt/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string6 = /ACLight\.ps1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string7 = /ACLight\.psd1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string8 = /ACLight\.psm1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string9 = /ACLight2\.ps1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string10 = /ACLight2\.psd1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string11 = /ACLight2\.psm1/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string12 = /ACLight\-master/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string13 = /cyberark\/ACLight/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string14 = /Execute\-ACLight\.bat/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string15 = /Execute\-ACLight2\.bat/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string16 = /Invoke\-ACLcsvFileAnalysis/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string17 = /Invoke\-ACLScanner\s.{0,1000}\s\-Filter\s/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string18 = /Invoke\-ACLScanner\s.{0,1000}\s\-Name\s/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string19 = /Privileged\sAccounts\s\-\sLayers\sAnalysis\.txt/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string20 = /Privileged\sAccounts\sPermissions\s\-\sFinal\sReport\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string21 = /Privileged\sAccounts\sPermissions\s\-\sIrregular\sAccounts\.csv/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string22 = /Start\-ACLsAnalysis\s\-Domain/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string23 = /Start\-domainACLsAnalysis/ nocase ascii wide
        // Description: A tool for advanced discovery of Privileged Accounts - including Shadow Admins.
        // Reference: https://github.com/cyberark/ACLight
        $string24 = /starting\sMulti\-Layered\sACLight\sscan/ nocase ascii wide

    condition:
        any of them
}
