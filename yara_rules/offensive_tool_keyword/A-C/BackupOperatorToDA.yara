rule BackupOperatorToDA
{
    meta:
        description = "Detection patterns for the tool 'BackupOperatorToDA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackupOperatorToDA"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string1 = /\/BackupOperatorToDA\.git/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string2 = /\\BackupOperatorToDA/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string3 = /0971A047\-A45A\-43F4\-B7D8\-16AC1114B524/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string4 = /BackupOperatorToDA\.cpp/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string5 = /BackupOperatorToDA\.exe/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string6 = /BackupOperatorToDA\.sln/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string7 = /BackupOperatorToDA\-master/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string8 = /mpgn\/BackupOperatorToDA/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string9 = /secredump\.exe/ nocase ascii wide

    condition:
        any of them
}
