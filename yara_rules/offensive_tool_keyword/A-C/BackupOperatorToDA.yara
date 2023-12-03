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
        $string1 = /.{0,1000}\/BackupOperatorToDA\.git.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string2 = /.{0,1000}\\BackupOperatorToDA.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string3 = /.{0,1000}0971A047\-A45A\-43F4\-B7D8\-16AC1114B524.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string4 = /.{0,1000}BackupOperatorToDA\.cpp.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string5 = /.{0,1000}BackupOperatorToDA\.exe.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string6 = /.{0,1000}BackupOperatorToDA\.sln.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string7 = /.{0,1000}BackupOperatorToDA\-master.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string8 = /.{0,1000}mpgn\/BackupOperatorToDA.{0,1000}/ nocase ascii wide
        // Description: From an account member of the group Backup Operators to Domain Admin without RDP or WinRM on the Domain Controller
        // Reference: https://github.com/mpgn/BackupOperatorToDA
        $string9 = /.{0,1000}secredump\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
