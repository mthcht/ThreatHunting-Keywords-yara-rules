rule schtasks
{
    meta:
        description = "Detection patterns for the tool 'schtasks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "schtasks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string1 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\ExploitGuard\\ExploitGuard\sMDM\spolicy\sRefresh\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string2 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sCache\sMaintenance\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string3 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sCleanup\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string4 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sScheduled\sScan\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string5 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sVerification\\"\s\/Disable/ nocase ascii wide
        // Description: view detailed information about all the scheduled tasks.
        // Reference: N/A
        $string6 = "schtasks /query /v /fo LIST" nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string7 = /schtasks\.exe\s\/create\s\/sc\s.{0,1000}\s\/tr\s\\"\%programdata\%\\sshd\\sshd\.exe\s\-f\s\%programdata\%\\sshd\\config\\sshd_config\\keys\\id_rsa\s\-N\s\-R\s.{0,1000}\s\-o\sStrictHostKeyChecking\=no\s\-o\s/ nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string8 = /schtasks\.exe\s\/create\s\/sc\sminute\s\/mo\s1\s\/tn\s.{0,1000}\s\/rl\shighest\s\/np\s\/tr\s.{0,1000}\\sshd\\sshd\.exe\s\-f\s.{0,1000}\\sshd\\config\\sshd_config/ nocase ascii wide

    condition:
        any of them
}
