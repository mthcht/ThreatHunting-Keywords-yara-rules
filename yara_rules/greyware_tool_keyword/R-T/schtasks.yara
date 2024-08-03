rule schtasks
{
    meta:
        description = "Detection patterns for the tool 'schtasks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "schtasks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: view detailed information about all the scheduled tasks.
        // Reference: N/A
        $string1 = /schtasks\s\/query\s\/v\s\/fo\sLIST/ nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string2 = /schtasks\.exe\s\/create\s\/sc\s.{0,1000}\s\/tr\s\"\%programdata\%\\sshd\\sshd\.exe\s\-f\s\%programdata\%\\sshd\\config\\sshd_config\\keys\\id_rsa\s\-N\s\-R\s.{0,1000}\s\-o\sStrictHostKeyChecking\=no\s\-o\s/ nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string3 = /schtasks\.exe\s\/create\s\/sc\sminute\s\/mo\s1\s\/tn\s.{0,1000}\s\/rl\shighest\s\/np\s\/tr\s.{0,1000}\\sshd\\sshd\.exe\s\-f\s.{0,1000}\\sshd\\config\\sshd_config/ nocase ascii wide

    condition:
        any of them
}
