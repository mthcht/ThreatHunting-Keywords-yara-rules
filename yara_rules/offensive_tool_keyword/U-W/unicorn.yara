rule unicorn
{
    meta:
        description = "Detection patterns for the tool 'unicorn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unicorn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string1 = /\sunicorn\.py/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string2 = /\.py\s.{0,1000}\.cs\scs\sms/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string3 = /\.txt\sshellcode\shta/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string4 = /\.txt\sshellcode\smacro/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string5 = /\.txt\sshellcode\sms/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string6 = /\/unicorn\.git/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string7 = /\/unicorn\.py/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string8 = /ASBBypass\.ps1/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string9 = /trustedsec\/unicorn/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string10 = /unicorn\.py\s/ nocase ascii wide
        // Description: Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory
        // Reference: https://github.com/trustedsec/unicorn
        $string11 = /unicorn\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
