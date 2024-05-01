rule KExecDD
{
    meta:
        description = "Detection patterns for the tool 'KExecDD' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KExecDD"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Admin to Kernel code execution using the KSecDD driver
        // Reference: https://github.com/floesen/KExecDD
        $string1 = /\/KExecDD\.git/ nocase ascii wide
        // Description: Admin to Kernel code execution using the KSecDD driver
        // Reference: https://github.com/floesen/KExecDD
        $string2 = /\\KExecDD\-main/ nocase ascii wide
        // Description: Admin to Kernel code execution using the KSecDD driver
        // Reference: https://github.com/floesen/KExecDD
        $string3 = /0ba663873a7926866e3dd717b970f7e651700d00e9d99f667dfd473eafa81b8a/ nocase ascii wide
        // Description: Admin to Kernel code execution using the KSecDD driver
        // Reference: https://github.com/floesen/KExecDD
        $string4 = /26085f4768e13063e5dde27f0e313854ce91aa032a7b26d4f57ebc03a6628560/ nocase ascii wide
        // Description: Admin to Kernel code execution using the KSecDD driver
        // Reference: https://github.com/floesen/KExecDD
        $string5 = /floesen\/KExecDD/ nocase ascii wide

    condition:
        any of them
}
