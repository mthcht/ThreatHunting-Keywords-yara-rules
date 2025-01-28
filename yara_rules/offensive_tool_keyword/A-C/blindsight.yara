rule blindsight
{
    meta:
        description = "Detection patterns for the tool 'blindsight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blindsight"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string1 = " - Dump LSASS memory bypassing countermeasures" nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string2 = /\s29ABE9Hy\.log/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string3 = /\/blindsight\.exe/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string4 = /\/blindsight\.git/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string5 = /\[\+\]\sFound\s\{LSASS\}\spid\:\s\{pid\}/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string6 = /\[\+\]\sSuccessfully\sopened\s\{LSASS\}\shandle/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string7 = /\\blindsight\.exe/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string8 = /\\lsass\.dmp/ nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string9 = "0xdea/blindsight" nocase ascii wide
        // Description: Red teaming tool to dump LSASS memory, bypassing basic countermeasures
        // Reference: https://github.com/0xdea/blindsight
        $string10 = "461356f9bd764b57b3b9a1457aa60494ae73a7935133f5b6122edcb286b7ef0a" nocase ascii wide

    condition:
        any of them
}
