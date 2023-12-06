rule tasklist
{
    meta:
        description = "Detection patterns for the tool 'tasklist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tasklist"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /tasklist\s\/svc\s\|\sfindstr\s\/i\s\"vmtoolsd\.exe\"/ nocase ascii wide

    condition:
        any of them
}
