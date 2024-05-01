rule python
{
    meta:
        description = "Detection patterns for the tool 'python' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "python"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: interactive shell
        // Reference: N/A
        $string1 = /\s\-c\s\'import\spty\;pty\.spawn\(\"\/bin\/bash/ nocase ascii wide
        // Description: interactive shell
        // Reference: N/A
        $string2 = /\s\-c\s\'import\spty\;pty\.spawn\(\"\/bin\/sh/ nocase ascii wide
        // Description: interactive shell
        // Reference: N/A
        $string3 = /\s\-c\s\'import\spty\;pty\.spawn\(\\\"\/bin\/sh/ nocase ascii wide

    condition:
        any of them
}
