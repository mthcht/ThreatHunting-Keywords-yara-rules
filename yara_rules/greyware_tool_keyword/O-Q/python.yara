rule python
{
    meta:
        description = "Detection patterns for the tool 'python' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "python"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious way of exeuting code
        // Reference: https://x.com/Ax_Sharma/status/1795813203500322953/photo/4
        $string1 = /\s\,exec\(__import__\(\'base64\'\)\.b64decode\(\"/ nocase ascii wide
        // Description: interactive shell
        // Reference: N/A
        $string2 = /\s\-c\s\'import\spty\;pty\.spawn\(\"\/bin\/bash/ nocase ascii wide
        // Description: interactive shell
        // Reference: N/A
        $string3 = /\s\-c\s\'import\spty\;pty\.spawn\(\"\/bin\/sh/ nocase ascii wide
        // Description: interactive shell
        // Reference: N/A
        $string4 = /\s\-c\s\'import\spty\;pty\.spawn\(\\\"\/bin\/sh/ nocase ascii wide

    condition:
        any of them
}
