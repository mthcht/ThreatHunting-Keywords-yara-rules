rule Tool_X
{
    meta:
        description = "Detection patterns for the tool 'Tool-X' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tool-X"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool-X is a Kali Linux hacking tools installer for Termux and linux system. Tool-X was developed for Termux and linux based systems. Using Tool-X you can install almost 370+ hacking tools in Termux (android) and other Linux based distributions. Now Tool-X is available for Ubuntu Debian etc.
        // Reference: https://github.com/rajkumardusad/Tool-X
        $string1 = /\/Tool\-X\.git/ nocase ascii wide
        // Description: Tool-X is a Kali Linux hacking tools installer for Termux and linux system. Tool-X was developed for Termux and linux based systems. Using Tool-X you can install almost 370+ hacking tools in Termux (android) and other Linux based distributions. Now Tool-X is available for Ubuntu Debian etc.
        // Reference: https://github.com/rajkumardusad/Tool-X
        $string2 = /rajkumardusad\/Tool\-X/ nocase ascii wide

    condition:
        any of them
}
