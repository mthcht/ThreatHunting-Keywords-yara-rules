rule getsploit
{
    meta:
        description = "Detection patterns for the tool 'getsploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "getsploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line search and download tool for Vulners Database inspired by searchsploit. It allows you to search online for the exploits across all the most popular collections: Exploit-DB. Metasploit. Packetstorm and others. The most powerful feature is immediate exploit source download right in your working path.
        // Reference: https://github.com/vulnersCom/getsploit
        $string1 = /getsploit/ nocase ascii wide

    condition:
        any of them
}
