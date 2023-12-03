rule tplmap
{
    meta:
        description = "Detection patterns for the tool 'tplmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tplmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tplmap assists the exploitation of Code Injection and Server-Side Template Injection vulnerabilities with a number of sandbox escape techniques to get access to the underlying operating system. The sandbox break-out techniques came from James Ketts Server-Side Template Injection: RCE For The Modern Web App. other public researches [1] [2]. and original contributions to this tool  It can exploit several code context and blind injection scenarios. It also supports eval()-like code injections in Python. Ruby. PHP. Java and generic unsandboxed template engines.
        // Reference: https://github.com/epinna/tplmap
        $string1 = /.{0,1000}tplmap.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
