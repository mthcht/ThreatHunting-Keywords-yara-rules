rule autonse
{
    meta:
        description = "Detection patterns for the tool 'autonse' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autonse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Massive NSE (Nmap Scripting Engine) AutoSploit and AutoScanner. The Nmap Scripting Engine (NSE) is one of Nmaps most powerful and flexible features. It allows users to write (and share) simple scripts (using the Lua programming language ) to automate a wide variety of networking tasks. Those scripts are executed in parallel with the speed and efficiency you expect from Nmap. Users can rely on the growing and diverse set of scripts distributed with Nmap. or write their own to meet custom needs. For more informations https://nmap.org/book/man-nse.html
        // Reference: https://github.com/m4ll0k/AutoNSE
        $string1 = /AutoNSE/ nocase ascii wide

    condition:
        any of them
}
