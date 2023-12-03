rule lyncsmash
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string1 = /.{0,1000}\.py\sdiscover\s\-H\sdomain_list\.txt.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string2 = /.{0,1000}\.py\senum\s\-H\s.{0,1000}\s\-U\s.{0,1000}\.txt\s\-P\s.{0,1000}\.txt\s\-.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string3 = /.{0,1000}\.py\slock\s\-H\s.{0,1000}\s\-u\sadministrator\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string4 = /.{0,1000}\/find_domain\.sh.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string5 = /.{0,1000}\/lyncsmash\/.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string6 = /.{0,1000}\/wordlists\/owa_directories\.txt.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string7 = /.{0,1000}\/wordlists\/skype\-directories\.txt.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string8 = /.{0,1000}1_FindDomain\.sh.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string9 = /.{0,1000}2_lyncbrute\.sh.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string10 = /.{0,1000}alexa\-top\-20000\-sites\.txt.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string11 = /.{0,1000}brute_force_ntlm\.sh.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string12 = /.{0,1000}find_domain\.sh\s.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string13 = /.{0,1000}lyncsmash.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string14 = /.{0,1000}lyncsmash\.git.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string15 = /.{0,1000}lyncsmash\.log.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string16 = /.{0,1000}lyncsmash\.py.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string17 = /.{0,1000}lyncsmash\-master.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string18 = /.{0,1000}ntlm\-info\.py.{0,1000}/ nocase ascii wide
        // Description: a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string19 = /.{0,1000}nyxgeek\/lyncsmash.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
