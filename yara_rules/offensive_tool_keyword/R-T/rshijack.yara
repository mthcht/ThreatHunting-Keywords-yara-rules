rule rshijack
{
    meta:
        description = "Detection patterns for the tool 'rshijack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rshijack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tcp connection hijacker. rust rewrite of shijack from 2001. This was written for TAMUctf 2018. brick house 100. The target was a telnet server that was protected by 2FA. Since the challenge wasn't authenticated. there have been multiple solutions for this. Our solution (cyclopropenylidene) was waiting until the authentication was done. then inject a tcp packet into the telnet connection:
        // Reference: https://github.com/kpcyrd/rshijack
        $string1 = /rshijack/ nocase ascii wide

    condition:
        any of them
}
