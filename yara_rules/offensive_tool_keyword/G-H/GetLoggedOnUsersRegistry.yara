rule GetLoggedOnUsersRegistry
{
    meta:
        description = "Detection patterns for the tool 'GetLoggedOnUsersRegistry' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GetLoggedOnUsersRegistry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC To enumerate logged on users on a remote system using the winreg named pipe
        // Reference: https://gist.github.com/RalphDesmangles/22f580655f479f189c1de9e7720776f1
        $string1 = /\]\sAttempting\sto\senumerate\slogged\son\susers\son\s/ nocase ascii wide
        // Description: PoC To enumerate logged on users on a remote system using the winreg named pipe
        // Reference: https://gist.github.com/RalphDesmangles/22f580655f479f189c1de9e7720776f1
        $string2 = /GetLoggedOnUsersRegistry\.cs/ nocase ascii wide
        // Description: PoC To enumerate logged on users on a remote system using the winreg named pipe
        // Reference: https://gist.github.com/RalphDesmangles/22f580655f479f189c1de9e7720776f1
        $string3 = /PoC\sTo\senumerate\slogged\son\susers\son\sa\sremote\ssystem\susing\sthe\swinreg\snamed\spipe/ nocase ascii wide
        // Description: PoC To enumerate logged on users on a remote system using the winreg named pipe
        // Reference: https://gist.github.com/RalphDesmangles/22f580655f479f189c1de9e7720776f1
        $string4 = /RalphDesmangles\/22f580655f479f189c1de9e7720776f1/ nocase ascii wide

    condition:
        any of them
}
