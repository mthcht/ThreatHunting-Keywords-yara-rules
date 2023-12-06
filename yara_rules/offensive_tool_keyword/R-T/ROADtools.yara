rule ROADtools
{
    meta:
        description = "Detection patterns for the tool 'ROADtools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ROADtools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string1 = /\/ROADtools\// nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string2 = /\\ROADtools\\/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string3 = /install\s.{0,1000}\sroadrecon/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string4 = /roadrecon\splugin\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string5 = /roadrecon.{0,1000}gather\.py/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string6 = /roadrecon\.db/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string7 = /roadrecon\/frontend/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string8 = /ROADtools\.git/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string9 = /ROADtools\-master/ nocase ascii wide

    condition:
        any of them
}
