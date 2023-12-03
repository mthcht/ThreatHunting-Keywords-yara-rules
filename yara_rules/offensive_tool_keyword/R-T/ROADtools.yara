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
        $string1 = /.{0,1000}\/ROADtools\/.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string2 = /.{0,1000}\\ROADtools\\.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string3 = /.{0,1000}install\s.{0,1000}\sroadrecon.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string4 = /.{0,1000}roadrecon\splugin\s.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string5 = /.{0,1000}roadrecon.{0,1000}gather\.py.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string6 = /.{0,1000}roadrecon\.db.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string7 = /.{0,1000}roadrecon\/frontend.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string8 = /.{0,1000}ROADtools\.git.{0,1000}/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string9 = /.{0,1000}ROADtools\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
