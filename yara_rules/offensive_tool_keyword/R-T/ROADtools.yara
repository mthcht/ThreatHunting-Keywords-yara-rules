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
        $string1 = /\sauth\s\-\-prt\s.{0,1000}\s\-\-prt\-sessionkey\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string2 = "/ROADtools/" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string3 = /\\ROADtools\\/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string4 = "1e2136c0b4bef6f7a9de7cd1d57d2c5f3dae7f90116b50454db495970d0fe251" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string5 = /dirkjan\@outsidersecurity\.nl/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string6 = /install\s.{0,1000}\sroadrecon/
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string7 = "pip install roadlib" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string8 = "pip install roadrecon" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string9 = "pip install roadtx" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string10 = "roadrecon auth " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string11 = "roadrecon dump " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string12 = "roadrecon gather " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string13 = "roadrecon plugin " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string14 = /roadrecon.{0,1000}gather\.py/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string15 = /roadrecon\.db/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string16 = "roadrecon/frontend" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string17 = /ROADtools\.git/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string18 = /roadtools\.roadlib\.auth/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string19 = /roadtools\.roadtx\.main\:main/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string20 = "ROADtools-master" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string21 = "roadtx browserprtinject " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string22 = "roadtx device -a delete " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string23 = "roadtx getscope -s" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string24 = "roadtx gettokens -u " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string25 = "roadtx interactiveauth -c " nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string26 = "roadtx keepassauth -" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string27 = /roadtx\sprt\s\-u\s.{0,1000}\-\-key\-pem\s/ nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string28 = "roadtx prtauth -" nocase ascii wide
        // Description: A collection of Azure AD tools for offensive and defensive security purposes
        // Reference: https://github.com/dirkjanm/ROADtools
        $string29 = "roadtx refreshtokento -" nocase ascii wide

    condition:
        any of them
}
