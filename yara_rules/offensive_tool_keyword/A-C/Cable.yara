rule Cable
{
    meta:
        description = "Detection patterns for the tool 'Cable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cable"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string1 = /\.NET\spost\-exploitation\stoolkit\sfor\sActive\sDirectory\sreconnaissance\sand\sexploitation\s/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string2 = /\[\-\]\sNo\sKerberoastable\saccounts\sfound/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string3 = /\[\+\]\sFinding\sKerberoastable\saccounts/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string4 = /\[\+\]\sSID\sadded\sto\smsDS\-AllowedToActOnBehalfOfOtherIdentity/ nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string5 = "06B2AE2B-7FD3-4C36-B825-1594752B1D7B" nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string6 = "16717cf09d49d252b21c5768092a557ea5a7899d781656da909a7766b6c55074" nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string7 = "fff1c91cf41743e46dc2b43b256680ce9015d0a705b31cf19c2cfb48f48c616f" nocase ascii wide
        // Description: *.NET post-exploitation toolkit for Active Directory reconnaissance and exploitation*
        // Reference: https://github.com/logangoins/Cable
        $string8 = "logangoins/Cable" nocase ascii wide

    condition:
        any of them
}
