rule AD_common_queries
{
    meta:
        description = "Detection patterns for the tool 'AD-common-queries' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD-common-queries"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Collection of common ADSI queries for Domain Account enumeration
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string1 = /\/AD\-common\-queries\.git/ nocase ascii wide
        // Description: Collection of common ADSI queries for Domain Account enumeration
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string2 = /ADUsers\-Disabled\.txt/ nocase ascii wide
        // Description: Collection of common ADSI queries for Domain Account enumeration
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string3 = /ADUsers\-PasswordNeverExpires\.txt/ nocase ascii wide
        // Description: Collection of common ADSI queries for Domain Account enumeration
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string4 = /ADUsers\-PasswordNotRequired\.txt/ nocase ascii wide
        // Description: Collection of common ADSI queries for Domain Account enumeration
        // Reference: https://github.com/swarleysez/AD-common-queries
        $string5 = /swarleysez\/AD\-common\-queries/ nocase ascii wide

    condition:
        any of them
}
