rule BabelStrike
{
    meta:
        description = "Detection patterns for the tool 'BabelStrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabelStrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string1 = /\sBabelStrike\.py/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string2 = /\/BabelStrike\.git/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string3 = /\/BabelStrike\.py/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string4 = /\\BabelStrike\.py/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string5 = /babelstrike\.py\s\-/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string6 = /BabelStrike\-main/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string7 = /t3l3machus\/BabelStrike/ nocase ascii wide

    condition:
        any of them
}
