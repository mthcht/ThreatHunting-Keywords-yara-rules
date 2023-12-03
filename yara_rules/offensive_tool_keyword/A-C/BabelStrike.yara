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
        $string1 = /.{0,1000}\sBabelStrike\.py.{0,1000}/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string2 = /.{0,1000}\/BabelStrike\.git.{0,1000}/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string3 = /.{0,1000}\/BabelStrike\.py.{0,1000}/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string4 = /.{0,1000}\\BabelStrike\.py.{0,1000}/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string5 = /.{0,1000}babelstrike\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string6 = /.{0,1000}BabelStrike\-main.{0,1000}/ nocase ascii wide
        // Description: The purpose of this tool is to normalize and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages. common problem occurring from scraped employee names lists (e.g. from Linkedin)
        // Reference: https://github.com/t3l3machus/BabelStrike
        $string7 = /.{0,1000}t3l3machus\/BabelStrike.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
