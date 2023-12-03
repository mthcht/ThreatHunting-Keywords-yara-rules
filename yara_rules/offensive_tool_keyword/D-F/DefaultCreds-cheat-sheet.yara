rule DefaultCreds_cheat_sheet
{
    meta:
        description = "Detection patterns for the tool 'DefaultCreds-cheat-sheet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DefaultCreds-cheat-sheet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password
        // Reference: https://github.com/ihebski/DefaultCreds-cheat-sheet
        $string1 = /.{0,1000}\/creds\-.{0,1000}\/creds\.zip.{0,1000}/ nocase ascii wide
        // Description: One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password
        // Reference: https://github.com/ihebski/DefaultCreds-cheat-sheet
        $string2 = /.{0,1000}\/DefaultCreds_db\.json.{0,1000}/ nocase ascii wide
        // Description: One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password
        // Reference: https://github.com/ihebski/DefaultCreds-cheat-sheet
        $string3 = /.{0,1000}\/tmp\/.{0,1000}\-passwords\.txt.{0,1000}/ nocase ascii wide
        // Description: One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password
        // Reference: https://github.com/ihebski/DefaultCreds-cheat-sheet
        $string4 = /.{0,1000}\/tmp\/.{0,1000}\-usernames\.txt.{0,1000}/ nocase ascii wide
        // Description: One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password
        // Reference: https://github.com/ihebski/DefaultCreds-cheat-sheet
        $string5 = /.{0,1000}DefaultCreds\-cheat\-sheet.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
