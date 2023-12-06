rule metagoofil
{
    meta:
        description = "Detection patterns for the tool 'metagoofil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "metagoofil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Metagoofil is a tool for extracting metadata of public documents (pdf.doc.xls.ppt..etc) availables in the target websites.This information could be useful because you can get valid usernames. people names. for using later in bruteforce password attacks (vpn. ftp. webapps). the tool will also extracts interesting paths of the documents. where we can get shared resources names. server names... etc.
        // Reference: https://github.com/laramies/metagoofi
        $string1 = /metagoofil/ nocase ascii wide

    condition:
        any of them
}
