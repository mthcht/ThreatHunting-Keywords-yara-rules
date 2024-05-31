rule temp_mail
{
    meta:
        description = "Detection patterns for the tool 'temp-mail' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "temp-mail"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: using the API of a disposable email address to use anytime - could be abused by malicious actors
        // Reference: temp-mail.org
        $string1 = /https\:\/\/privatix\-temp\-mail\-v1\.p\.rapidapi\.com\/request\/domains\// nocase ascii wide
        // Description: using the API of a disposable email address to use anytime - could be abused by malicious actors
        // Reference: temp-mail.org
        $string2 = /https\:\/\/privatix\-temp\-mail\-v1\.p\.rapidapi\.com\/request\/mail\/id\/null\// nocase ascii wide

    condition:
        any of them
}
