rule awesome_web_security
{
    meta:
        description = "Detection patterns for the tool 'awesome-web-security' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-web-security"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Curated list of Web Security materials and resources.Needless to say. most websites suffer from various types of bugs which may eventually lead to vulnerabilities. Why would this happen so often? There can be many factors involved including misconfiguration. shortage of engineers' security skills. etc. To combat this. here is a curated list of Web Security materials and resources for learning cutting edge penetration techniques. and I highly encourage you to read this article So you want to be a web security researcher? first
        // Reference: https://github.com/qazbnm456/awesome-web-security
        $string1 = /awesome\-web\-security/ nocase ascii wide

    condition:
        any of them
}
