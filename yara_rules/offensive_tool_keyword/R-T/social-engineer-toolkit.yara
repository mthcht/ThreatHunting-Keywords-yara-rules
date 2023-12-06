rule social_engineer_toolkit
{
    meta:
        description = "Detection patterns for the tool 'social-engineer-toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "social-engineer-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec
        // Reference: https://github.com/trustedsec/social-engineer-toolkit
        $string1 = /\ssetoolkit/ nocase ascii wide
        // Description: The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec
        // Reference: https://github.com/trustedsec/social-engineer-toolkit
        $string2 = /apt\sinstall\sset\s\-y/ nocase ascii wide
        // Description: The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec
        // Reference: https://github.com/trustedsec/social-engineer-toolkit
        $string3 = /bin\/setoolkit/ nocase ascii wide
        // Description: The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec
        // Reference: https://github.com/trustedsec/social-engineer-toolkit
        $string4 = /setoolkit\s/ nocase ascii wide
        // Description: The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec. LLC  an information security consulting firm located in Cleveland. Ohio.
        // Reference: https://github.com/trustedsec/social-engineer-toolkit
        $string5 = /Social\sEngineer\sToolkit/ nocase ascii wide
        // Description: The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. SET has a number of custom attack vectors that allow you to make a believable attack quickly. SET is a product of TrustedSec
        // Reference: https://github.com/trustedsec/social-engineer-toolkit
        $string6 = /trustedsec\/social\-engineer\-toolkit/ nocase ascii wide

    condition:
        any of them
}
