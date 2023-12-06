rule WhatBreach
{
    meta:
        description = "Detection patterns for the tool 'WhatBreach' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WhatBreach"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WhatBreach is an OSINT tool that simplifies the task of discovering what breaches an email address has been discovered in. WhatBreach provides a simple and effective way to search either multiple. or a single email address and discover all known breaches that this email has been seen in. From there WhatBreach is capable of downloading the database if it is publicly available. downloading the pastes the email was seen in. or searching the domain of the email for further investigation. To perform this task successfully WhatBreach takes advantage of the following websites and/or APIs:
        // Reference: https://github.com/Ekultek/WhatBreach
        $string1 = /WhatBreach/ nocase ascii wide

    condition:
        any of them
}
