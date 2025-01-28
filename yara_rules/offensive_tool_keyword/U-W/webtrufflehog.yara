rule webtrufflehog
{
    meta:
        description = "Detection patterns for the tool 'webtrufflehog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webtrufflehog"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string1 = /\/com\.webtrufflehog\.json/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string2 = /\/webtrufflehog\.git/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string3 = /\/webtrufflehog\.log/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string4 = /\\webtrufflehog\.log/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string5 = /\\webtrufflehog\-main/ nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string6 = "450746e51e6f1369e7e73c5e2122d0ca81153d3a4c7bcec3d66266b15ee547f7" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string7 = "52b6c057a9e0af822cbe129053d2c2d3541bf6e9ef162432fae60fdbd7a2d0f0" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string8 = "85239f4abe215e87a147a6f63e8a281c2c3a687dcc45d430042c1e897de36696" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string9 = "922d41ca55d3fa150f1c8fdc1f030e2acf6c24fcbd0ce1cd1021aeffe29bf24c" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string10 = "akoofbljmjeodfmdpjndmmnifglppjdi" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string11 = "c3l3si4n/webtrufflehog" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string12 = "d62a0e8ea863d3812dcbf3927534db6b2a82223f2bfd2c374c7263be98b855f1" nocase ascii wide
        // Description: Browser extension that leverages TruffleHog to scan web traffic in real-time for exposed secrets
        // Reference: https://github.com/c3l3si4n/webtrufflehog
        $string13 = /scan_with_trufflehog\(/ nocase ascii wide

    condition:
        any of them
}
