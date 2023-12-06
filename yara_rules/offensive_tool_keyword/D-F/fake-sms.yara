rule fake_sms
{
    meta:
        description = "Detection patterns for the tool 'fake-sms' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fake-sms"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple command line tool using which you can skip phone number based SMS verification by using a temporary phone number that acts like a proxy.
        // Reference: https://github.com/Narasimha1997/fake-sms
        $string1 = /\.\/fake\-sms/ nocase ascii wide
        // Description: A simple command line tool using which you can skip phone number based SMS verification by using a temporary phone number that acts like a proxy.
        // Reference: https://github.com/Narasimha1997/fake-sms
        $string2 = /\/bin\/fake\-sms/ nocase ascii wide
        // Description: A simple command line tool using which you can skip phone number based SMS verification by using a temporary phone number that acts like a proxy.
        // Reference: https://github.com/Narasimha1997/fake-sms
        $string3 = /\/fake\-sms\.git/ nocase ascii wide
        // Description: A simple command line tool using which you can skip phone number based SMS verification by using a temporary phone number that acts like a proxy.
        // Reference: https://github.com/Narasimha1997/fake-sms
        $string4 = /fake\-sms\-main/ nocase ascii wide
        // Description: A simple command line tool using which you can skip phone number based SMS verification by using a temporary phone number that acts like a proxy.
        // Reference: https://github.com/Narasimha1997/fake-sms
        $string5 = /Narasimha1997\/fake\-sms/ nocase ascii wide

    condition:
        any of them
}
