rule AMSI_Provider
{
    meta:
        description = "Detection patterns for the tool 'AMSI-Provider' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSI-Provider"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string1 = /\/AMSI\-Provider\.git/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string2 = /\\AmsiProvider\.cpp/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string3 = /\\AmsiProvider\.sln/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string4 = /\\AMSI\-Provider\-main/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string5 = /58B32FCA\-F385\-4500\-9A8E\-7CBA1FC9BA13/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string6 = /7a9a81c7ef99897281466ea06c14886335cf8d4c835f15aeb1e3a2c7c1d0e760/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string7 = /90bf7beb921839957e7977851f01e757346d2b4f672e6a08b04e57878cd6efbf/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string8 = /b4a7045568cb78f48f42b93f528e14ef24f8dc3bf878af0b94ca22c5df546da5/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string9 = /netbiosX\/AMSI\-Provider/ nocase ascii wide

    condition:
        any of them
}
