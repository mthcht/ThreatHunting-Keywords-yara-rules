rule subbrute
{
    meta:
        description = "Detection patterns for the tool 'subbrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "subbrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string1 = /\ssubbrute\.py/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string2 = /\ssubbrute\.run\(/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string3 = /\/subbrute\.git/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string4 = /\/subbrute\.py/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string5 = "/subbrute/releases/download/" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string6 = /\\subbrute\.py/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string7 = "0901aac4feb3ef12677e64599acc30daf72ab2e3227ab46db8b06a6e8a5c2070" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string8 = "0e0ea3fcb913470c6f7814cc1d943d51f687578f2d59a1a15101587cb0ff709d" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string9 = "340ced72dda48a480d8a7d3f4e4d55af5de3f32bd61806362c04b7081bb11607" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string10 = "34aa130f8c55629bb00cad0d4834c274b5408cabd49579ee3d75d2cf5054ba9e" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string11 = "4ab4e04a014333fd820edebcd24b0fa920390d312f951bcf3cc1a7733baecdb8" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string12 = "58c2cf7ff89c1fc1871e507f0c1a467dcf37b45d094d73c61b0ded0f935eec98" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string13 = "7d90e68af91d2670512ca9db8d6c6d1055007918ca637b9ae54f39f0380ad2e3" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string14 = "7ee2ae92197926fc349bebbf9c6065aa54f994234d543a58725f4dda99699afa" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string15 = "import subbrute" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string16 = /subbrute\.exe/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string17 = /subbrute\.py\s\-/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string18 = /subbrute_windows\.zip/ nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string19 = "TheRook/subbrute" nocase ascii wide
        // Description: A DNS meta-query spider that enumerates DNS records and subdomains.
        // Reference: https://github.com/TheRook/subbrute
        $string20 = /windows\-subbrute\.zip/ nocase ascii wide

    condition:
        any of them
}
