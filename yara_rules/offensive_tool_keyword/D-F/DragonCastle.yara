rule DragonCastle
{
    meta:
        description = "Detection patterns for the tool 'DragonCastle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DragonCastle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string1 = /\sdragoncastle\.py/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string2 = /\s\-target\-ip\s.{0,1000}\s\-remote\-dll\s.{0,1000}\.dll.{0,1000}\s\-local\-dll\s/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string3 = /\/DragonCastle\.git/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string4 = /\/DragonCastle\.pdb/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string5 = /\/dragoncastle\.py/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string6 = /\\DragonCastle\.dll/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string7 = /\\DragonCastle\.pdb/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string8 = /\\DragonCastle\-master\\/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string9 = /\\kuhl_m_sekurlsa\.c/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string10 = /\\pwned\.txt/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string11 = /274F19EC\-7CBA\-4FC7\-80E6\-BB41C1FE6728/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string12 = /DragonCastle\s\-\s\@TheXC3LL/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string13 = /DragonCastle\.dll/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string14 = /dragoncastle\.py\s\-/ nocase ascii wide
        // Description: A PoC that combines AutodialDLL Lateral Movement technique and SSP to scrape NTLM hashes from LSASS process.
        // Reference: https://github.com/mdsecactivebreach/DragonCastle
        $string15 = /mdsecactivebreach\/DragonCastle/ nocase ascii wide

    condition:
        any of them
}
