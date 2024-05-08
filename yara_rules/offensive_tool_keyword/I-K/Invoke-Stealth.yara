rule Invoke_Stealth
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Stealth' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Stealth"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string1 = /\s\[\+\]\sSUCCESS\:\sAMSI\sBypassed\!/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string2 = /\sby\s\@JoelGMSec\s/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string3 = /\sInvoke\-Stealth\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string4 = /\srevshell\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string5 = /\"iN\"\+\"voK\"\+\"e\"\+\"\-\"\+\"eXP\"\+\"re\"\+\"sSi\"\+\"oN\"/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string6 = /\.ps1\s\-technique\sBetterXencrypt/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string7 = /\.ps1\s\-technique\sChameleon/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string8 = /\.ps1\s\-technique\sPSObfuscation/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string9 = /\.ps1\s\-technique\sPyFuscation/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string10 = /\.ps1\s\-technique\sReverseB64/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string11 = /\/Invoke\-Stealth\.git/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string12 = /\/invoke\-stealth\.php/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string13 = /\/Invoke\-Stealth\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string14 = /\/printernightmare\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string15 = /\/revshell\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string16 = /\[\!\]\sAvoid\smixing\sBetterXencrypt\swith\sanother\stechniques/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string17 = /\[\#\]\sChecking\sfile\sagainst\sAMSI\sTrigger/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string18 = /\[\+\]\sEncoding\swith\sbase64\sand\sreverse\sit\sto\savoid\sdetections/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string19 = /\[\+\]\sLoading\sBetterXencrypt\sand\sdoing\ssome\sencryption\swith\srandom\siterations/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string20 = /\[\+\]\sLoading\sPSObfuscation\sand\srandomizing\sscript/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string21 = /\[\+\]\sLoading\sPyFuscation\sand\sdoing\s\$some\sobfuscation/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string22 = /\\AmsiTrigger\.pdb/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string23 = /\\Invoke\-Stealth\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string24 = /\\printernightmare\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string25 = /\\revshell\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string26 = /\]\sWriting\sobfuscated\spayload\sto\s/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string27 = /\=\=gCkV2Zh5WYNNXZB5SeoBXYyd2b0BXeyNkL5RXayV3YlNlLtVGdzl3U/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string28 = /\=\=gNyEDMx80UJpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string29 = /\=\=gQDVkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string30 = /\=\=wcvJXZapjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string31 = /\=\=wMykDWJNlTBpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string32 = /\=\=wNTN0SQpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string33 = /\=\=wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string34 = /2ba17d622736a4d3132c17db3b8c725f001fdbe7fca4b9b4248262b5e54a4107/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string35 = /729ed6976b1710e57fb5e486e1a017b39a437895ae86056c2aa3d45763a6f330/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string36 = /7aa6a3be25f05eb6a5c5cda7f10e48007dae601c9918a9734db3697ed6c63afc/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string37 = /7becedb670137807e079f535c7bec03131414f90e8e2a70e4c989b9d9167f4aa/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string38 = /9eb21ba1323fac7c64c1e03fb3c29e374ab7d99ab9c4d27eb4c3166575769a0f/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string39 = /aec7b9f5d2bf5b9ae363fce9c7426bf03a08271f1f7ea1bba4bc5e05f717ac69/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string40 = /AMSITrigger\.exe/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string41 = /BetterXencrypt\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string42 = /c288394f0c71cea2f14223899de957ca2a5d101bcbfe1efacc23e480fabde335/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string43 = /Invoke\-BetterXencrypt/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string44 = /Invoke\-PSObfuscation/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string45 = /JoelGMSec\/Invoke\-Stealth/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string46 = /Load\-BetterXencrypt.{0,1000}\s/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string47 = /Load\-PSObfuscation/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string48 = /Load\-PyFuscation/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string49 = /o\-printernightmare\.ps1/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string50 = /U3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5BZXNNYW5hZ2VkCg\=\=/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string51 = /W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkNCQw\=\=/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string52 = /W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQ2lwaGVyTW9kZV06OkVDQg\=\=/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string53 = /W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpaZXJvcw\=\=/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string54 = /W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpBTlNJWDkyMw\=\=/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string55 = /W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpJU08xMDEyNg\=\=/ nocase ascii wide
        // Description: Simple & Powerful PowerShell Script Obfuscator
        // Reference: https://github.com/JoelGMSec/Invoke-Stealth
        $string56 = /W1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpQS0NTNw\=\=/ nocase ascii wide

    condition:
        any of them
}
