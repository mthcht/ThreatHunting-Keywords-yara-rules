rule TeamFiltration
{
    meta:
        description = "Detection patterns for the tool 'TeamFiltration' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TeamFiltration"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string1 = /\s\-\-config\s.{0,1000}\.json\s\-\-debug\s\-\-exfil\s\-\-onedrive/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string2 = /\s\-\-config\s.{0,1000}\.json\s\-\-enum\s\-\-validate\-msol\s\-\-usernames\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string3 = /\s\-\-config\s.{0,1000}\.json\s\-\-enum\s\-\-validate\-teams/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string4 = /\s\-\-config\s.{0,1000}\.json\s\-\-exfil\s\-\-aad/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string5 = /\s\-\-debug\s\-\-exfil\s\-\-onedrive/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string6 = /\s\-\-enum\s\-\-validate\-msol\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string7 = /\s\-\-enum\s\-\-validate\-teams/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string8 = /\s\-\-exfil\s\-\-cookie\-dump\s\s.{0,1000}\s\-\-all/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string9 = /\s\-\-exfil\s\-\-cookie\-dump\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string10 = /\s\-\-exfil\s\-\-teams\s\-\-owa\s\-\-owa\-limit/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string11 = /\s\-\-exfil\s\-\-teams\s\-\-owa/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string12 = /\s\-\-exfil\s\-\-tokens\s.{0,1000}\s\-\-onedrive\s\-\-owa/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string13 = /\s\-\-exfil\s\-\-tokens\s.{0,1000}\s\-\-onedrive/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string14 = /\sloginAAD\.ps1/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string15 = /\s\-\-outpath\s.{0,1000}\s\-\-config\s.{0,1000}\.json\s\-\-backdoor/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string16 = /\s\-\-outpath\s.{0,1000}\.json\s\-\-backdoor/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string17 = /\s\-\-shuffle\-users.{0,1000}\s\-\-spray/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string18 = /\s\-\-spray\s.{0,1000}\-\-shuffle\-users/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string19 = /\s\-\-spray\s\-\-passwords\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string20 = /\s\-\-spray\s\-\-push\-locked\s\-\-months\-only\s\-\-exclude\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string21 = /\s\-\-spray\s\-\-push\-locked\s\-\-months\-only/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string22 = /\sTeamFiltration\.dll/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string23 = /\sTeamFiltration\.exe/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string24 = /\"sacrificialO365Passwords\"\:\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string25 = /\"sacrificialO365Username\"\:\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string26 = /\/loginAAD\.ps1/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string27 = /\/TeamFiltration\.dll/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string28 = /\/TeamFiltration\.exe/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string29 = /\/TeamFiltration\/releases\/latest/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string30 = /\[\!\]\sCould\snot\sextract\suseful\stoken\sfrom\sspecified\sTeams\sdatabase\!/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string31 = /\[\!\]\sESTSAUTHPERSISTENT\scookie\swas\sempty\!/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string32 = /\[\!\]\sFailed\sto\sexfiltrate\susing\sRoadTools\sauth\sfile/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string33 = /\[\!\]\sFailed\sto\sparse\sRoadTools\sauth\sJSON\sfile/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string34 = /\[\!\]\sThe\sexfiltration\smodules\sdoes\snot\suse\sFireProx/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string35 = /\[\!\]\sYou\sare\srunning\sTeamFiltration\swithout\sa\sconfig/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string36 = /\[\+\]\sCould\snot\sfind\sTeamFiltration\sconfig/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string37 = /\[\+\]\sSuccessfully\sretrieved\san\saccess\stoken\sfor\sUser\:/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string38 = /\\CookieData\.txt\s\-\-all/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string39 = /\\loginAAD\.ps1/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string40 = /\\Modules\\Backdoor\.cs/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string41 = /\\TeamFiltration\.dll/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string42 = /\\TeamFiltration\.exe/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string43 = /\\TeamFiltration\\OneDriveAPI/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string44 = /\\TeamFiltration\\TeamFiltration\\/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string45 = /\\TeamFiltrationConfig_Example\.json/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string46 = /\]\sTeamFiltration\sV3\.5\.3\sPUBLIC/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string47 = /\>TeamFiltration\.dll\</ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string48 = /2659c2d40606e2b088c3bbd6fd6a293692ac7f219221844071abf434a638e1da/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string49 = /4e09f3d552d00f6ade653b2a9c289a411062b14fab2148f7accab8c8428c9bdb/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string50 = /A0F044C5\-D910\-4720\-B082\-58824E372281/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string51 = /EF143476\-E53D\-4C39\-8DBB\-A6AC7883236C/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string52 = /Flangvik\/TeamFiltration/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string53 = /OutputTokens\.txt\s\-\-onedrive\s\-\-owa/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string54 = /raw\.githubusercontent\.com\/Flangvik\/statistically\-likely\-usernames\// nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string55 = /TeamFiltration\.exe\s/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string56 = /TeamFiltration\\Program\.cs/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string57 = /TeamFiltration\-v.{0,1000}\-linux\-x86_64\.zip/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string58 = /TeamFiltration\-v.{0,1000}\-macOS\-arm64\.zip/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string59 = /TeamFiltration\-v.{0,1000}\-macOS\-x86_64\.zip/ nocase ascii wide
        // Description: TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
        // Reference: https://github.com/Flangvik/TeamFiltration
        $string60 = /TeamFiltration\-v.{0,1000}\-win\-x86_64\.zip/ nocase ascii wide

    condition:
        any of them
}
