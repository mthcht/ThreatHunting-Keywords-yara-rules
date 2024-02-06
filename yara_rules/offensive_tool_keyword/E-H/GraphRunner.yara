rule GraphRunner
{
    meta:
        description = "Detection patterns for the tool 'GraphRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphRunner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string1 = /\sCan\ssearch\sall\sTeams\smessages\sin\sall\schannels\sthat\sare\sreadable\sby\sthe\scurrent\suser/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string2 = /\sClones\sa\ssecurity\sgroup\swhile\susing\san\sidentical\sname\sand\smember\slist\sbut\scan\sinject\sanother\suser\sas\swell/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string3 = /\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sGraphRunner\sModule\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string4 = /\sGraphRunner\.ps1/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string5 = /\sImport\stokens\sfrom\sother\stools\sfor\suse\sin\sGraphRunner/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string6 = /\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sPillage\sModules\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string7 = /\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sRecon\s\&\sEnumeration\sModules\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string8 = /\sSuccessful\sauthentication\.\sAccess\sand\srefresh\stokens\shave\sbeen\swritten\sto\sthe\sglobal\s\$apptokens\svariable\.\sTo\suse\sthem\swith\sother\sGraphRunner\smodules\suse\sthe\sTokens\sflag\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string9 = /\sTest\sdifferent\sCLientID\'s\sagainst\sMSGraph\sto\sdetermine\spermissions/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string10 = /\#\sPerform\sthe\sHTTP\sPOST\srequest\sto\ssearch\semails/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string11 = /\/GraphRunner\.git/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string12 = /\/GraphRunner\.ps1/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string13 = /\/GraphRunner\-main/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string14 = /\/interesting\-teamsmessages\.csv/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string15 = /\/Passwords\.docx/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string16 = /\[.{0,1000}\]\sAppending\saccess\stokens\sto\saccess_tokens\.txt/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string17 = /\[.{0,1000}\]\sChecking\saccess\sto\smailboxes\sfor\seach\semail\saddress\?/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string18 = /\\\"\-SecureString\\\"\sOR\s\\\"\-AsPlainText\\\"\sOR\s\\\"Net\.NetworkCredential\\\"/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string19 = /\\GraphRunner\.ps1/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string20 = /\\GraphRunner\-main/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string21 = /\\interesting\-teamsmessages\.csv/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string22 = /\\Passwords\.docx/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string23 = /\]\sListing\sGraphRunner\smodules\?/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string24 = /\-\-\-All\sAzure\sAD\sUser\sPrincipal\sNames\-\-\-/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string25 = /Beau\sBullock\s\(\@dafthack\)/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string26 = /dafthack\/GraphRunner/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string27 = /deckard\@tyrellcorporation\.io/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string28 = /DON\'T\sRUN\sTHIS\sIN\sYOUR\sWEB\sROOT\sAS\sIT\sWILL\sOUTPUT\sACCESS\sTOKENS/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string29 = /filetype\:credentials.{0,1000}\sAND\s\(\(client_id\sOR\sclientID\)\sAND\s\(tenant\)\sAND\s\(secret\)\)/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string30 = /filetype\:credentials.{0,1000}\sAND\s\(\\\"AWS_ACCESS_KEY_ID\\\"\sOR\s\\\"AWS_SECRET_ACCESS_KEY\\\"/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string31 = /filetype\:credentials.{0,1000}\sAND\s\(begin\sNEAR\(n\=1\)\s\(RSA\sOR\sOPENSSH\sOR\sDSA\sOR\sEC\sOR\sPGP\)\sNEAR\(n\=1\)\sKEY\)/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string32 = /filetype\:pem.{0,1000}AND\s\(\\\"BEGIN\sRSA\sPRIVATE\sKEY\\\"\sOR\s\\\"BEGIN\sDSA\sPRIVATE\sKEY\\\"\sOR\s\\\"BEGIN\sEC\sPRIVATE\sKEY\\/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string33 = /Get\-AzureADUsers\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string34 = /Get\-GraphTokens/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string35 = /Get\-SharePointSiteURLs/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string36 = /Get\-TeamsChat\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string37 = /Get\-TeamsChat.{0,1000}Downloads\sfull\sTeams\schat\sconversations/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string38 = /GraphRunner.{0,1000}access_tokens\.txt/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string39 = /GraphRunner.{0,1000}chatsResponse\.json/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string40 = /GraphRunner\/PHPRedirector/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string41 = /GraphRunner\\PHPRedirector/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string42 = /GraphRunnerGUI\.html/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string43 = /Guest\sUser\sPolicy\:\sGuest\susers\shave\sthe\ssame\saccess\sas\smembers\s\(most\sinclusive\)/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string44 = /http\:\/\/localhost\:8000\/emailviewer\.html/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string45 = /https\:\/\/YOURREDIRECTWEBSERVER\.azurewebsites\.net/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string46 = /iamlordvoldemort\@31337schoolofhackingandwizardry\.com/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string47 = /Invoke\-AutoOAuthFlow/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string48 = /Invoke\-AutoTokenRefresh.{0,1000}access_token\.txt/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string49 = /Invoke\-BruteClientIDAccess/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string50 = /Invoke\-CheckAccess/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string51 = /Invoke\-DeleteGroup\s\-Tokens\s.{0,1000}\s\-groupID\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string52 = /Invoke\-DeleteOAuthApp\s\-Tokens\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string53 = /Invoke\-DeleteOAuthApp/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string54 = /Invoke\-DriveFileDownload/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string55 = /Invoke\-DriveFileDownload/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string56 = /Invoke\-DumpApps/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string57 = /Invoke\-DumpCAPS/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string58 = /Invoke\-ForgeUserAgent\s\-Device\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string59 = /Invoke\-GraphOpenInboxFinder\s\-Tokens/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string60 = /Invoke\-GraphOpenInboxFinder/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string61 = /Invoke\-GraphRecon/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string62 = /Invoke\-GraphRunner/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string63 = /Invoke\-HTTPServer/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string64 = /Invoke\-ImmersiveFileReader/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string65 = /Invoke\-InjectOAuthApp\s\-AppName\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string66 = /Invoke\-InjectOAuthApp/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string67 = /Invoke\-InviteGuest/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string68 = /Invoke\-RefreshAzureAppTokens\s\-ClientId\s.{0,1000}\s\-ClientSecret\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string69 = /Invoke\-RefreshGraphTokens/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string70 = /Invoke\-RefreshToSharePointToken/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string71 = /Invoke\-SearchMailbox/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string72 = /Invoke\-SearchSharePointAndOneDrive/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string73 = /Invoke\-SearchTeams\s\-Tokens\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string74 = /Invoke\-SearchUserAttributes.{0,1000}Search\sfor\sterms\sacross\sall\suser\sattributes\sin\sa\sdirectory/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string75 = /Invoke\-SecurityGroupCloner\s\-Tokens\s/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string76 = /Invoke\-SecurityGroupCloner/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string77 = /Listening\sfor\sincoming\srequests\son\shttp\:\/\/localhost\:\$port\// nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string78 = /List\-GraphRunnerModules/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string79 = /PHPRedirector.{0,1000}AutoOAuthFlow\.py/ nocase ascii wide
        // Description: A Post-exploitation Toolset for Interacting with the Microsoft Graph API
        // Reference: https://github.com/dafthack/GraphRunner
        $string80 = /v\-Q8Q\~fEXAMPLEEXAMPLEDsmKpQw_Wwd57\-albMZ/ nocase ascii wide

    condition:
        any of them
}
