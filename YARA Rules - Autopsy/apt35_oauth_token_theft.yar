Detects patterns associated with cloud token abuse or OAuth phishing apps.

rule APT35_OAuth_Token_Theft
{
    meta:
        description = "Detects OAuth token abuse or token extraction behavior"
        category = "Cloud Credential Theft"

    strings:
        $oauth1 = "access_token" nocase
        $oauth2 = "refresh_token" nocase
        $oauth3 = "client_secret" nocase
        $oauth4 = "authorization_code" nocase
        $api1 = "api.microsoftonline.com" nocase
        $api2 = "login.microsoftonline.com" nocase

    condition:
        2 of ($oauth*) and 1 of ($api*)
}
