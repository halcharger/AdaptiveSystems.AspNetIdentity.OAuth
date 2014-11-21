using System;
using System.Configuration;
using AdaptiveSystems.AspNetIdentity.OAuth.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.MicrosoftAccount;
using Microsoft.Owin.Security.OAuth;
using NExtensions;
using Owin;

namespace AdaptiveSystems.AspNetIdentity.OAuth
{
    public static class StartupOptions
    {
        public const string AccessTokenExpiresInMinutesAppSettingKey = "AdaptiveSystems.AspNetIdentity.OAuth.AccessTokenExpiresInMinutes";
        public const string GoogleClientIdAppSettingKey = "AdaptiveSystems.AsapNetIdentity.OAuth.GoogleClientId";
        public const string GoogleClientSecretAppSettingKey = "AdaptiveSystems.AspNetIdentity.OAuth.GoogleClientSecret";
        public const string FacebookAppIdAppSettingKey = "AdaptiveSystems.AspNetIdentity.OAuth.FacebookAppId";
        public const string FacebookAppSecretAppSettingKey = "AdaptiveSystems.AspNetIdentity.OAuth.FacebookAppSecret";
        public const string FacebookAppTokenAppSettingKey = "AdaptiveSystems.AspNetIdentity.OAuth.FacebookAppToken";

        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static GoogleOAuth2AuthenticationOptions GoogleAuthOptions { get; private set; }
        public static FacebookAuthenticationOptions FacebookAuthOptions { get; private set; }
        public static MicrosoftAccountAuthenticationOptions MicrosoftAuthOptions { get; private set; }

        public static void ConfigureOAuth(IAppBuilder app)
        {
            //use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(Microsoft.AspNet.Identity.DefaultAuthenticationTypes.ExternalCookie);

            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();

            var options = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = GetAccessTokenExpireTimeSpanFromAppSettings(),
                Provider = new SimpleAuthorizationServerProvider(),
                RefreshTokenProvider = new SimpleRefreshTokenProvider()
            };

            // Token Generation
            app.UseOAuthAuthorizationServer(options);
            app.UseOAuthBearerAuthentication(OAuthBearerOptions);

            //Configure Google External Login
            GoogleAuthOptions = new GoogleOAuth2AuthenticationOptions()
            {
                //ClientId = "906041197601-v5v95tijskeiltb1bj2kbur9m0tha1pf.apps.googleusercontent.com",
                //ClientSecret = "FVmI7WRUV1bF0TOazSk_2I1n",
                ClientId = GoogleClientIdAppSettingKey.GetAppSettingValue(),
                ClientSecret = GoogleClientSecretAppSettingKey.GetAppSettingValue(),
                Provider = new GoogleAuthProvider()
            };
            app.UseGoogleAuthentication(GoogleAuthOptions);

            //Configure Facebook External Login
            FacebookAuthOptions = new FacebookAuthenticationOptions()
            {
                //AppId = "1556891417855856",
                //AppSecret = "363f6b4377706c270b7ec6afaae23525",
                AppId = FacebookAppIdAppSettingKey.GetAppSettingValue(),
                AppSecret = FacebookAppSecretAppSettingKey.GetAppSettingValue(),
                Provider = new FacebookAuthProvider(),
            };
            FacebookAuthOptions.Scope.Add("email");
            app.UseFacebookAuthentication(FacebookAuthOptions);

            //configure Microsoft external login
            //MicrosoftAuthOptions = new MicrosoftAccountAuthenticationOptions
            //{
            //    ClientId = "0000000048131E21",
            //    ClientSecret = "r-I7BrnlogBFQGc2BlAfFQeYMRMHLF9r",
            //    Provider = new MicrosoftAccountAuthenticationProvider()
            //};
            //app.UseMicrosoftAccountAuthentication(MicrosoftAuthOptions);
            
        }

        private static TimeSpan GetAccessTokenExpireTimeSpanFromAppSettings()
        {
            var appSettingValue = ConfigurationManager.AppSettings[AccessTokenExpiresInMinutesAppSettingKey];
            if (!appSettingValue.HasValue())
                throw new Exception("You have not configured the Access Token Expirary in minutes in the config file. Please add an AppSetting entry with a key of '0' and specify the Access Token Expirary in minutes.".FormatWith(AccessTokenExpiresInMinutesAppSettingKey));

            return TimeSpan.FromMinutes(appSettingValue.ToInteger());
        }

        public static string GetAppSettingValue(this string key)
        {
            var appSettingValue = ConfigurationManager.AppSettings[key];

            if (!appSettingValue.HasValue())
                throw new Exception("You have not provided a value for the config App Setting key: '{0}', please create this App Setting key and provide a relevant value.".FormatWith(key));

            return appSettingValue;
        }
    }
}