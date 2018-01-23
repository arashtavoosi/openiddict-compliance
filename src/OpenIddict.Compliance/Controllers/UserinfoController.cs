/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using AspNet.Security.OAuth.Introspection;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Compliance.Controllers
{
    [Authorize(AuthenticationSchemes = OAuthIntrospectionDefaults.AuthenticationScheme)]
    public class UserinfoController : Controller
    {
        [HttpGet("~/connect/userinfo")]
        [HttpPost("~/connect/userinfo")]
        public IActionResult Userinfo()
        {
            var claims = new JObject
            {
                // Note: the "sub" claim is a mandatory claim that must be included in the JSON response.
                [OpenIdConnectConstants.Claims.Subject] = User.GetClaim(OpenIdConnectConstants.Claims.Subject),

                // Note: the "name" claim is deliberately always included, even if the profile scope was not granted.
                [OpenIdConnectConstants.Claims.Name] = User.GetClaim(OpenIdConnectConstants.Claims.Name)
            };

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Profile))
            {
                claims[OpenIdConnectConstants.Claims.Gender] = User.GetClaim(OpenIdConnectConstants.Claims.Gender);
                claims[OpenIdConnectConstants.Claims.GivenName] = User.GetClaim(OpenIdConnectConstants.Claims.GivenName);
                claims[OpenIdConnectConstants.Claims.MiddleName] = User.GetClaim(OpenIdConnectConstants.Claims.MiddleName);
                claims[OpenIdConnectConstants.Claims.FamilyName] = User.GetClaim(OpenIdConnectConstants.Claims.FamilyName);
                claims[OpenIdConnectConstants.Claims.Nickname] = User.GetClaim(OpenIdConnectConstants.Claims.Nickname);
                claims[OpenIdConnectConstants.Claims.PreferredUsername] = User.GetClaim(OpenIdConnectConstants.Claims.PreferredUsername);
                claims[OpenIdConnectConstants.Claims.Birthdate] = User.GetClaim(OpenIdConnectConstants.Claims.Birthdate);
                claims[OpenIdConnectConstants.Claims.Profile] = User.GetClaim(OpenIdConnectConstants.Claims.Profile);
                claims[OpenIdConnectConstants.Claims.Picture] = User.GetClaim(OpenIdConnectConstants.Claims.Picture);
                claims[OpenIdConnectConstants.Claims.Website] = User.GetClaim(OpenIdConnectConstants.Claims.Website);
                claims[OpenIdConnectConstants.Claims.Locale] = User.GetClaim(OpenIdConnectConstants.Claims.Locale);
                claims[OpenIdConnectConstants.Claims.Zoneinfo] = User.GetClaim(OpenIdConnectConstants.Claims.Zoneinfo);
                claims[OpenIdConnectConstants.Claims.UpdatedAt] = long.Parse(
                    User.GetClaim(OpenIdConnectConstants.Claims.UpdatedAt),
                    NumberStyles.Number, CultureInfo.InvariantCulture);
            }

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Email))
            {
                claims[OpenIdConnectConstants.Claims.Email] = User.GetClaim(OpenIdConnectConstants.Claims.Email);
                claims[OpenIdConnectConstants.Claims.EmailVerified] = false;
            }

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Phone))
            {
                claims[OpenIdConnectConstants.Claims.PhoneNumber] = User.GetClaim(OpenIdConnectConstants.Claims.PhoneNumber);
                claims[OpenIdConnectConstants.Claims.PhoneNumberVerified] = false;
            }

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Address))
            {
                claims[OpenIdConnectConstants.Claims.Address] = JObject.Parse(User.GetClaim(OpenIdConnectConstants.Claims.Address));
            }

            return Json(claims);
        }
    }
}