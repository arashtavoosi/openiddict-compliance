/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Compliance.Controllers
{
    [AutoValidateAntiforgeryToken]
    public class AuthenticationController : Controller
    {
        [HttpGet("~/signin")]
        public IActionResult SignIn([FromQuery] string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;

            return View();
        }

        [HttpPost("~/signin")]
        public IActionResult SignIn([FromForm] string username, [FromForm] string returnUrl = null)
        {
            var identity = new ClaimsIdentity(
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role);

            var time = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.AuthenticationTime, time, ClaimValueTypes.Integer64));

            if (string.Equals(username, "John", StringComparison.OrdinalIgnoreCase))
            {
                // Profile claims:
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Subject, "7DADB7DB-0637-4446-8626-2781B06A9E20"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "John F. Kennedy"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Gender, "male"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.GivenName, "John"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.MiddleName, "Fitzgerald"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.FamilyName, "Kennedy"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Nickname, "JFK"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.PreferredUsername, "John"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Birthdate, "1917-05-29"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Profile,
                    "https://www.biography.com/people/john-f-kennedy-9362930"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Picture,
                    "https://www.biography.com/.image/c_fill%2Ccs_srgb%2Cg_face%2Ch_300%2Cq_80%2Cw_300/MTIwNjA4NjMzODY3ODk2MzMy/john-f-kennedy-9362930-1-402.jpg"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Website, "https://www.whitehouse.gov/"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Locale, "en-US"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Zoneinfo, "America/New York"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.UpdatedAt, "1483225200", ClaimValueTypes.Integer64));

                // Email claim:
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Email, "john.fitzgerald.kennedy@usa.gov"));

                // Phone claim:
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.PhoneNumber, "+1 202-456-1111"));

                // Address claim:
                var address = new JObject
                {
                    [OpenIdConnectConstants.Claims.Country] = "United States of America",
                    [OpenIdConnectConstants.Claims.Locality] = "Washington",
                    [OpenIdConnectConstants.Claims.PostalCode] = "DC 20500",
                    [OpenIdConnectConstants.Claims.StreetAddress] = "1600 Pennsylvania Ave NW"
                };

                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Address, address.ToString(Formatting.None), JsonClaimValueTypes.Json));
            }

            else if (string.Equals(username, "Donald", StringComparison.OrdinalIgnoreCase))
            {
                // Profile claims:
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Subject, "95D7BE81-0CFB-4B52-9C92-33A45747FCEF"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Name, "Donald J. Trump"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Gender, "male"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.GivenName, "Donald"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.MiddleName, "John"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.FamilyName, "Trump"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Nickname, "The Donald"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.PreferredUsername, "Donald"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Birthdate, "1946-06-14"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Profile,
                    "https://www.biography.com/people/donald-trump-9511238"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Picture,
                    "https://www.biography.com/.image/c_fill%2Ccs_srgb%2Cg_face%2Ch_300%2Cq_80%2Cw_300/MTQxNzI4NTg2OTU1NDk5MDE3/donald_trump_photo_michael_stewartwireimage_gettyimages_169093538_croppedjpg.jpg"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Website, "https://www.whitehouse.gov/"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Locale, "en-US"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Zoneinfo, "America/New York"));
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.UpdatedAt, "1483225200", ClaimValueTypes.Integer64));

                // Email claim:
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Email, "donald.john.trump@usa.gov"));

                // Phone claim:
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.PhoneNumber, "+1 202-456-1111"));

                // Address claim:
                var address = new JObject
                {
                    [OpenIdConnectConstants.Claims.Country] = "United States of America",
                    [OpenIdConnectConstants.Claims.Locality] = "Washington",
                    [OpenIdConnectConstants.Claims.PostalCode] = "DC 20500",
                    [OpenIdConnectConstants.Claims.StreetAddress] = "1600 Pennsylvania Ave NW"
                };

                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.Address, address.ToString(Formatting.None), JsonClaimValueTypes.Json));
            }

            else
            {
                return BadRequest();
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/signin"
            };

            return SignIn(new ClaimsPrincipal(identity), properties, CookieAuthenticationDefaults.AuthenticationScheme);
        }

        [HttpPost("~/signout")]
        public IActionResult SignOut([FromQuery] string returnUrl = null)
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/signin"
            };

            return SignOut(properties, CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}