/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Compliance.Helpers;

namespace OpenIddict.Compliance.Controllers
{
    [AutoValidateAntiforgeryToken]
    public class AuthorizationController : Controller
    {
        [HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize(OpenIdConnectRequest request)
        {
            // Retrieve the claims stored in the authentication cookie.
            // If they can't be extracted, redirect the user to the login page.
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded || request.HasPrompt(OpenIdConnectConstants.Prompts.Login))
            {
                return Challenge(request);
            }

            // If a max_age parameter was provided, ensure that the cookie is not too old.
            // If it's too old, automatically redirect the user agent to the login page.
            if (request.MaxAge != null && result.Properties.IssuedUtc != null &&
                DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value))
            {
                return Challenge(request);
            }

            // Create a new authentication ticket.
            var ticket = CreateTicket(request, result);

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        [HttpPost("~/connect/token"), IgnoreAntiforgeryToken, Produces("application/json")]
        public async Task<IActionResult> Exchange(OpenIdConnectRequest request)
        {
            if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
            {
                // Retrieve the claims principal stored in the authorization code/refresh token.
                var result = await HttpContext.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);

                // Create a new authentication ticket, but reuse the properties stored in the
                // authorization code/refresh token, including the scopes originally granted.
                var ticket = CreateTicket(request, result, result.Properties);

                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }

            throw new NotSupportedException("The specified grant type is not supported.");
        }

        private AuthenticationTicket CreateTicket(
            OpenIdConnectRequest request, AuthenticateResult result,
            AuthenticationProperties properties = null)
        {
            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = new ClaimsIdentity(
                result.Principal.Claims,
                OpenIdConnectServerDefaults.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity), properties,
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Set the list of scopes granted to the client application.
            if (request.IsAuthorizationRequest() || (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType()))
            {
                ticket.SetScopes(new[]
                {
                    OpenIdConnectConstants.Scopes.OfflineAccess,
                    OpenIdConnectConstants.Scopes.OpenId,
                    OpenIdConnectConstants.Scopes.Address,
                    OpenIdConnectConstants.Scopes.Email,
                    OpenIdConnectConstants.Scopes.Phone,
                    OpenIdConnectConstants.Scopes.Profile
                }.Intersect(request.GetScopes()));
            }

            // The OP-Req-acr_values test consists in sending an "acr_values=1 2" parameter
            // as part of the authorization request. To indicate to the certification client
            // that the "1" reference value was satisfied, an "acr" claim is added.
            if (request.IsAuthorizationRequest() && request.HasAcrValue("1"))
            {
                identity.AddClaim(new Claim(OpenIdConnectConstants.Claims.AuthenticationContextReference, "1"));
            }

            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(destinations: GetDestinations(claim, ticket));
            }

            return ticket;
        }

        private IActionResult Challenge(OpenIdConnectRequest request)
        {
            // If the client application requested promptless authentication,
            // return an error indicating that the user is not logged in.
            if (request.HasPrompt(OpenIdConnectConstants.Prompts.None))
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIdConnectConstants.Properties.Error] = OpenIdConnectConstants.Errors.LoginRequired,
                    [OpenIdConnectConstants.Properties.ErrorDescription] = "The user is not logged in."
                });

                // Ask OpenIddict to return a login_required error to the client application.
                return Forbid(properties, OpenIdConnectServerDefaults.AuthenticationScheme);
            }

            // Otherwise, simply redirect the user agent to the login endpoint.
            else
            {
                var properties = new AuthenticationProperties
                {
                    RedirectUri = GetRedirectUrl()
                };

                return Challenge(properties, CookieAuthenticationDefaults.AuthenticationScheme);
            }
        }

        private string GetRedirectUrl()
        {
            // Override the prompt parameter to prevent infinite authentication/authorization loops.
            var parameters = Request.Query.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            parameters[OpenIdConnectConstants.Parameters.Prompt] = "continue";

            return Request.PathBase + Request.Path + QueryString.Create(parameters);
        }

        private IEnumerable<string> GetDestinations(Claim claim, AuthenticationTicket ticket)
        {
            switch (claim.Type)
            {
                // Note: always include acr and auth_time in the identity token as they must be flowed
                // from the authorization endpoint to the identity token returned from the token endpoint.
                case OpenIdConnectConstants.Claims.AuthenticationContextReference:
                case OpenIdConnectConstants.Claims.AuthenticationTime:
                    yield return OpenIdConnectConstants.Destinations.IdentityToken;
                    yield break;

                // Note: the name claim is always included, even if
                // the profile scope is not requested nor granted.
                case OpenIdConnectConstants.Claims.Name:
                    yield return OpenIdConnectConstants.Destinations.AccessToken;
                    yield return OpenIdConnectConstants.Destinations.IdentityToken;
                    yield break;

                case OpenIdConnectConstants.Claims.Subject:
                case OpenIdConnectConstants.Claims.Gender:
                case OpenIdConnectConstants.Claims.GivenName:
                case OpenIdConnectConstants.Claims.MiddleName:
                case OpenIdConnectConstants.Claims.FamilyName:
                case OpenIdConnectConstants.Claims.Nickname:
                case OpenIdConnectConstants.Claims.PreferredUsername:
                case OpenIdConnectConstants.Claims.Birthdate:
                case OpenIdConnectConstants.Claims.Profile:
                case OpenIdConnectConstants.Claims.Picture:
                case OpenIdConnectConstants.Claims.Website:
                case OpenIdConnectConstants.Claims.Locale:
                case OpenIdConnectConstants.Claims.Zoneinfo:
                case OpenIdConnectConstants.Claims.UpdatedAt:
                    yield return OpenIdConnectConstants.Destinations.AccessToken;

                    if (ticket.HasScope(OpenIdConnectConstants.Scopes.Profile))
                        yield return OpenIdConnectConstants.Destinations.IdentityToken;

                    yield break;

                case OpenIdConnectConstants.Claims.Email:
                    yield return OpenIdConnectConstants.Destinations.AccessToken;

                    if (ticket.HasScope(OpenIdConnectConstants.Scopes.Email))
                        yield return OpenIdConnectConstants.Destinations.IdentityToken;

                    yield break;

                case OpenIdConnectConstants.Claims.PhoneNumber:
                    yield return OpenIdConnectConstants.Destinations.AccessToken;

                    if (ticket.HasScope(OpenIdConnectConstants.Scopes.Phone))
                        yield return OpenIdConnectConstants.Destinations.IdentityToken;

                    yield break;

                case OpenIdConnectConstants.Claims.Address:
                    yield return OpenIdConnectConstants.Destinations.AccessToken;

                    if (ticket.HasScope(OpenIdConnectConstants.Scopes.Address))
                        yield return OpenIdConnectConstants.Destinations.IdentityToken;

                    yield break;

                default:
                    yield return OpenIdConnectConstants.Destinations.AccessToken;
                    yield break;
            }
        }
    }
}