using System;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Compliance.Models;
using OpenIddict.Core;
using OpenIddict.Models;

namespace OpenIddict.Compliance
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public IHostingEnvironment Environment { get; }

        public Startup(
            IConfiguration configuration,
            IHostingEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                // Configure the context to use an in-memory store.
                options.UseInMemoryDatabase(nameof(ApplicationDbContext));

                // Register the entity sets needed by OpenIddict.
                options.UseOpenIddict();
            });

            // Register the OpenIddict services.
            services.AddOpenIddict(options =>
            {
                // Register the Entity Framework stores.
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>();

                // Register the ASP.NET Core MVC binder used by OpenIddict.
                options.AddMvcBinders();

                // Enable the authorization, token, introspection and userinfo endpoints.
                options.EnableAuthorizationEndpoint(Configuration["OpenIddict:Endpoints:Authorization"])
                       .EnableTokenEndpoint(Configuration["OpenIddict:Endpoints:Token"])
                       .EnableIntrospectionEndpoint(Configuration["OpenIddict:Endpoints:Introspection"])
                       .EnableUserinfoEndpoint(Configuration["OpenIddict:Endpoints:Userinfo"]);

                // Enable the authorization code, implicit and the refresh token flows.
                options.AllowAuthorizationCodeFlow()
                       .AllowImplicitFlow()
                       .AllowRefreshTokenFlow();

                // Expose all the supported claims in the discovery document.
                options.RegisterClaims(Configuration.GetSection("OpenIddict:Claims").Get<string[]>());

                // Expose all the supported scopes in the discovery document.
                options.RegisterScopes(Configuration.GetSection("OpenIddict:Scopes").Get<string[]>());

                // Make the "client_id" parameter mandatory when sending a token request.
                options.RequireClientIdentification();

                // Enable request caching.
                options.EnableRequestCaching();

                // Use reference tokens, which is required to be able
                // to use immediate access token revocation.
                options.UseReferenceTokens();

                // Note: an ephemeral signing key is deliberately used
                // to make the "OP-Rotation-OP-Sig" test easier to run as
                // restarting the application is enough to rotate the keys.
                options.AddEphemeralSigningKey();

                // Disable the security transport requirement.
                if (Environment.IsDevelopment())
                {
                    options.DisableHttpsRequirement();
                }
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })

            .AddCookie(options =>
            {
                options.AccessDeniedPath = "/signin";
                options.LoginPath = "/signin";
                options.LogoutPath = "/signout";
            })

            .AddOAuthIntrospection(options =>
            {
                options.Authority = Configuration.GetValue<Uri>("OpenIddict:Introspection:Authority");
                options.RequireHttpsMetadata = options.Authority.Scheme == Uri.UriSchemeHttps;

                options.ClientId = Configuration["OpenIddict:Introspection:ClientId"];
                options.ClientSecret = Configuration["OpenIddict:Introspection:ClientSecret"];

                // Disable the built-in caching feature so that
                // token revocation is immediately applied.
                options.CachingPolicy = null;

                // Allow the access token to be retrieved from the
                // query string when the request is a userinfo request.
                options.Events.OnRetrieveToken = context =>
                {
                    var request = context.HttpContext.GetOpenIdConnectRequest();
                    if (request != null && request.IsUserinfoRequest())
                    {
                        context.Token = request.AccessToken;
                    }

                    return Task.CompletedTask;
                };
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseStatusCodePagesWithReExecute("/error");

            app.UseAuthentication();

            app.Use((context, next) =>
            {
                var request = context.GetOpenIdConnectRequest();
                if (request == null || (!request.IsAuthorizationRequest() && !request.IsLogoutRequest()))
                {
                    // Only enable the status code pages feature for authorization and logout requests.
                    var feature = context.Features.Get<IStatusCodePagesFeature>();
                    if (feature != null)
                    {
                        feature.Enabled = false;
                    }
                }

                return next();
            });

            app.UseMvcWithDefaultRoute();

            app.UseWelcomePage();

            // Seed the database with the sample applications.
            // Note: in a real world application, this step should be part of a setup script.
            InitializeAsync(app.ApplicationServices, CancellationToken.None).GetAwaiter().GetResult();
        }

        private async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken)
        {
            // Create a new service scope to ensure the database context is correctly disposed when this methods returns.
            using (var scope = services.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                await context.Database.EnsureCreatedAsync(cancellationToken);

                // Retrieve the client definitions from the configuration
                // and insert them in the applications table if necessary.
                var descriptors = Configuration.GetSection("OpenIddict:Clients").Get<OpenIddictApplicationDescriptor[]>();
                if (descriptors.Length == 0)
                {
                    throw new InvalidOperationException("No client application was found in the configuration file.");
                }

                var manager = scope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

                foreach (var descriptor in descriptors)
                {
                    if (await manager.FindByClientIdAsync(descriptor.ClientId, cancellationToken) != null)
                    {
                        continue;
                    }

                    await manager.CreateAsync(descriptor, cancellationToken);
                }
            }
        }
    }
}
