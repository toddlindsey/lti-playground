using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.SpaServices.Webpack;
using Lti.Web.Services;

namespace Lti.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // HELPFUL SITES:
            // https://www.jerriepelser.com/blog/authenticate-oauth-aspnet-core-2/

            // https://andrewlock.net/an-introduction-to-openid-connect-in-asp-net-core/ ??

            // older to new syntax for open ID connect
            // https://docs.microsoft.com/en-us/aspnet/core/migration/1x-to-2x/identity-2x?view=aspnetcore-2.1

            // https://stackoverflow.com/questions/46222520/turn-off-automaticchallenge-in-asp-net-mvc-core-2-openidconnect ??

            services.AddMvc();
            services.AddSingleton<ConfigService>();

            //services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores();
            //services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            //            .AddCookie(o => o.LoginPath = new PathString("/login"))
            //            .AddFacebook(o =>
            //            {
            //                o.AppId = Configuration["facebook:appid"];
            //                o.AppSecret = Configuration["facebook:appsecret"];
            //            });
            //services.AddAuthentication(options =>
            //{
            //    // Normally, use cookies first:
            //    //options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    //options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

            //    // We will force Open ID for now
            //    options.DefaultAuthenticateScheme = OpenIdConnectDefaults.AuthenticationScheme;
            //    // options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            //})
            // .AddCookie()
            // .AddOAuth(OpenIdConnectDefaults.AuthenticationScheme, options =>
                //{
                //    options.ClientId = Configuration["OAuth:ClientId"];
                //    options.ClientSecret = Configuration["OAuth:ClientSecret"];
                //    //options.CallbackPath = new PathString("/signin-github");

                //    //options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                //    //options.TokenEndpoint = "https://github.com/login/oauth/access_token";
                //    //options.UserInformationEndpoint = "https://api.github.com/user";

                //    //options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                //    //options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                //    //options.ClaimActions.MapJsonKey("urn:github:login", "login");
                //    //options.ClaimActions.MapJsonKey("urn:github:url", "html_url");
                //    //options.ClaimActions.MapJsonKey("urn:github:avatar", "avatar_url");

                //    //options.Events = new OAuthEvents
                //    //{
                //    //    OnCreatingTicket = async context =>
                //    //    {
                //    //        var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                //    //        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                //    //        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

                //    //        var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                //    //        response.EnsureSuccessStatusCode();

                //    //        var user = JObject.Parse(await response.Content.ReadAsStringAsync());

                //    //        context.RunClaimActions(user);
                //    //    }
                //    //};
                //})
            //.AddOpenIdConnect(options =>
            //{
            //    options.Authority = Configuration["auth:openid:authority"];
            //    options.ClientId = Configuration["auth:openid:clientid"];
            //})
            //.AddJwtBearer(options =>
            //{
            //     options.TokenValidationParameters = new TokenValidationParameters
            //     {
            //         // Clock skew compensates for server time drift.
            //         // We recommend 5 minutes or less:
            //         ClockSkew = TimeSpan.FromMinutes(5),
            //         // Specify the key used to sign the token:
            //         IssuerSigningKey = signingKey,
            //         RequireSignedTokens = true,
            //         // Ensure the token hasn't expired:
            //         RequireExpirationTime = true,
            //         ValidateLifetime = true,
            //         // Ensure the token audience matches our audience value (default true):
            //         ValidateAudience = true,
            //         ValidAudience = "api://default",
            //         // Ensure the token was issued by a trusted authorization server (default true):
            //         ValidateIssuer = true,
            //         ValidIssuer = "https://{yourOktaDomain}/oauth2/default"
            //     };
            //});

            //// Microsoft.AspNetCore.Authentication.JwtBearer
            //.AddJwtBearer(cfg =>
            //{
            //    cfg.RequireHttpsMetadata = false;
            //    cfg.SaveToken = true;

            //    cfg.TokenValidationParameters = new TokenValidationParameters()
            //    {
            //        ValidIssuer = Configuration["Tokens:Issuer"],
            //        ValidAudience = Configuration["Tokens:Issuer"],
            //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Tokens:Key"]))
            //    };

            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            //if (env.IsDevelopment())
            //{
            //    app.UseDeveloperExceptionPage();
            //}
            //else
            //{
            //    app.UseExceptionHandler("/Error");
            //}

            //app.UseStaticFiles();

            //             app.UseIdentity

            // app.UseAuthentication();

            //app.UseMvc();
            //app.UseMvc(routes =>
            //{
            //    routes.MapRoute(
            //        name: "default",
            //        template: "{controller}/{action=Index}/{id?}");
            //});

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseWebpackDevMiddleware(new WebpackDevMiddlewareOptions
                {
                    HotModuleReplacement = true
                });
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");

                routes.MapSpaFallbackRoute(
                    name: "spa-fallback",
                    defaults: new { controller = "Home", action = "Index" });
            });
        }
    }
}
