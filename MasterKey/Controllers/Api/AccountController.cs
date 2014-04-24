using MasterKey.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using Microsoft.AspNet.Identity.Owin;
using System.Security.Claims;
using Microsoft.Owin.Security;
using Microsoft.Owin.Infrastructure;
using Microsoft.AspNet.Identity;

namespace MasterKey.Controllers.Api
{
    public class AccountController : ApiController
    {
        private AppUserManager _userManager;
        public AppUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.Current.Request.GetOwinContext().GetUserManager<AppUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        } 

      
        [HttpPost]
        [ActionName("Authenticate")]
        [AllowAnonymous]
        public String Authenticate(string user, string password)
        {

            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
                return "failed";
            var userIdentity = UserManager.FindAsync(user, password).Result;
            if (userIdentity != null)
            {
                var identity = new ClaimsIdentity(Startup.OAuthBearerOptions.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, user));
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userIdentity.Id));
                AuthenticationTicket ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                var currentUtc = new SystemClock().UtcNow;
                ticket.Properties.IssuedUtc = currentUtc;
                ticket.Properties.ExpiresUtc = currentUtc.Add(TimeSpan.FromMinutes(30));
                string AccessToken = Startup.OAuthBearerOptions.AccessTokenFormat.Protect(ticket);
                return AccessToken;
            }
            return "failed";
        }

        [Authorize]
        [HttpGet]
        [ActionName("ValidateToken")]
        public String ValidateToken()
        {
            var user = this.User.Identity;
            if (user != null)
                return string.Format("{0} - {1}", user.GetUserId(), user.GetUserName());
            else
                return "Unable to resolve user id";

        }

        [Authorize]
        [HttpGet]
        [ActionName("GetPrivateData")]
        public object GetPrivateData()
        {
            return new { Message = "Secret information"};
        }
    }
}