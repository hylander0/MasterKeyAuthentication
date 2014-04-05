using MasterKey.Identity.UserStore;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MasterKey.Identity
{
    public class AppUserManager : UserManager<AppUserIdentity>
    {
        public AppUserManager(IUserStore<AppUserIdentity> store)
            : base(store) { }

        public static AppUserManager Create(IdentityFactoryOptions<AppUserManager> options, IOwinContext context)
        {
            var manager = new AppUserManager(new UserStore<AppUserIdentity>(context.Get<AppUserIdentityDbContext>()));
            manager.RegisterTwoFactorProvider("PhoneCode", new PhoneNumberTokenProvider<AppUserIdentity>
            {
                MessageFormat = "Your security code is: {0}"
            });
            manager.SmsService = new GoogleSmsService();
            return manager;
        }

    }

}