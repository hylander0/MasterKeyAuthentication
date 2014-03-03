using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace MasterKey.Identity.UserStore
{
    public class AppUserIdentityDbContextInitializer : CreateDatabaseIfNotExists<AppUserIdentityDbContext>
    {
        protected override void Seed(AppUserIdentityDbContext context)
        {
            InitializeIdentityForEF(context);
            base.Seed(context);


        }

        private void InitializeIdentityForEF(AppUserIdentityDbContext context)
        {
            var UserManager = new UserManager<AppUserIdentity>(new UserStore<AppUserIdentity>(context));
            var RoleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(context));
            string name = "Admin";
            string password = "123456";
            string test = "test";

            //Create Role Test and User Test
            RoleManager.Create(new IdentityRole(test));
            UserManager.Create(new AppUserIdentity()
            {
                UserName = test,
                Domain = "ITEEDEE",
                FirstName = "Test User"
            }, password);

            //Create Role Admin if it does not exist
            if (!RoleManager.RoleExists(name))
            {
                var roleresult = RoleManager.Create(new IdentityRole(name));
            }

            //Create User=Admin with password=123456
            var user = new AppUserIdentity();
            user.UserName = name;
            user.Domain = "ITEEDEE";
            user.FirstName = "Admin User";
            var adminresult = UserManager.Create(user, password);

            //Add User Admin to Role Admin
            if (adminresult.Succeeded)
            {
                var result = UserManager.AddToRole(user.Id, name);
            }
        }
    }
}