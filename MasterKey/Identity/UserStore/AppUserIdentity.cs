using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace MasterKey.Identity.UserStore
{
    public class AppUserIdentity : IdentityUser
    {
        public string Domain { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string TimezoneOffSetInMinutes { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<AppUserIdentity> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }



    public class AppUserIdentityDbContext : IdentityDbContext<AppUserIdentity>
    {
        public AppUserIdentityDbContext()
            : base("AppUserIdentityDbContext")
        {
        }

        public static AppUserIdentityDbContext Create()
        {
            return new AppUserIdentityDbContext();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Change the name of the table to be Users instead of AspNetUsers
            modelBuilder.Entity<IdentityUser>()
                .ToTable("Users");
            modelBuilder.Entity<AppUserIdentity>()
                .ToTable("Users");
        }

    }
}