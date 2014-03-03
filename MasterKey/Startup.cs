using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(MasterKey.Startup))]
namespace MasterKey
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
