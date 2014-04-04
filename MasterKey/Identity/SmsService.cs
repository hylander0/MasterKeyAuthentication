using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace MasterKey.Identity
{
    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your sms service here to send a text message.
            //You need to make sure your google account is signed up 
            SharpVoice.Voice v = new SharpVoice.Voice("YourAccount@gmail.com", "YourPassword");
            v.SendSMS(message.Destination, message.Body);
            return Task.FromResult(0);
        }
    }
}