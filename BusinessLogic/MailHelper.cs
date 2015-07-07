using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net.Mail;

namespace wasAssign3.BusinessLogic
{
    public class MailHelper
    {
        //class recieves message, email address and subject from controller
        public void EmailFromArvixe(string message, string to, string subject) 
        {
            
            // Set mail account credentials
            const string FROM        = "noreply@confirmation.samnew-portfolio.com"; 
            const string FROM_PWD    = "";                
            const bool   USE_HTML    = true;
            const string SMTP_SERVER = "mail.samnew-portfolio.com.BROWN.mysitehosted.com";
            //create email object
                MailMessage mailMsg  = new MailMessage(FROM, to);
                mailMsg.Subject      = subject;
                mailMsg.Body         = message;
                mailMsg.IsBodyHtml   = USE_HTML;
            
            // Connect to mail server
                SmtpClient smtp      = new SmtpClient();
                smtp.Port            = 25;
                smtp.Host            = SMTP_SERVER;
                smtp.Credentials     = new System.Net.NetworkCredential(FROM, FROM_PWD);
            //send email
                smtp.Send(mailMsg);
        }

    }
}