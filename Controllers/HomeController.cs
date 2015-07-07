using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataProtection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using wasAssign3.ViewModels;
using wasAssign3.BusinessLogic;

namespace wasAssign3.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        [HttpGet]
        public ActionResult Index()
        {
            //load homepage view
            return View();
        }
        [HttpPost]
        public ActionResult Index(Login login)
        {
            // UserStore and UserManager manages data retreival.
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            IdentityUser identityUser = manager.Find(login.UserName,
                                                             login.Password);
            //when user logs in checks model requirements to ensure valid input
            if (ModelState.IsValid)
            {
                //calls method to check valid credentials
                if (ValidLogin(login)) 
                {
                    //if credentials are valid retrieve user identity from database
                    IAuthenticationManager authenticationManager
                                           = HttpContext.GetOwinContext().Authentication;
                    authenticationManager
                   .SignOut(DefaultAuthenticationTypes.ExternalCookie);

                    var identity = new ClaimsIdentity(new[] {
                                            new Claim(ClaimTypes.Name, login.UserName),
                                        },
                                        DefaultAuthenticationTypes.ApplicationCookie,
                                        ClaimTypes.Name, ClaimTypes.Role);
                    // SignIn() accepts ClaimsIdentity and issues logged in cookie. 
                    authenticationManager.SignIn(new AuthenticationProperties
                    {
                        IsPersistent = false
                    }, identity);
                    return RedirectToAction("SecureArea", "Home");
                }
            }
            return View();
        }
        [HttpGet]
        public ActionResult Register()
        {
            //load registration page view
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisteredUser newUser)
        {
            //when user registers in checks model requirements to ensure valid input
            if (ModelState.IsValid)
            {
                CaptchaHelper captchaHelper = new CaptchaHelper();
                string captchaResponse = captchaHelper.CheckRecaptcha();
                ViewBag.CaptchaResponse = captchaResponse;

                // add user to database, lock account until email confirmation
                var userStore = new UserStore<IdentityUser>();
                UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore)
                {
                    //set account to lock after consecutive failed login attempts
                    UserLockoutEnabledByDefault = true,
                    DefaultAccountLockoutTimeSpan = new TimeSpan(0, 10, 0),
                    MaxFailedAccessAttemptsBeforeLockout = 3
                };
                
                var identityUser = new IdentityUser()
                {
                    UserName = newUser.UserName,
                    Email = newUser.Email
                };
                IdentityResult result = manager.Create(identityUser, newUser.Password);

                if (result.Succeeded)
                {
                    samUserRegEntities context = new samUserRegEntities();
                    AspNetUser user = context.AspNetUsers
                        .Where(u => u.UserName == newUser.UserName).FirstOrDefault();
                    AspNetRole role = context.AspNetRoles
                        .Where(r => r.Name == "registered").FirstOrDefault();

                    user.AspNetRoles.Add(role);
                    context.SaveChanges();
                    
                    //creates token to be passed to mail helper to allow email confirmation
                    CreateToken ct = new CreateToken();
                    CreateTokenProvider(manager, EMAIL_CONFIRMATION);


                    var code = manager.GenerateEmailConfirmationToken(identityUser.Id);
                    var callbackUrl = Url.Action("ConfirmEmail", "Home",
                                                    new { userId = identityUser.Id, code = code },
                                                        protocol: Request.Url.Scheme);
                    //send callbackURL to email helper
                    MailHelper mailer = new MailHelper();
                    string email = "Please confirm your account by clicking this link: <a href=\""
                                    + callbackUrl + "\">Confirm Registration</a>";
                    string subject = "Please confirm your email";
                    //try
                    //{
                        mailer.EmailFromArvixe(email, identityUser.Email, subject);
                        ViewBag.FakeConfirmation =
                            "An account confirmation has been sent to your email, please confirm before attempting to login";
                    //}
                    //catch (System.Exception ex)
                    //{
                    //    ViewBag.FakeConfirmation = ex.Message;
                    //}

                }
            }
            return View();
        }
        [Authorize(Roles = "registered")]
        public ActionResult SecureArea()
        {
            return View();
        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authenticationManager = ctx.Authentication;
            authenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        bool ValidLogin(Login login)
        {
            //gets user identity details
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> userManager = new UserManager<IdentityUser>(userStore)
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = new TimeSpan(0, 10, 0),
                MaxFailedAccessAttemptsBeforeLockout = 3
            };
            var user = userManager.FindByName(login.UserName);

            if (user == null)
                return false;

            // User is locked out.
            if (userManager.SupportsUserLockout && userManager.IsLockedOut(user.Id))
                return false;

            // Validated user was locked out but now can be reset.
            if (userManager.CheckPassword(user, login.Password)
                && userManager.IsEmailConfirmed(user.Id))

            {
                if (userManager.SupportsUserLockout
                 && userManager.GetAccessFailedCount(user.Id) > 0)
                {
                    userManager.ResetAccessFailedCount(user.Id);
                }
            }
            // Login is invalid so increment failed attempts.
            else
            {
                bool lockoutEnabled = userManager.GetLockoutEnabled(user.Id);
                if (userManager.SupportsUserLockout && userManager.GetLockoutEnabled(user.Id))
                {
                    userManager.AccessFailed(user.Id);
                    return false;
                }
            }
            return true;
        }
        const string EMAIL_CONFIRMATION = "EmailConfirmation";
        const string PASSWORD_RESET = "ResetPassword";

        //calls method from confirmation email
        public ActionResult ConfirmEmail(string userID, string code)
        {
            //confirms user and unlocks account
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            CreateToken ct = new CreateToken();
            CreateTokenProvider(manager, EMAIL_CONFIRMATION);
            try
            {
                IdentityResult result = manager.ConfirmEmail(userID, code);
                if (result.Succeeded)
                    ViewBag.Message = "You are now registered!";
            }
            catch
            {
                ViewBag.Message = "Validation attempt failed!";
            }
            return View();
        }

        [HttpGet]
        public ActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ForgotPassword(string email)
        {
            //ensures valid input
            if (ModelState.IsValid)
            {
                CaptchaHelper captchaHelper = new CaptchaHelper();
                string captchaResponse = captchaHelper.CheckRecaptcha();
                ViewBag.CaptchaResponse = captchaResponse;

                //creates token to be sent to mail helper to allow password reset through email
                var userStore = new UserStore<IdentityUser>();
                UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
                var user = manager.FindByEmail(email);
                CreateToken ct = new CreateToken();
                CreateTokenProvider(manager, PASSWORD_RESET);

                var code = manager.GeneratePasswordResetToken(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Home",
                                             new { userId = user.Id, code = code },
                                             protocol: Request.Url.Scheme);

                //send callbackUrl to email helper
                MailHelper mailer = new MailHelper();
                string message = "Please reset your password by clicking <a href=\""
                                         + callbackUrl + "\">here</a>";
                string subject = "Please reset your password";
                try
                {
                    mailer.EmailFromArvixe(message, user.Email, subject);
                    ViewBag.FakeEmailMessage =
                        "You have been sent an email to finish reseting your password";
                }
                catch (System.Exception ex)
                {
                    ViewBag.FakeEmailMessage = ex.Message;
                }
            }
            return View();
        }

        [HttpGet]
        public ActionResult ResetPassword(string userID, string code)
        {
            ViewBag.PasswordToken = code;
            ViewBag.UserID = userID;
            return View();
        }
        [HttpPost]
        public ActionResult ResetPassword(string password, string passwordConfirm,
                                          string passwordToken, string userID)
        {
            //called from email link, receives token and allows user to change password
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            CreateToken ct = new CreateToken();
            CreateTokenProvider(manager, PASSWORD_RESET);

            IdentityResult result = manager.ResetPassword(userID, passwordToken, password);
            if (result.Succeeded)
                ViewBag.Result = "The password has been reset.";
            else
                ViewBag.Result = "The password has not been reset.";
            return View();
        }
        //method that generates random tokens for email confirmation and password reset
        public void CreateTokenProvider(UserManager<IdentityUser> manager, string tokenType)
        {
            manager.UserTokenProvider = new EmailTokenProvider<IdentityUser>();
        }

        [HttpGet]
        public ActionResult AddRole()
        {
            return View();
        }
        //method to allow new role creation ie Admin, user
        [HttpPost]
        public ActionResult AddRole(AspNetRole role)
        {
            var roleStore = new RoleStore<IdentityRole>();
            var manager = new RoleManager<IdentityRole>(roleStore);
            var identityRole = new IdentityRole()
            { 
                Name = role.Name
            };
            IdentityResult result = manager.Create(identityRole);
            return View();
        }


    }
}