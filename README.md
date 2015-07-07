# sampleAccountCreation
This app simulates account registration, user login, and password reset, using C#, ASP.NET, and MVC 5

A hosted sample of this app can be seen at http://confirmation.samnew-portfolio.com/

This app was created for an ASP.NET/web app security class assignment.

It allows users to register an account, confirm account registration through email, login to private pages, and reset password through email if forgotten.

It leverages ASP.NET's built in User models and methods to easily create accounts, hash passwords, and enable simple user validation

It contains methods that create users in the database, set up account restrictions like account lock out on failed log in attempt, a mailer class that sends tokens that allows users to confirm account registration or password reset.

The view pages utilize razor syntax to set role restrictions, causing different content and menu optionsto be displayed depending when a user is or isn't logged in 

The forms and models have various requirements forcing certain input such as a regex for email during user registration

Twitter Bootstrap was used as a style template, this also allows for mobile responsiveness

Main code is contained in the BusinessLogic, Controllers, ViewModels, and Views folders, as well as Startup1.csin the root folder, several lines that contained DB and email server credentials have been rempved for security
