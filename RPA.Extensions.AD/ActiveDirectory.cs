using System;
using System.DirectoryServices;

namespace RPA.Extensions.AD
{
    public class ActiveDirectory
    {
        public string SetPasswordByAdmin(string ldapPath, string adminUsername, string adminPassword, string searchUserBy, string searchValue, string newPassword)
        {
            // string path = "domain-AD-CA/DC=domain,DC=com";
            //string path = ldapPath;// "AD.domain.com";
            try
            {
                using (var entry = new DirectoryEntry($"LDAP://{ldapPath}:636", adminUsername, adminPassword, AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure))
                {
                    using (var searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = $"(&(objectClass=user)({searchUserBy}={searchValue}*))";
                        SearchResult result = searcher.FindOne();
                        if (result != null)
                        {
                            var userEntry = result.GetDirectoryEntry();
                            if (userEntry != null)
                            {
                                userEntry.Invoke("SetPassword", new object[] { newPassword });
                                userEntry.CommitChanges();
                                return "Password Reset Successful";
                            }
                            else
                            {
                                return $"Cannot find the user with {searchUserBy} as {searchValue}";
                            }
                        }
                        else
                        {
                            return $"Cannot find the user with {searchUserBy} as {searchValue}";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return ex.GetBaseException().ToString();
            }
        }

        public static string UpdateUserMustChangePassword(string ldapPath, string adminUsername, string adminPassword, string searchUserBy, string searchValue)
        {
            try
            {
                using (var entry = new DirectoryEntry($"LDAP://{ldapPath}:636", adminUsername, adminPassword, AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure))
                {
                    using (var searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = $"(&(objectClass=user)({searchUserBy}={searchValue}*))";
                        SearchResult result = searcher.FindOne();
                        if (result != null)
                        {
                            var userEntry = result.GetDirectoryEntry();
                            if (userEntry != null)
                            {
                                //Modifications to Pwd-Last-Set attribute #
                                //The only values that can be set are:
                                    //  0 -> To set "User Must Change Password at Next Logon", set the pwdLastSet attribute to zero(0). This is as if the Pwd-Last-Set attribute = True - which is an implementation of Password MUST Change condition.
                                    // -1 -> setting the Pwd-Last-Set attribute attribute to - 1 which will effectively set the Pwd-Last-Set attribute to the current time and remove the "User Must Change Password at Next Logon" restriction.
                                    // The Pwd-Last - Set attribute attribute cannot be set to any other values except by the system.
                                userEntry.Properties["pwdLastSet"][0] = -1;
                                userEntry.CommitChanges();
                                return "Updated User must change password";
                           
                            }
                            else
                            {
                                return $"Cannot find the user with {searchUserBy} as {searchValue}";
                            }
                        }
                        else
                        {
                            return $"Cannot find the user with {searchUserBy} as {searchValue}";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return ex.GetBaseException().ToString();
            }
        }


    }
}
