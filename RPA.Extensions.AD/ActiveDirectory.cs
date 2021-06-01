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

        public static string UpdateUserMustChangePassword(string ldapPath, string adminUsername, string adminPassword, string userEmail)
        {
            try
            {
                using (var entry = new DirectoryEntry($"LDAP://{ldapPath}:636", adminUsername, adminPassword, AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure))
                {
                    using (var searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = $"(&(objectClass=user)(mail={userEmail}*))";
                        SearchResult result = searcher.FindOne();
                        if (result != null)
                        {
                            var userEntry = result.GetDirectoryEntry();
                            if (userEntry != null)
                            {
                                userEntry.Properties["pwdLastSet"][0] = 0;
                                userEntry.CommitChanges();
                                return "Updated User must change password";
                           
                            }
                            else
                            {
                                return $"Cannot find the user with Email as {userEmail}";
                            }
                        }
                        else
                        {
                            return $"Cannot find the user with Email as {userEmail}";
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
