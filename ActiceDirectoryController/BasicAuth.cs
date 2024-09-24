using System.DirectoryServices;
using System.Reflection.PortableExecutable;
using DirectoryEntry = System.DirectoryServices.DirectoryEntry;

public class BasicAuth
{
    public static bool AuthenticateUser(string ldapPath, string username, string password)
    {
        try
        {
            using (DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password))
            {
                // Force authentication by binding to the native AdsObject.
                object nativeObject = entry.NativeObject;

                using (DirectorySearcher searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(sAMAccountName={username})";
                    searcher.PropertiesToLoad.Add("cn");

                    SearchResult? result = searcher.FindOne();

                    if (result != null)
                    {
                        Console.WriteLine($"User {username} found: {result.Properties["cn"][0]}");
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"User {username} not found.");
                        return false;
                    }
                }
            }
        }
        catch (DirectoryServicesCOMException ex)
        {
            Console.WriteLine($"DirectoryServicesCOMException: {ex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Unexpected error: {ex.Message}");
            return false;
        }
    }
}