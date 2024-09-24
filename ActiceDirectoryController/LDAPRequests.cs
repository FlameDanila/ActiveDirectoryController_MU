using System.DirectoryServices.Protocols;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Text;
using System;
using System.Configuration;
using System.Collections.Specialized;
using System.Linq;
using Microsoft.Extensions.Primitives;
using System.Collections;
using System.DirectoryServices;
using System.Security.Principal;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;

namespace ActiveDirectoryController
{
    public class LDAPRequests
    {
        private static string? ldapServer = System.Configuration.ConfigurationManager.AppSettings.Get("ldapServer");
        public static List<ADUser>? GetUsersList(string ldapUsername, string ldapPassword, out string? ldapError, out int counter)
        {
            //Main2();
            ldapUsername = "TMN\\" + ldapUsername;
            // Укажите учетные данные для подключения к серверу

            // Создайте объект LdapDirectoryIdentifier для указания сервера и порта
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ldapServer);

            // Создайте объект NetworkCredential для указания учетных данных
            NetworkCredential credential = new NetworkCredential(ldapUsername, ldapPassword);

            // Создайте соединение с сервером LDAP
            LdapConnection connection = new LdapConnection(identifier, credential)
            {
                AuthType = AuthType.Basic // Укажите тип аутентификации
            };

            try
            {
                counter = 0;

                // Создайте запрос LDAP
                string searchBase = "DC=tmn,DC=martinural,DC=ru"; // Базовый DN для поиска
                string searchFilter = $"(objectClass=user)"; // Фильтр поиска

                SearchRequest request = new SearchRequest(
                    searchBase, // Базовый DN
                    searchFilter, // Фильтр поиска
                    System.DirectoryServices.Protocols.SearchScope.Subtree, // Область поиска
                    ["sAMAccountName", "CN"] // Атрибуты для выборки (null означает выбрать все атрибуты)
                );

                // Отправьте запрос
                SearchResponse response = (SearchResponse)connection.SendRequest(request);

                // Обработайте результат
                if (response.Entries.Count != 0)
                {
                    List<ADUser> listADUsers = new List<ADUser>();
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        ADUser _aDUser = new ADUser();
                        if (entry.Attributes.Contains("sAMAccountName"))
                        {
                            _aDUser.sAMAccountName = GetStringFromAttribute(entry.Attributes["sAMAccountName"][0]);
                        }

                        if (entry.Attributes.Contains("cn"))
                        {
                            _aDUser.cName = GetStringFromAttribute(entry.Attributes["cn"][0]);
                        }
                        listADUsers.Add(_aDUser);
                        counter++;
                    }
                    ldapError = null;
                    return listADUsers;
                }
                else
                {
                    ldapError = null;
                    return null;
                }
            }
            catch (LdapException ex)
            {
                ldapError = $"LDAP Error: {ex.Message}"; counter = 0; return null; 
            }
        }
        public static String? GetUserName(string? cName, string ldapUsername, string ldapPassword, out string? ldapError)
        {

            ldapUsername = "TMN\\" + ldapUsername;
            // Укажите учетные данные для подключения к серверу

            // Создайте объект LdapDirectoryIdentifier для указания сервера и порта
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ldapServer);

            // Создайте объект NetworkCredential для указания учетных данных
            NetworkCredential credential = new NetworkCredential(ldapUsername, ldapPassword);

            // Создайте соединение с сервером LDAP
            LdapConnection connection = new LdapConnection(identifier, credential)
            {
                AuthType = AuthType.Basic // Укажите тип аутентификации
            };

            try
            {
                // Создайте запрос LDAP
                string searchBase = "DC=tmn,DC=martinural,DC=ru"; // Базовый DN для поиска
                string searchFilter = $"(&(cn=*{cName}*)(objectClass=user))"; // Фильтр поиска

                SearchRequest request = new SearchRequest(
                    searchBase, // Базовый DN
                    searchFilter, // Фильтр поиска
                    System.DirectoryServices.Protocols.SearchScope.Subtree, // Область поиска
                    ["sAMAccountName"] // Атрибуты для выборки (null означает выбрать все атрибуты)
                );

                // Отправьте запрос
                SearchResponse response = (SearchResponse)connection.SendRequest(request);

                // Обработайте результат
                foreach (SearchResultEntry entry in response.Entries)
                {
                    if (entry.Attributes.Contains("sAMAccountName"))
                    {
                        string stringValue = GetStringFromAttribute(entry.Attributes["sAMAccountName"][0]);

                        ldapError = null;
                        return stringValue;
                    }
                    else
                    {
                        ldapError = "sAMAccountName not found for this name.";
                        return null;
                    }
                }
                ldapError = "Login undefined.";
                return null;
            }
            catch (LdapException ex)
            {
                ldapError = $"LDAP Error: {ex.Message}";
                return null;
            }
        }
        public static bool DisableUserAccount(string? samAccountName, string ldapUsername, string ldapPassword, out string? ldapError)
        {
            try
            {
                ldapUsername = "TMN\\" + ldapUsername;

                LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ldapServer);
                NetworkCredential credential = new NetworkCredential(ldapUsername, ldapPassword);

                using (var connection = new LdapConnection(identifier, credential))
                {
                    connection.AuthType = AuthType.Basic;

                    string searchBase = "DC=tmn,DC=martinural,DC=ru";
                    string searchFilter = $"(sAMAccountName={samAccountName})";

                    SearchRequest searchRequest = new SearchRequest(
                        searchBase, searchFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, null);

                    SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                    if (searchResponse.Entries.Count == 0)
                    {
                        throw new Exception("User not found");
                    }

                    string userDn = searchResponse.Entries[0].DistinguishedName;

                    // Получение текущего значения userAccountControl
                    int userAccountControl = Convert.ToInt32(searchResponse.Entries[0].Attributes["userAccountControl"][0]);
                    int ADS_UF_ACCOUNTDISABLE = 0x0002;

                    // Установка флага отключения
                    userAccountControl |= ADS_UF_ACCOUNTDISABLE;

                    // Создание модификации
                    DirectoryAttributeModification modification = new DirectoryAttributeModification
                    {
                        Operation = DirectoryAttributeOperation.Replace,
                        Name = "userAccountControl"
                    };
                    modification.Add(userAccountControl.ToString());

                    ModifyRequest modifyRequest = new ModifyRequest(userDn, modification);
                    connection.SendRequest(modifyRequest);

                    ldapError = "";
                    return true;
                }
            }
            catch (LdapException ex)
            {
                ldapError = $"Произошла ошибка LDAP: {ex.Message}";
                return false;
            }
            catch (Exception ex)
            {
                ldapError = $"Произошла ошибка: {ex.Message}";
                return false;
            }
        }
        public static bool EnableUserAccount(string? samAccountName, string ldapUsername, string ldapPassword)
        {
            try
            {
                ldapUsername = "TMN\\" + ldapUsername;

                LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ldapServer);
                NetworkCredential credential = new NetworkCredential(ldapUsername, ldapPassword);

                using (var connection = new LdapConnection(identifier, credential))
                {
                    connection.AuthType = AuthType.Basic;

                    string searchBase = "DC=tmn,DC=martinural,DC=ru";
                    string searchFilter = $"(sAMAccountName={samAccountName})";

                    SearchRequest searchRequest = new SearchRequest(
                        searchBase, searchFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, new string[] { "userAccountControl" });

                    SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                    if (searchResponse.Entries.Count == 0)
                    {
                        throw new Exception("User not found");
                    }

                    string userDn = searchResponse.Entries[0].DistinguishedName;
                    int userAccountControl = Convert.ToInt32(searchResponse.Entries[0].Attributes["userAccountControl"][0]);
                    int ADS_UF_ACCOUNTDISABLE = 0x0002;
                    userAccountControl &= ~ADS_UF_ACCOUNTDISABLE;

                    DirectoryAttributeModification modification = new DirectoryAttributeModification
                    {
                        Operation = DirectoryAttributeOperation.Replace,
                        Name = "userAccountControl"
                    };
                    modification.Add(userAccountControl.ToString());

                    ModifyRequest modifyRequest = new ModifyRequest(userDn, modification);
                    connection.SendRequest(modifyRequest);

                    return true;
                }
            }
            catch (LdapException ex)
            {
                Console.WriteLine($"Произошла ошибка LDAP: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Произошла ошибка: {ex.Message}");
                return false;
            }
        }
        public static bool CreateUser(string ldapUsername, string ldapPassword, ADUser newUser, out string? ldapError)
        {
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ldapServer);
            NetworkCredential credential = new NetworkCredential(ldapUsername, ldapPassword, "TMN");
            LdapConnection connection = new LdapConnection(identifier, credential);
            //if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            //{
            //    throw new UnauthorizedAccessException("The current user does not have administrative rights.");
            //}

            try
            {
                // Создайте объект для нового пользователя
                string userDn = $"CN={newUser.cName},{newUser.OrganizationalUnitDN}";
                var request = new AddRequest(userDn,
                    new DirectoryAttribute("objectClass", "user"),
                    new DirectoryAttribute("sAMAccountName", newUser.sAMAccountName),
                    new DirectoryAttribute("userPrincipalName", $"{newUser.sAMAccountName}@tmn.martinural.ru"),
                    new DirectoryAttribute("givenName", newUser.FirstName),
                    new DirectoryAttribute("sn", newUser.LastName),
                    new DirectoryAttribute("displayName", newUser.DisplayName),
                    new DirectoryAttribute("mail", newUser.Email),
                    new DirectoryAttribute("description", "z")
                );
                connection.SendRequest(request);
                connection.Dispose();

                EnableUserAccount(newUser.sAMAccountName, ldapUsername, ldapPassword);
                //ChangeUserPassword(ldapUsername, ldapPassword, userDn, newUser.Password, out ldapError);
                ManageUserAccount(userDn, newUser.Password, out ldapError);
                //UnlockUserAccount(userDn, connection);
                //ClearPasswordChangeAtNextLogon(userDn, connection);
                //SetPasswordNeverExpires(userDn, connection);

                ldapError = null;
                return true;
            }
            catch (DirectoryOperationException ex)
            {
                // Обработка ошибки, когда объект уже существует
                if (ex.Message.Contains("00000524") && ex.Message.Contains("ENTRY_EXISTS"))
                {
                    ldapError = "Ошибка: Пользователь уже существует.";
                }
                else
                {
                    ldapError = $"LDAP Error: {ex.Message}";
                }
                return false;
            }
            catch (LdapException ex)
            {
                ldapError = $"LDAP Error: {ex.Message} {ex.ToString()}";
                return false;
            }
        }
        public static bool DeleteUser(string ldapUsername, string ldapPassword, string userDn, out string? ldapError)
        {
            ldapUsername = "TMN\\" + ldapUsername;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(ldapServer);
            NetworkCredential credential = new NetworkCredential(ldapUsername, ldapPassword);
            LdapConnection connection = new LdapConnection(identifier, credential)
            {
                AuthType = AuthType.Basic
            };

            try
            {
                // Создайте запрос на удаление пользователя
                var request = new DeleteRequest(userDn);

                // Отправьте запрос
                connection.SendRequest(request);

                ldapError = null;
                return true;
            }
            catch (LdapException ex)
            {
                ldapError = $"LDAP Error: {ex.Message}";
                return false;
            }
        }
        public static bool ChangeUserPassword(string ldapUsername, string ldapPassword, string userDn, string newPassword, out string ldapError)
        {
            ldapError = string.Empty;

            try
            {
                // Подключение к LDAP серверу с использованием SSL
                var identifier = new LdapDirectoryIdentifier(ldapServer);
                var credential = new NetworkCredential(ldapUsername, ldapPassword);
                using var connection = new LdapConnection(identifier, credential)
                {
                    AuthType = AuthType.Basic
                };

                // Устанавливаем Secure Socket Layer (SSL)
                connection.SessionOptions.SecureSocketLayer = true;
                connection.SessionOptions.VerifyServerCertificate += (sender, certificate) => true;

                // Формирование строки пароля в формате Unicode и заключение в двойные кавычки
                string unicodePwd = $"\"{newPassword}\"";
                byte[] unicodePwdBytes = Encoding.Unicode.GetBytes(unicodePwd);

                // Создание ModifyRequest для изменения пароля
                var modifyPasswordRequest = new ModifyRequest(
                    userDn,
                    DirectoryAttributeOperation.Replace,
                    "unicodePwd",
                    unicodePwdBytes
                );

                // Отправка запроса
                connection.SendRequest(modifyPasswordRequest);
                return true;
            }
            catch (Exception ex)
            {
                ldapError = $"LDAP Error: {ex.Message}";
                return false;
            }
        }
        public static void UnlockUserAccount(string userDn, LdapConnection connection)
        {
            // Получение текущего значения userAccountControl
            var searchRequest = new SearchRequest(userDn, "(objectClass=user)", System.DirectoryServices.Protocols.SearchScope.Base, "userAccountControl");
            var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            int userAccountControl = Convert.ToInt32(searchResponse.Entries[0].Attributes["userAccountControl"][0]);
            int ADS_UF_LOCKOUT = 0x0010;

            // Снимаем флаг блокировки
            userAccountControl &= ~ADS_UF_LOCKOUT;

            // Создаем и отправляем запрос на изменение
            var modifyRequest = new ModifyRequest(
                userDn,
                DirectoryAttributeOperation.Replace,
                "userAccountControl",
                userAccountControl.ToString()
            );
            connection.SendRequest(modifyRequest);
        }
        public static void ClearPasswordChangeAtNextLogon(string userDn, LdapConnection connection)
        {
            // Получение текущего значения userAccountControl
            var searchRequest = new SearchRequest(userDn, "(objectClass=user)", System.DirectoryServices.Protocols.SearchScope.Base, "userAccountControl");
            var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            int userAccountControl = Convert.ToInt32(searchResponse.Entries[0].Attributes["userAccountControl"][0]);
            int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;
            int ADS_UF_PASSWORD_EXPIRED = 0x800000;

            // Снимаем флаг требуемой смены пароля и устанавливаем флаг неограниченного срока действия пароля
            userAccountControl &= ~ADS_UF_PASSWORD_EXPIRED;
            userAccountControl |= ADS_UF_DONT_EXPIRE_PASSWD;

            // Создаем и отправляем запрос на изменение
            var modifyRequest = new ModifyRequest(
                userDn,
                DirectoryAttributeOperation.Replace,
                "userAccountControl",
                userAccountControl.ToString()
            );
            connection.SendRequest(modifyRequest);
        }
        public static void SetPasswordNeverExpires(string userDn, LdapConnection connection)
        {
            // Получение текущего значения userAccountControl
            var searchRequest = new SearchRequest(userDn, "(objectClass=user)", System.DirectoryServices.Protocols.SearchScope.Base, "userAccountControl");
            var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

            int userAccountControl = Convert.ToInt32(searchResponse.Entries[0].Attributes["userAccountControl"][0]);
            int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;

            // Устанавливаем флаг неограниченного срока действия пароля
            userAccountControl |= ADS_UF_DONT_EXPIRE_PASSWD;

            // Создаем и отправляем запрос на изменение
            var modifyRequest = new ModifyRequest(
                userDn,
                DirectoryAttributeOperation.Replace,
                "userAccountControl",
                userAccountControl.ToString()
            );
            connection.SendRequest(modifyRequest);
        }
        private static string GetStringFromAttribute(object attribute)
        {
            if (attribute is byte[] byteArray)
            {
                return Encoding.GetEncoding("Windows-1251").GetString(byteArray);
            }
            return attribute.ToString();
        }
        public static List<ADUser>? GetGroupUsers(string groupName, string objectClass, string ldapUsername, string ldapPassword, out string? ldapError, out int counter)
        {
            counter = 0;
            string searchBase = "DC=tmn,DC=martinural,DC=ru";

            using (DirectoryEntry entry = new DirectoryEntry($"LDAP://{searchBase}"))
            {
                using (DirectorySearcher searcher = new DirectorySearcher(entry))
                {
                    searcher.Filter = $"(&(objectClass={objectClass})(cn={groupName}))";
                    searcher.PropertiesToLoad.Add("member");

                    SearchResult? result = searcher.FindOne();
                    if (result != null)
                    {
                        List<ADUser> requiredParameters = new List<ADUser>();

                        foreach (string dn in result.Properties["member"])
                        {
                            counter++;
                            using (DirectoryEntry memberEntry = new DirectoryEntry($"LDAP://{dn}"))
                            {
                                ADUser members = new ADUser()
                                {
                                    sAMAccountName = memberEntry.Properties["sAMAccountName"][0].ToString()
                                };
                                requiredParameters.Add(members);
                            }
                        }
                        ldapError = "";
                        return requiredParameters;
                    }
                    else
                    {
                        ldapError = "Group not found.";
                        return null;
                    }
                }
            }
        }
        public static bool GetGroupType(string ldapUsername, string ldapPassword, string groupCn, out string groupInfo, out string ldapError)
        {
            ldapError = string.Empty;
            groupInfo = string.Empty;

            try
            {
                // Подключение к LDAP серверу
                var identifier = new LdapDirectoryIdentifier(ldapServer);
                var credential = new NetworkCredential(ldapUsername, ldapPassword);
                using var connection = new LdapConnection(identifier, credential)
                {
                    AuthType = AuthType.Basic
                };

                // Поиск группы по CN
                var searchFilter = $"(&(objectClass=group)(cn={groupCn}))";
                var searchRequest = new SearchRequest(
                    null,
                    searchFilter,
                    System.DirectoryServices.Protocols.SearchScope.Subtree,
                    null // можно указать конкретные атрибуты для поиска
                );

                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                {
                    ldapError = $"Группа с CN '{groupCn}' не найдена.";
                    return false;
                }

                var groupEntry = searchResponse.Entries[0];

                // Формирование информации о группе
                var groupDetails = new StringBuilder();
                foreach (DirectoryAttribute attr in groupEntry.Attributes.Values)
                {
                    foreach (var value in attr)
                    {
                        groupDetails.AppendLine($"{attr.Name}: {value}");
                    }
                }

                groupInfo = groupDetails.ToString();
                return true;
            }
            catch (Exception ex)
            {
                ldapError = $"LDAP Error: {ex.Message}";
                return false;
            }
        }
        public static bool ManageUserAccount(string username, string newPassword, out string error)
        {
            error = string.Empty;

            try
            {
                // Подключаемся к домену, используя контекст PrincipalContext
                using (var context = new PrincipalContext(ContextType.Domain))
                {
                    // Находим пользователя в домене по имени пользователя
                    using (var user = UserPrincipal.FindByIdentity(context, username))
                    {
                        if (user == null)
                        {
                            error = "Пользователь не найден.";
                            return false;
                        }
                        error += "1";
                        // Меняем пароль
                        user.SetPassword(newPassword);

                        error += "2";
                        // Сбрасываем флаг "Требовать смены пароля при следующем входе в систему"
                        user.PasswordNeverExpires = true;
                        error += "3";
                        user.UserCannotChangePassword = false;
                        error += "4";
                        user.ExpirePasswordNow();

                        error += "5";
                        // Сохраняем изменения
                        user.Save();
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                error += "6";
                error = $"Ошибка управления учетной записью: {ex.Message}";
                return false;
            }
        }
    }
    public class ADUser
    {
        public string? sAMAccountName { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? cName { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? FirstName { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? LastName { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? DisplayName { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Email { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Password { get; set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? OrganizationalUnitDN { get; set; } // DN организационного подразделения, где будет создан пользователь
    }
}