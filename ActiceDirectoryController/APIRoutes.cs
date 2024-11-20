using ActiveDirectoryController;
using Microsoft.AspNet.Identity;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Ldap = System.DirectoryServices.Protocols;

internal class APIRoutes
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                //webBuilder.UseKestrel(options =>
                //{
                //    options.ListenAnyIP(4040); // ��������� ����� Kestrel
                //});
                webBuilder.UseIISIntegration();
                webBuilder.UseStartup<Startup>(); // ��������� Startup �����
            });
}
[Authorize]
public class Startup
{
    private static string? ldapServer = System.Configuration.ConfigurationManager.AppSettings.Get("ldapServer");

    // ������������ ����� ConfigureServices
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme);
        services.AddAuthorization();
    }

    // ������������ ����� Configure
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        app.UseRouting();
        app.UseAuthentication(); // Middleware ��� ��������������
        app.UseAuthorization();  // Middleware ��� �����������

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/testAuth", async context =>
            {
                if (context.User.Identity?.IsAuthenticated == true)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? name = queryParameters["name"];

                        if (name != null) // �������� name �� ����
                        {
                            string? ldapErrorResponce = "";
                            //string? userName = LDAPRequests.GetUserName(name, isAuth[0], isAuth[1], out ldapErrorResponce); // ���������� ������������ � ldap
                            string? userName = LDAPRequests.GetUserName(name, out ldapErrorResponce); // ���������� ������������ � ldap
                            if (userName != null)
                            {
                                userName = $"{{\"sAMAccountName\":\"{userName}\"}}";

                                await context.Response.WriteAsync(userName);
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'name' is missing or null!\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'name' is missing or null!\"}}"); }

                }
                else
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("{\"Error\": \"��������� ��������������\"}");
                }
            });
            endpoints.MapGet("/ListADUsers", async (context) =>
            {
                //string[] isAuth = await AurhorizeRequestUser(context);
                //if (isAuth != null)
                //{
                    context.Response.ContentType = "application/json";
                    string? ldapErrorResponce = "";
                    int counter = 0;
                    List<ADUser>? userName = LDAPRequests.GetUsersList("oda", "Qwe123456", out ldapErrorResponce, out counter); // ���������� ������������ � ldap
                    if (ldapErrorResponce == null)
                    {
                        if (userName != null)
                        {
                            string jsonString = System.Text.Json.JsonSerializer.Serialize(userName, new JsonSerializerOptions { WriteIndented = true });
                            jsonString = "{\"Users\": " + jsonString + ", \"Total\": " + counter + "}";

                            await context.Response.WriteAsync(jsonString);
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Users not found\"}}"); }
                    }
                    else
                    { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                //}
            });
            endpoints.MapGet("/GetAdUser", async (context) =>
            {
                //string[] isAuth = await AurhorizeRequestUser(context);

                //if (isAuth != null)
                //{
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? name = queryParameters["name"];

                        if (name != null) // �������� name �� ����
                        {
                            string? ldapErrorResponce = "";
                            //string? userName = LDAPRequests.GetUserName(name, isAuth[0], isAuth[1], out ldapErrorResponce); // ���������� ������������ � ldap
                            string? userName = LDAPRequests.GetUserName(name, "oda", "Qwe123456", out ldapErrorResponce); // ���������� ������������ � ldap
                            if (userName != null)
                            {
                                userName = $"{{\"sAMAccountName\":\"{userName}\"}}";

                                await context.Response.WriteAsync(userName);
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'name' is missing or null!\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'name' is missing or null!\"}}"); }
                //}
            });
            endpoints.MapPost("/DeactivateADUser", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? name = queryParameters["name"];
                        string? sAMAccountName = queryParameters["sAMAccountName"];

                        if (sAMAccountName != null)
                        {
                            string? ldapErrorResponce = "";
                            bool disable = LDAPRequests.DisableUserAccount(sAMAccountName, isAuth[0], isAuth[1], out ldapErrorResponce);
                            if (disable)
                            {
                                await context.Response.WriteAsync("Success");
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else if (name != null)
                        {
                            string? ldapErrorResponce = "";
                            string? userName = LDAPRequests.GetUserName(name, isAuth[0], isAuth[1], out ldapErrorResponce); // ���������� ������������ � ldap
                            if (userName != null)
                            {
                                bool disable = LDAPRequests.DisableUserAccount(userName, isAuth[0], isAuth[1], out ldapErrorResponce);
                                if (disable)
                                {
                                    await context.Response.WriteAsync("Success");
                                }
                                else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Params 'name' or 'sAMAccountName' is missing or null!\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Params 'name' or 'sAMAccountName' is missing or null!\"}}"); }
                }
            });
            endpoints.MapPost("/ActivateADUser", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? name = queryParameters["name"];
                        string? sAMAccountName = queryParameters["sAMAccountName"];

                        if (sAMAccountName != null)
                        {
                            await context.Response.WriteAsync(LDAPRequests.EnableUserAccount(sAMAccountName, isAuth[0], isAuth[1]).ToString());
                        }
                        else if (name != null)
                        {
                            string? ldapErrorResponce = "";
                            string? userName = LDAPRequests.GetUserName(name, isAuth[0], isAuth[1], out ldapErrorResponce); // ���������� ������������ � ldap
                            if (userName != null)
                            {
                                await context.Response.WriteAsync(LDAPRequests.EnableUserAccount(userName, isAuth[0], isAuth[1]).ToString());
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Params 'name' or 'sAMAccountName' is missing or null!\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Params 'name' or 'sAMAccountName' is missing or null!\"}}"); }
                }
            });
            endpoints.MapDelete("/DeleteADUser", async (context) =>
            {
                //string[] isAuth = await AurhorizeRequestUser(context);

                //if (isAuth != null)
                //{
                //    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                //    {
                //        context.Response.ContentType = "application/json";
                //        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                //        string userDn = queryParameters["userDn"];

                //        if (userDn != null)
                //        {
                //            string? ldapErrorResponce = "";
                //            bool deleted = LDAPRequests.DeleteUser(isAuth[0], isAuth[1], userDn, out ldapErrorResponce);

                //            if (deleted)
                //            {
                //                await context.Response.WriteAsync(deleted.ToString());
                //            }
                //            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                //        }
                //        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Params 'userDn' is missing or null!\"}}"); }
                //    }
                //    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Params 'userDn' is missing or null!\"}}"); }
                //}
            });
            endpoints.MapPost("/CreateADUser", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? sAMAccountName = queryParameters["sAMAccountName"];
                        string? cName = queryParameters["cName"];
                        string? firstName = queryParameters["firstName"];
                        string? lastName = queryParameters["lastName"];
                        string? displayName = queryParameters["displayName"];
                        string? email = queryParameters["email"];
                        string? password = queryParameters["password"];
                        string? organizationalUnitDN = queryParameters["organizationalUnitDN"];

                        // �������� ������������ ����������
                        if (string.IsNullOrWhiteSpace(sAMAccountName) ||       // sAMAccountName � ��� ����� ������������ � Active Directory.
                            string.IsNullOrWhiteSpace(cName) ||                // CN (Common Name) � ��� ������ ��� ������������, ������� ������������ ��� ������������� ������� � LDAP.
                            string.IsNullOrWhiteSpace(firstName) ||            // FirstName � ��� ������������.
                            string.IsNullOrWhiteSpace(lastName) ||             // LastName � ������� ������������.
                            string.IsNullOrWhiteSpace(displayName) ||          // DisplayName � ������������ ��� ������������, ������� ����� � ��������� � �������� ������.
                            string.IsNullOrWhiteSpace(email) ||                // Email � ����������� ����� ������������.
                            string.IsNullOrWhiteSpace(password) ||             // Password � ������ ��� ����� ������� ������ ������������.
                            string.IsNullOrWhiteSpace(organizationalUnitDN))   // OrganizationalUnitDN � DN ��������������� ������� (OU), � ������� ����� ������ ������������.
                        {
                            await context.Response.WriteAsync("{\"Error\": \"Missing required attributes. Use LdapRequaredHelp request for more information\"}");
                            return;
                        }

                        ADUser newUser = new ADUser
                        {
                            sAMAccountName = sAMAccountName,
                            cName = cName,
                            FirstName = firstName,
                            LastName = lastName,
                            DisplayName = displayName,
                            Email = email,
                            Password = password,
                            OrganizationalUnitDN = organizationalUnitDN
                        };

                        string? ldapErrorResponce = "";
                        bool created = LDAPRequests.CreateUser(isAuth[0], isAuth[1], newUser, out ldapErrorResponce);

                        if (created)
                        {
                            await context.Response.WriteAsync(created.ToString());
                        }
                        else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync("{\"Error\": \"Missing required attributes. Use LdapRequaredHelp request for more information\"}"); }
                }
            });
            endpoints.MapGet("/LdapRequaredHelp", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    var requiredParameters = new
                    {
                        Parameters = new[]
                        {
                        new
                        {
                            Name = "userDn",
                            Description = "������ Distinguished Name (DN) ������������, ���������� ������������� � LDAP-������.",
                            CreateRequired = true
                        },
                        new
                        {
                            Name = "sAMAccountName",
                            Description = "sAMAccountName � ��� ����� ������������ � Active Directory.",
                            CreateRequired = true
                        },
                        new
                        {
                            Name = "cName",
                            Description = "CN (Common Name) � ��� ������ ��� ������������, ������� ������������ ��� ������������� ������� � LDAP.",
                            CreateRequired = true
                        },
                        new
                        {
                            Name = "firstName",
                            Description = "FirstName � ��� ������������.",
                            CreateRequired = true
                        },
                        new
                        {
                            Name = "lastName",
                            Description = "LastName � ������� ������������.",
                            CreateRequired = true
                        },
                        new
                        {
                            Name = "displayName",
                            Description = "DisplayName � ������������ ��� ������������, ������� ����� � ��������� � �������� ������.",
                            CreateRequired = false
                        },
                        new
                        {
                            Name = "email",
                            Description = "Email � ����������� ����� ������������.",
                            CreateRequired = false
                        },
                        new
                        {
                            Name = "password",
                            Description = "Password � ������ ��� ����� ������� ������ ������������.",
                            CreateRequired = true
                        },
                        new
                        {
                            Name = "organizationalUnitDN",
                            Description = "OrganizationalUnitDN � DN ��������������� ������� (OU), � ������� ����� ������ ������������.",
                            CreateRequired = true
                        }
                        }
                    };

                    string jsonResponse = System.Text.Json.JsonSerializer.Serialize(requiredParameters);
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(jsonResponse);
                }
            });
            endpoints.MapGet("/ListADUsersGroup", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? groupName = queryParameters["groupName"];
                        string? objectClass = queryParameters["objectClass"];

                        // �������� ������������ ����������
                        if (string.IsNullOrWhiteSpace(groupName) ||
                            string.IsNullOrWhiteSpace(objectClass))
                        {
                            await context.Response.WriteAsync("{\"Error\": \"Param 'groupName' and 'objectClass' is missing or null!\"}");
                        }

                        string? ldapErrorResponce = "";
                        List<ADUser>? users = LDAPRequests.GetGroupUsers(groupName, objectClass, isAuth[0], isAuth[1], out ldapErrorResponce, out int counter); // ���������� ������������ � ldap

                        if (users != null)
                        {
                            string jsonString = System.Text.Json.JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true });
                            jsonString = "{\"Users\": " + jsonString + ", \"Total\": " + counter + "}";

                            await context.Response.WriteAsync(jsonString);
                        }
                        else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'groupName' and 'objectClass' is missing or null!\"}}"); }

                }
            });
            endpoints.MapGet("/GetAdGroup", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? name = queryParameters["name"];

                        if (name != null) // �������� name �� ����
                        {
                            string? ldapErrorResponce = "";
                            string? userName = LDAPRequests.GetUserName(name, isAuth[0], isAuth[1], out ldapErrorResponce); // ���������� ������������ � ldap
                            if (userName != null)
                            {
                                userName = $"{{\"sAMAccountName\":\"{userName}\"}}";

                                await context.Response.WriteAsync(userName);
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'name' is missing or null!\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'name' is missing or null!\"}}"); }
                }
            });
            endpoints.MapGet("/GetAdGroupType", async (context) =>
            {
                string[] isAuth = await AurhorizeRequestUser(context);

                if (isAuth != null)
                {
                    context.Response.ContentType = "application/json";
                    if (context.Request.QueryString.HasValue) // ���� ��������� �������
                    {
                        var queryParameters = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                        string? cName = queryParameters["cName"];

                        if (cName != null) // �������� name �� ����
                        {
                            string? ldapErrorResponce = "";
                            string? groupInfo = "";
                            bool getGroup = LDAPRequests.GetGroupType(isAuth[0], isAuth[1], cName, out groupInfo, out ldapErrorResponce); // ���������� ������������ � ldap
                            if (getGroup)
                            {
                                groupInfo = $"{{\"Info\":\"{groupInfo}\"}}";

                                await context.Response.WriteAsync(groupInfo);
                            }
                            else { context.Response.StatusCode = 501; await context.Response.WriteAsync($"{{\"Error\": \"{ldapErrorResponce}\"}}"); }
                        }
                        else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'cName' is missing or null!\"}}"); }
                    }
                    else { context.Response.StatusCode = 500; await context.Response.WriteAsync($"{{\"Error\": \"Param 'cName' is missing or null!\"}}"); }
                }
            });
        });
    }
    private async static Task<string[]> AurhorizeRequestUser(HttpContext context)
    {
        context.Response.ContentType = "application/json";
        if (context.Request.Headers.ContainsKey("Authorization"))
        {
            var authHeader = context.Request.Headers["Authorization"].ToString();
            if (authHeader.StartsWith("Basic "))
            {
                var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
                var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
                var usernamePassword = decodedCredentials.Split(':');
                var username = usernamePassword[0];
                var password = usernamePassword[1];


                string ldapPath = $"LDAP://{ldapServer}";

                bool isAuthenticated = BasicAuth.AuthenticateUser(ldapPath, username, password); // ��������� ��������� Authorization � ��������� ������������
                if (isAuthenticated)
                {
                    return new string[] { username, password };
                }
                else
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("{\"Error\": \"Authentication failed.\"}");
                    return null;
                }
            }
            else
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("{\"Error\": \"Basic-Authorization header is requared!\"}");
                return null;
            }
        }
        else
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("{\"Error\": \"Basic-Authorization header is requared!\"}");
            return null;
        }
    }
}