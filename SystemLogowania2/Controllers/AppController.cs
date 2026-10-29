using SystemLogowania2.Data;
using Microsoft.AspNetCore.Mvc;

namespace SystemLogowania2.Controllers;


public abstract class AppController : Controller
{
    protected User? Me => HttpContext.Items["user"] as User;
}
