using SystemLogowania2.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SystemLogowania2.Controllers;

namespace SystemLogowania2.Controllers;

public class HomeController : AppController
{
    public IActionResult Index() => View();
}


public class ContentController : AppController
{
    [Authorize(Policy = Permissions.ContentRead)]
    public IActionResult Read() => View("Show", Permissions.ContentRead);

    [Authorize(Policy = Permissions.ContentWrite)]
    public IActionResult Write() => View("Show", Permissions.ContentWrite);

    [Authorize(Policy = Permissions.ContentApprove)]
    public IActionResult Approve() => View("Show", Permissions.ContentApprove);
}
